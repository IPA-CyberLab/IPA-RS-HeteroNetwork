#!/usr/bin/env python3
"""Stage a lost PostgreSQL/DCS member removal while preserving two replicas.

Runs as root on the database authority. The stage is private and includes an
etcd snapshot plus the previous authority. Membership removal is a separate,
retryable operation and refuses to run while automatic reconciliation is active.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import yaml


spec = importlib.util.spec_from_file_location(
    "database_recovery", Path(__file__).with_name("recover-database-authority.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

ETCDCTL = "/opt/heteronetwork/postgres-ha/etcdctl"
PATRONICTL = "/opt/heteronetwork/postgres-ha/patroni/bin/patronictl"
CONFIG = Path("/etc/heteronetwork/postgres-ha")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(command, timeout=45):
    result = subprocess.run([str(x) for x in command], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    require(result.returncode == 0, "a database health or membership command failed")
    return result.stdout


def etcd(endpoints, *args):
    return run([ETCDCTL, "--endpoints=" + ",".join(f"https://{x}:12379" for x in endpoints),
                "--dial-timeout=3s", "--command-timeout=10s",
                "--cacert=" + str(CONFIG / "pki/ca.crt"),
                "--cert=" + str(CONFIG / "pki/node.crt"),
                "--key=" + str(CONFIG / "pki/node.key"), *args], timeout=40)


def members(endpoints):
    data = json.loads(etcd(endpoints, "member", "list", "-w", "json"))
    return data["members"]


def healthy_dcs(survivors):
    endpoints = [f"https://{address}:12379" for address in survivors.values()]
    status = json.loads(etcd(survivors.values(), "endpoint", "status", "-w", "json"))
    health = json.loads(etcd(survivors.values(), "endpoint", "health", "-w", "json"))
    require(len(status) == len(endpoints) and
            {row["Endpoint"] for row in status} == set(endpoints),
            "not all surviving DCS endpoints responded")
    ids = {row["Status"]["header"]["member_id"] for row in status}
    leaders = {row["Status"]["leader"] for row in status}
    clusters = {row["Status"]["header"]["cluster_id"] for row in status}
    applied = [row["Status"]["raftAppliedIndex"] for row in status]
    require(len(ids) == len(endpoints) and len(clusters) == 1 and len(leaders) == 1 and
            leaders <= ids and max(applied) - min(applied) <= 10000 and
            not any(row["Status"].get("errors") for row in status),
            "surviving DCS voters are not healthy and caught up")
    require({row["endpoint"] for row in health} == set(endpoints) and
            all(row["health"] for row in health), "surviving DCS voters are not healthy")


def healthy_postgres(survivors):
    rows = json.loads(run([PATRONICTL, "-c", CONFIG / "patroni.yml", "list", "-f", "json"]))
    rows = [row for row in rows if row.get("Member") in survivors]
    require(len(rows) == 2 and {row["Member"] for row in rows} == set(survivors),
            "both surviving database members must be visible")
    leaders = [row for row in rows if row.get("Role") == "Leader" and row.get("State") == "running"]
    sync = [row for row in rows if row.get("Role") == "Sync Standby" and
            row.get("State") == "streaming" and row.get("Replay Lag") == 0]
    require(len(leaders) == len(sync) == 1, "database primary and synchronous standby are not healthy")


def snapshot_members(current, expected):
    actual = {}
    for member in current:
        urls = member.get("peerURLs", [])
        require(not member.get("isLearner") and len(urls) == 1 and member.get("name") not in actual,
                "DCS membership is ambiguous")
        actual[member["name"]] = (urls[0], format(member["ID"], "x"))
    require(set(actual) == set(expected), "DCS membership differs from the planned topology")
    require(all(actual[name][0] == f"https://{address}:12380" for name, address in expected.items()),
            "DCS peer addresses differ from the planned topology")
    return actual


def prepare(bundle, archive, stage, target, address, node_id):
    require(os.geteuid() == 0, "root is required")
    require(not stage.exists(), "the retirement stage already exists")
    authority = recovery.inspect_authority(bundle, archive)
    require(not authority["retired"], "database authority has unrelated pending retirements")
    old_members = authority["members"]
    old_dcs = authority["dcs"]
    require(old_members.get(target) == address and old_dcs.get(target) == address and
            authority["identities"].get(target) == node_id,
            "database member identity does not match the target")
    survivors = {name: addr for name, addr in old_dcs.items() if name != target}
    require(len(survivors) == 2 and {name: old_members.get(name) for name in survivors} == survivors,
            "exactly two existing database voters must survive")
    require(authority["revision"] + 1 == recovery.LOST_MEMBER_RETIREMENT_REVISION and
            survivors == recovery.TWO_HOST_DCS,
            "the requested protected authority is outside the reviewed retirement")
    healthy_dcs(survivors)
    healthy_postgres(survivors)
    current = snapshot_members(members(survivors.values()), old_dcs)
    stage.mkdir(mode=0o700, parents=True)
    try:
        shutil.copy2(archive, stage / "previous-bundle.tar.gz")
        staged_bundle = stage / "bundle"
        shutil.copytree(bundle, staged_bundle, symlinks=False)
        values = dict(authority["values"])
        for key in ("HETERONETWORK_DB_MEMBERS", "HETERONETWORK_DB_DCS_MEMBERS",
                    "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS"):
            values[key] = ",".join(f"{name}={value}" for name, value in survivors.items())
        values["HETERONETWORK_DB_MEMBER_IDENTITIES"] = ",".join(
            f"{name}={authority['identities'][name]}" for name in survivors)
        values["HETERONETWORK_DB_TOPOLOGY_REVISION"] = str(authority["revision"] + 1)
        recovery.atomic_write(staged_bundle / "manifest.env", "".join(
            f"{name}={values[name]}\n" for name in authority["order"]).encode(), 0o600)
        shutil.rmtree(staged_bundle / "nodes" / target)
        staged_archive = stage / "bundle.tar.gz"
        recovery.pack_bundle(staged_bundle, staged_archive)
        staged = recovery.inspect_authority(staged_bundle, staged_archive)
        require(staged["members"] == survivors and staged["dcs"] == survivors and
                staged["revision"] == authority["revision"] + 1,
                "staged database authority did not converge")
        etcd([next(iter(survivors.values()))], "snapshot", "save", str(stage / "dcs-snapshot.db"))
        (stage / "dcs-snapshot.db").chmod(0o600)
        require((stage / "dcs-snapshot.db").stat().st_size > 4096, "DCS snapshot is unexpectedly small")
        state = {"target": target, "address": address, "node_id": node_id,
                 "old_revision": authority["revision"], "revision": staged["revision"],
                 "old_dcs": old_dcs, "survivors": survivors,
                 "target_member_id": current[target][1], "old_archive_sha256": sha(archive),
                 "new_archive_sha256": sha(staged_archive),
                 "dcs_snapshot_sha256": sha(stage / "dcs-snapshot.db")}
        recovery.atomic_write(stage / "state.json", (json.dumps(state, sort_keys=True) + "\n").encode(), 0o600)
        return {"result": "staged", "revision": staged["revision"], "surviving_voters": len(survivors)}
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def retire_vote(archive, stage):
    require(os.geteuid() == 0, "root is required")
    state = json.loads(recovery.read_limited(stage / "state.json", private=True))
    require(sha(archive) == state["old_archive_sha256"] and
            sha(stage / "bundle.tar.gz") == state["new_archive_sha256"] and
            sha(stage / "dcs-snapshot.db") == state["dcs_snapshot_sha256"],
            "the protected authority or recovery snapshot changed")
    stopped = subprocess.run(["systemctl", "is-active", "--quiet", "heteronetwork-postgres-autopilot.service"])
    require(stopped.returncode == 3, "automatic database reconciliation must be paused on both members")
    healthy_dcs(state["survivors"])
    healthy_postgres(state["survivors"])
    live = members(state["survivors"].values())
    actual_names = {member.get("name") for member in live}
    if actual_names == set(state["old_dcs"]):
        current = snapshot_members(live, state["old_dcs"])
        require(current[state["target"]][1] == state["target_member_id"], "lost voter identity changed")
        etcd(state["survivors"].values(), "member", "remove", state["target_member_id"])
    snapshot_members(members(state["survivors"].values()), state["survivors"])
    healthy_dcs(state["survivors"])
    healthy_postgres(state["survivors"])
    return {"result": "retired", "surviving_voters": 2, "revision_staged": state["revision"]}


def render_local_configs(patroni_raw, etcd_raw, proxy_raw, state):
    """Remove only the exact retired endpoint and preserve all other settings."""
    patroni = yaml.safe_load(patroni_raw)
    etcd_config = yaml.safe_load(etcd_raw)
    old_endpoint = state["address"] + ":12379"
    old_hosts = patroni["etcd3"]["hosts"]
    expected_hosts = [address + ":12379" for address in state["survivors"].values()]
    require(old_hosts in (expected_hosts, [
        address + ":12379" for address in state["old_dcs"].values()]),
        "Patroni DCS endpoints differ from both reviewed topologies")
    expected_patroni = yaml.safe_load(patroni_raw)
    expected_patroni["etcd3"]["hosts"] = expected_hosts
    needle = "    - " + old_endpoint + "\n"
    if old_endpoint in old_hosts:
        require(patroni_raw.count(needle) == 1, "retired Patroni endpoint is ambiguous")
        patroni_new = patroni_raw.replace(needle, "", 1)
    else:
        patroni_new = patroni_raw
    require(yaml.safe_load(patroni_new) == expected_patroni, "unexpected Patroni configuration change")
    previous_cluster = ",".join(f"{name}=https://{addr}:12380" for name, addr in state["old_dcs"].items())
    next_cluster = ",".join(f"{name}=https://{addr}:12380" for name, addr in state["survivors"].items())
    require(etcd_config["initial-cluster"] in (previous_cluster, next_cluster),
            "etcd bootstrap topology differs from both reviewed topologies")
    etcd_new = etcd_raw.replace("initial-cluster: " + previous_cluster,
                                "initial-cluster: " + next_cluster)
    expected_etcd = yaml.safe_load(etcd_raw)
    expected_etcd["initial-cluster"] = next_cluster
    require(yaml.safe_load(etcd_new) == expected_etcd, "unexpected etcd configuration change")
    removed = []
    retained = []
    for line in proxy_raw.splitlines(keepends=True):
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "server" and fields[1] in (
                state["target"], "health-" + state["target"]):
            require(fields[2].split(":", 1)[0] == state["address"],
                    "retired proxy backend points to an unexpected address")
            removed.append(fields[1])
        else:
            retained.append(line)
    require(set(removed) in (set(), {state["target"], "health-" + state["target"]}) and
            len(removed) in (0, 2), "retired proxy backends are ambiguous")
    return patroni_new, etcd_new, "".join(retained)


def write_preserving_owner(path, data):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), "database configuration is not a regular file")
    fd, temp = tempfile.mkstemp(prefix=".retire-", dir=path.parent)
    try:
        os.fchown(fd, info.st_uid, info.st_gid)
        os.fchmod(fd, stat.S_IMODE(info.st_mode))
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        recovery.fsync_directory(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def extract_protected_archive(archive, destination):
    # Python's data filter intentionally drops directory modes. The autopilot
    # hashes those modes, so restore the verified archive modes explicitly.
    recovery.archive_digest(archive)
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(destination, filter="data")
        for member in source.getmembers():
            target = destination / member.name
            os.chmod(target, member.mode & 0o777, follow_symlinks=False)


def fix_modes(bundle, archive, stage):
    """Restore archive modes after proving every protected byte is identical."""
    require(os.geteuid() == 0, "root is required")
    stopped = subprocess.run(["systemctl", "is-active", "--quiet", "heteronetwork-postgres-autopilot.service"])
    require(stopped.returncode == 3, "automatic database reconciliation must be paused")
    state = json.loads(recovery.read_limited(stage / "state.json", private=True))
    candidate = stage / "bundle.tar.gz"
    require(sha(candidate) == state["new_archive_sha256"], "staged bundle checksum differs")
    authority = recovery.inspect_authority(bundle, archive)
    require(authority["revision"] == state["revision"], "installed topology revision differs")
    candidate_files, _ = recovery.archive_digest(candidate)
    require(recovery.tree_digest(bundle) == candidate_files, "installed protected files differ from the staged bundle")
    changed = 0
    with tarfile.open(candidate, "r:gz") as source:
        for member in source.getmembers():
            name = recovery.normalized_member_name(member.name)
            path = bundle if name is None else bundle / name
            info = path.lstat()
            mode = member.mode & 0o777
            require(not stat.S_ISLNK(info.st_mode) and
                    ((member.isdir() and stat.S_ISDIR(info.st_mode)) or
                     (member.isfile() and stat.S_ISREG(info.st_mode))),
                    "installed bundle entry type differs")
            require(not member.isdir() or mode & 0o022 == 0, "staged directory mode is unsafe")
            if stat.S_IMODE(info.st_mode) != mode:
                os.chmod(path, mode, follow_symlinks=False)
                changed += 1
    recovery.inspect_authority(bundle, archive)
    return {"result": "modes_aligned", "revision": state["revision"], "changed": changed}


def preflight_install(bundle, archive, stage):
    """Prove a local member can accept the staged topology without modifying it."""
    require(os.geteuid() == 0, "root is required")
    state = json.loads(recovery.read_limited(stage / "state.json", private=True))
    candidate = stage / "bundle.tar.gz"
    require(sha(candidate) == state["new_archive_sha256"], "staged bundle checksum differs")
    authority = recovery.inspect_authority(bundle, archive)
    require(authority["revision"] in (state["old_revision"], state["revision"]),
            "local database authority changed during retirement")
    healthy_dcs(state["survivors"])
    healthy_postgres(state["survivors"])
    for service in ("heteronetwork-db.service", "heteronetwork-db-proxy.service"):
        require(run(["systemctl", "show", service, "-p", "CanReload", "--value"]).strip() == b"yes",
                "database service cannot safely reload")
    configs = [CONFIG / "patroni.yml", CONFIG / "etcd.yml", CONFIG / "haproxy.cfg"]
    new_configs = render_local_configs(*(path.read_text() for path in configs), state)
    with tempfile.TemporaryDirectory(prefix=".retire-db-check-", dir=bundle.parent) as temp:
        temp = Path(temp)
        staged_bundle = temp / "bundle"
        staged_bundle.mkdir(mode=0o700)
        extract_protected_archive(candidate, staged_bundle)
        staged = recovery.inspect_authority(staged_bundle, candidate)
        require(staged["revision"] == state["revision"] and
                staged["members"] == state["survivors"] and staged["dcs"] == state["survivors"],
                "staged authority does not match the retirement")
        validation = temp / "haproxy.cfg"
        validation.write_text(new_configs[2])
        run(["/usr/sbin/haproxy", "-c", "-f", validation])
    return {"result": "ready", "old_revision": authority["revision"], "new_revision": state["revision"]}


def install(bundle, archive, stage):
    require(os.geteuid() == 0, "root is required")
    state = json.loads(recovery.read_limited(stage / "state.json", private=True))
    new_archive = stage / "bundle.tar.gz"
    require(sha(new_archive) == state["new_archive_sha256"], "staged bundle checksum differs")
    stopped = subprocess.run(["systemctl", "is-active", "--quiet", "heteronetwork-postgres-autopilot.service"])
    require(stopped.returncode == 3, "automatic database reconciliation must be paused")
    snapshot_members(members(state["survivors"].values()), state["survivors"])
    healthy_dcs(state["survivors"])
    healthy_postgres(state["survivors"])
    authority = recovery.inspect_authority(bundle, archive)
    require(authority["revision"] in (state["old_revision"], state["revision"]),
            "local database authority changed during retirement")
    for service in ("heteronetwork-db.service", "heteronetwork-db-proxy.service"):
        require(run(["systemctl", "show", service, "-p", "CanReload", "--value"]).strip() == b"yes",
                "database service cannot safely reload")
    configs = [CONFIG / "patroni.yml", CONFIG / "etcd.yml", CONFIG / "haproxy.cfg"]
    originals = [path.read_text() for path in configs]
    new_configs = render_local_configs(*originals, state)
    backup = stage / "local-backup"
    if not backup.exists():
        backup.mkdir(mode=0o700)
        for path in configs:
            shutil.copy2(path, backup / path.name)
            (backup / path.name).chmod(0o600)
        shutil.copy2(archive, backup / "bundle.tar.gz")
    recovery.secure_directory(backup)
    with tempfile.TemporaryDirectory(prefix=".retire-db-", dir=bundle.parent) as temp:
        temp = Path(temp)
        staged_bundle = temp / "bundle"
        staged_bundle.mkdir(mode=0o700)
        extract_protected_archive(new_archive, staged_bundle)
        staged_authority = recovery.inspect_authority(staged_bundle, new_archive)
        require(staged_authority["revision"] == state["revision"] and
                staged_authority["members"] == state["survivors"] and
                staged_authority["dcs"] == state["survivors"], "staged authority does not match the retirement")
        validation = temp / "haproxy.cfg"
        validation.write_text(new_configs[2])
        run(["/usr/sbin/haproxy", "-c", "-f", validation])
        previous_bundle = temp / "previous-bundle"
        moved_previous = False
        try:
            if authority["revision"] != state["revision"]:
                os.replace(bundle, previous_bundle)
                moved_previous = True
                os.replace(staged_bundle, bundle)
                recovery.replace_archive(archive, new_archive)
            for path, content in zip(configs, new_configs):
                write_preserving_owner(path, content.encode())
            run(["systemctl", "reload", "heteronetwork-db.service"])
            run(["systemctl", "reload", "heteronetwork-db-proxy.service"])
            healthy_dcs(state["survivors"])
            healthy_postgres(state["survivors"])
            recovery.inspect_authority(bundle, archive)
            recovery.publish_proxy_archive(bundle, bundle.parent / "proxy-bundle.tar.gz")
            for marker in ("configured-revision", "applied-revision"):
                recovery.atomic_write(bundle.parent / marker, f"{state['revision']}\n".encode(), 0o600)
        except Exception:
            for path, content in zip(configs, originals):
                write_preserving_owner(path, content.encode())
            if moved_previous:
                if bundle.exists():
                    shutil.rmtree(bundle)
                os.replace(previous_bundle, bundle)
                recovery.replace_archive(archive, backup / "bundle.tar.gz")
            subprocess.run(["systemctl", "reload", "heteronetwork-db.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "reload", "heteronetwork-db-proxy.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            raise
    return {"result": "configured", "revision": state["revision"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["stage", "retire-vote", "preflight-install", "install", "fix-modes"])
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--target")
    parser.add_argument("--address")
    parser.add_argument("--node-id")
    args = parser.parse_args()
    if args.action == "stage":
        require(all((args.target, args.address, args.node_id)), "target identity is required")
        result = prepare(args.bundle, args.archive, args.stage, args.target, args.address, args.node_id)
    elif args.action == "retire-vote":
        result = retire_vote(args.archive, args.stage)
    elif args.action == "preflight-install":
        result = preflight_install(args.bundle, args.archive, args.stage)
    elif args.action == "fix-modes":
        result = fix_modes(args.bundle, args.archive, args.stage)
    else:
        result = install(args.bundle, args.archive, args.stage)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError,
            recovery.RecoveryError) as error:
        raise SystemExit("Database retirement failed: " + str(error))
