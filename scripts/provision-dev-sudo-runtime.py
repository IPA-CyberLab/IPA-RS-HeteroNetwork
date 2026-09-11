#!/usr/bin/env python3
"""Prepare verified DEV sudo runtime and disabled units; never activate enforcement."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import socket
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
BUNDLE = Path("/opt/heteronetwork-dev-sudo-runtime-v2")
VERSION = "0.1.15-dev.6"
IPARSD_SHA = "dd26e9907c426fe1f2b628a5010441a4127ef26ab763195c353a8c7e09cf05bb"
HOSTS_SHA = "c28d3c1fe54d7016752bad8f3fb92652f3f1dd96b81a9271ac6b9aac95b688c8"
LOCAL_UNIT_SHA = "1a7c9f32574555230056389d2b413e9db57f13a7dc4ccca3236a3735a229853d"
SIGNER_UNIT_SHA = "a7c966d14295d62ff14f645092a161b846f7b6a8b993a9d686cc8fa8849a8328"
DKG_HELPER = Path("/opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py")
DKG_SHA = "0fc2ac15c65cb2a69fee5a15157d02476afdc0284629c44d45f299d4d48c7cfe"
HOST_HELPER = Path("/opt/heteronetwork-dev-sudo-host-key-f0e8c943/provision-dev-sudo-host-key.py")
HOST_HELPER_SHA = "f0e8c9437d3a9e108de253bf3aff1cd66c30078e52b363168bc32cf6254f2fff"
RUNTIME = Path("/opt/heteronetwork/sudo-v2/runtime")
ARTIFACTS = Path("/opt/heteronetwork/sudo-v2/artifacts")
LOCAL_UNIT = Path("/etc/systemd/system/heteronetwork-sudo-local.service")
SIGNER_UNIT = Path("/etc/systemd/system/heteronetwork-sudo-quorum-signer.service")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def require(value):
    if not value:
        raise ValueError("DEV inactive sudo runtime preparation rejected")


def trusted(path, directory=False, mode=None):
    path = Path(path)
    require(path.is_absolute())
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o7022)
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    require(mode is None or stat.S_IMODE(info.st_mode) == mode)
    return info


def read(path, limit, mode=None):
    trusted(path, mode=mode)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(info.st_size <= limit)
        raw = source.read(limit + 1)
        require(len(raw) <= limit)
        return raw


def load(path, digest, name):
    require(hashlib.sha256(read(path, 128 * 1024)).hexdigest() == digest)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mkdir(path, mode):
    if not os.path.lexists(path):
        path.mkdir(mode=mode)
    trusted(path, directory=True, mode=mode)


def install_file(path, raw, mode):
    created = not os.path.lexists(path)
    if created:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
            target.flush()
            os.fchmod(target.fileno(), mode)
            os.fsync(target.fileno())
    require(read(path, len(raw), mode=mode) == raw)
    return created


def select(path, target):
    created = not os.path.lexists(path)
    if created:
        os.symlink(target, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    info = path.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid() and os.readlink(path) == target)
    return created


def unit_state(path):
    fields = ("LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths",
              "UnitFileState", "NeedDaemonReload")
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(fields), path.name],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=ENV, cwd="/", timeout=15, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 65536)
    values = {}
    for line in result.stdout.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key not in values)
        values[key] = value
    require(set(values) == set(fields) and values["LoadState"] == "loaded"
            and values["ActiveState"] == "inactive" and values["SubState"] == "dead"
            and values["FragmentPath"] == str(path) and not values["DropInPaths"]
            and values["UnitFileState"] == "disabled" and values["NeedDaemonReload"] == "no")
    return {key: values[key] for key in ("ActiveState", "SubState", "UnitFileState")}


def main():
    require(len(sys.argv) == 1 and os.getuid() == 0 and os.geteuid() == 0)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    dkg = load(DKG_HELPER, DKG_SHA, "dev_dkg")
    member = dkg.check_identity()
    host_helper = load(HOST_HELPER, HOST_HELPER_SHA, "host_key")
    before = host_helper.sudo_snapshot()
    public_records = json.loads(read(BUNDLE / "sudo-hosts.json", 32768))
    require(hashlib.sha256(read(BUNDLE / "sudo-hosts.json", 32768)).hexdigest() == HOSTS_SHA)
    require(public_records["cluster_id"] == dkg.CLUSTER and len(public_records["hosts"]) == 3)
    expected = {**public_records["hosts"][member - 1],
                "schema_version": public_records["schema_version"],
                "cluster_id": public_records["cluster_id"],
                "manifest_file_sha256": public_records["manifest_file_sha256"]}
    require(expected["guest"] == socket.gethostname()
            and expected == dkg.decode(host_helper.read(host_helper.ROOT / "host-public.json", 8192, mode=0o600)))

    iparsd = read(BUNDLE / "iparsd", 256 * 1024 * 1024, mode=0o600)
    local_unit = read(BUNDLE / LOCAL_UNIT.name, 65536, mode=0o600)
    signer_unit = read(BUNDLE / SIGNER_UNIT.name, 65536, mode=0o600)
    require(hashlib.sha256(iparsd).hexdigest() == IPARSD_SHA
            and hashlib.sha256(local_unit).hexdigest() == LOCAL_UNIT_SHA
            and hashlib.sha256(signer_unit).hexdigest() == SIGNER_UNIT_SHA)
    require(iparsd[:7] == b"\x7fELF\x02\x01\x01")

    mkdir(RUNTIME, 0o755)
    version = RUNTIME / VERSION
    mkdir(version, 0o755)
    mkdir(version / "bin", 0o755)
    binary_created = install_file(version / "bin/iparsd", iparsd, 0o555)
    runtime_selected = select(RUNTIME / "current", VERSION)
    artifact = ARTIFACTS / VERSION
    trusted(artifact, directory=True, mode=0o755)
    require(hashlib.sha256(read(artifact / "bin/local-sudo-v2", 256 * 1024 * 1024, mode=0o755)).hexdigest()
            == "0154c932915cfdf0e5d510bfae47d888b49349bbd6d3734aaa9641e2514aa392")
    artifact_selected = select(ARTIFACTS / "current", VERSION)
    local_created = install_file(LOCAL_UNIT, local_unit, 0o644)
    signer_created = install_file(SIGNER_UNIT, signer_unit, 0o644)

    help_result = subprocess.run([str(RUNTIME / "current/bin/iparsd"), "quorum-signer", "--help"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=ENV, cwd="/", timeout=15)
    require(help_result.returncode == 0 and b"--sudo-policy-path" in help_result.stdout
            and b"--check-config" in help_result.stdout)
    reload_result = subprocess.run(["/usr/bin/systemctl", "daemon-reload"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=ENV, cwd="/", timeout=30)
    require(reload_result.returncode == 0)
    states = {path.name: unit_state(path) for path in (LOCAL_UNIT, SIGNER_UNIT)}
    require(not os.path.lexists("/run/ipars-sudo-v2") and not os.path.lexists("/var/lib/ipars-sudo-v2"))
    require(not os.path.lexists("/etc/ipars-sudo-v2/config.json"))
    require(host_helper.sudo_snapshot() == before)
    print(json.dumps({"guest": socket.gethostname(), "member": member,
                      "binary_created": binary_created, "runtime_selected": runtime_selected,
                      "artifact_selected": artifact_selected, "local_unit_created": local_created,
                      "signer_unit_created": signer_created, "unit_states": states,
                      "services_started": False, "services_enabled": False,
                      "sudo_configuration_unchanged": True, "activation_performed": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("DEV sudo runtime preparation stopped; preserve existing files for inspection", file=sys.stderr)
        sys.exit(1)
