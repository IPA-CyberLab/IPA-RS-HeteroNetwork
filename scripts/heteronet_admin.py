#!/usr/bin/env python3
"""Retire a lost HeteroNetwork worker across its declared infrastructure."""
import argparse
import base64
from contextlib import contextmanager
import datetime
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse
import yaml

from prune_overlay_dns_node import reconcile as reconcile_dns
from prune_node_declarations import plan as plan_declarations
from retire_lost_garage_volume import Kube
from retire_node_inventory import apply as apply_inventory, plan as plan_inventory
from retire_node_kubernetes import ETCD, delete_kubernetes_objects, kubernetes_preflight


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/terraform/master-only"
SAFE_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def default_work_dir():
    configured = os.environ.get("TF_VAR_work_dir")
    if configured:
        return Path(configured).expanduser()
    sibling = ROOT.parent / ".heteronetwork-iac"
    return sibling if sibling.is_dir() else Path("~/.local/share/heteronetwork-iac").expanduser()


def default_kubeconfig(work_dir):
    configured = os.environ.get("TF_VAR_kubeconfig_path") or os.environ.get("KUBECONFIG")
    if configured:
        return Path(configured).expanduser()
    tunnel = work_dir / "local-tunnel-admin.conf"
    return tunnel if tunnel.is_file() else Path("~/.kube/config").expanduser()


def port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@contextmanager
def kube_tunnel(args):
    """Open the configured local Kubernetes API tunnel when it is not running."""
    require(args.kubeconfig.is_file() and args.ssh_key.is_file(), "kubeconfig and SSH key are required")
    config = yaml.safe_load(args.kubeconfig.read_text())
    contexts = {item["name"]: item["context"] for item in config.get("contexts", [])}
    clusters = {item["name"]: item["cluster"] for item in config.get("clusters", [])}
    context = contexts.get(config.get("current-context"), {})
    url = urlparse(clusters.get(context.get("cluster"), {}).get("server", ""))
    if url.scheme != "https" or url.hostname not in ("127.0.0.1", "localhost") or not url.port:
        yield
        return
    if port_open("127.0.0.1", url.port):
        yield
        return
    known_hosts = args.work_dir / "known_hosts"
    require(known_hosts.is_file(), "the operator known_hosts file is required")
    bootstrap = json.loads((MODULE / "edge-nodes.json").read_text())["bootstrap"]
    command = ["ssh", "-N", "-T", "-i", str(args.ssh_key), "-o", "IdentitiesOnly=yes",
               "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15",
               "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes",
               "-o", "UserKnownHostsFile=" + str(known_hosts), "-L",
               f"127.0.0.1:{url.port}:127.0.0.1:6443", args.ssh_user + "@" + bootstrap["ssh_host"]]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not port_open("127.0.0.1", url.port):
            require(process.poll() is None, "could not establish the Kubernetes API SSH tunnel")
            time.sleep(0.2)
        require(port_open("127.0.0.1", url.port), "Kubernetes API SSH tunnel timed out")
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stderr:
            process.stderr.close()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def contains_address(value, address):
    if isinstance(value, dict):
        return address in value or any(contains_address(item, address) for item in value.values())
    if isinstance(value, list):
        return any(contains_address(item, address) for item in value)
    return value == address


def run(command, *, env=None, capture=False, input=None, timeout=900):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env, input=input,
                            text=True, capture_output=capture, timeout=timeout)
    if result.returncode:
        raise ValueError("operation failed: " + str(command[0]) +
                         (" (" + result.stderr[-300:].strip() + ")" if capture else ""))
    return result.stdout if capture else ""


class Remote:
    def __init__(self, host, user, key, known_hosts, password):
        self.host, self.user, self.key, self.known_hosts, self.password = host, user, key, known_hosts, password

    def python(self, source, args):
        encoded = base64.b64encode(source.encode()).decode()
        launcher = "import base64,sys; s=base64.b64decode(sys.argv[1]); sys.argv=sys.argv[2:]; exec(compile(s,'<retirement>','exec'),{'__name__':'__main__'})"
        remote = shlex.join(["sudo", "-S", "-p", "", "python3", "-c", launcher, encoded, *args])
        command = ["ssh", "-T", "-i", self.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(self.known_hosts),
                   self.user + "@" + self.host, remote]
        output = run(command, capture=True, input=self.password + "\n", timeout=120)
        return json.loads(output)

    def stream_snapshot(self, source_path, output):
        # SSH carries both the sudo password on stdin and the binary snapshot
        # on stdout. Neither is put in process arguments or terminal output.
        source = r'''import os,stat,sys
path=sys.argv[1]
assert path.startswith('/var/lib/etcd/heteronetwork-retirement-') and path.endswith('.db')
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
try:
    info=os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode & 0o077==0
    with os.fdopen(fd,'rb') as f:
        while block:=f.read(1024*1024): sys.stdout.buffer.write(block)
        sys.stdout.buffer.flush()
except BaseException:
    try: os.close(fd)
    except OSError: pass
    raise
'''
        encoded = base64.b64encode(source.encode()).decode()
        launcher = "import base64,sys; s=base64.b64decode(sys.argv[1]); sys.argv=sys.argv[2:]; exec(compile(s,'<snapshot>','exec'),{'__name__':'__main__'})"
        remote = shlex.join(["sudo", "-S", "-p", "", "python3", "-c", launcher, encoded, "snapshot", source_path])
        command = ["ssh", "-T", "-i", self.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(self.known_hosts),
                   self.user + "@" + self.host, remote]
        result = subprocess.run([str(x) for x in command], input=(self.password + "\n").encode(),
                                stdout=output, stderr=subprocess.PIPE, timeout=240)
        require(result.returncode == 0, "protected etcd snapshot transfer failed")

    def remove_snapshot(self, source_path):
        source = r'''import os,pathlib,sys
path=pathlib.Path(sys.argv[1])
assert str(path).startswith('/var/lib/etcd/heteronetwork-retirement-') and path.name.endswith('.db')
for item in (path,pathlib.Path(str(path)+'.part')):
    try: item.unlink()
    except FileNotFoundError: pass
print('{"result":"removed"}')
'''
        self.python(source, ["cleanup", source_path])

    def registration(self, identity, apply):
        helper = (ROOT / "scripts/retire_hn_registration.py").read_text()
        # The operator daemon uses the running control plane binary and a
        # loopback-only, short-lived token; no DB or API secret is printed.
        prefix = ("import os,subprocess,sys\n"
                  "pid=int(subprocess.check_output(['systemctl','show','heteronetwork-control-plane.service',"
                  "'-p','MainPID','--value'],text=True))\n"
                  "assert pid>1\n"
                  "sys.argv += ['--binary',os.readlink('/proc/%d/exe' % pid)]\n")
        args = ["retire_hn_registration.py", "--node-id", identity["node_id"],
                "--hostname", identity["hostname"], "--vpn-ip", identity["vpn_ip"],
                "--cluster-id", identity["cluster_id"]]
        if apply:
            args.append("--apply")
        return self.python(prefix + helper, args)

    def database_absent(self, identity):
        source = r'''import json, pathlib, subprocess, sys
name,address,node_id=sys.argv[1:]
path=pathlib.Path('/etc/heteronetwork/postgres-autopilot/bundle/manifest.env')
values=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
for key in ('HETERONETWORK_DB_MEMBERS','HETERONETWORK_DB_MEMBER_IDENTITIES','HETERONETWORK_DB_DCS_MEMBERS','HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS'):
    entries=dict(entry.split('=',1) for entry in values[key].split(','))
    if (name and name in entries) or (address and address in entries.values()) or node_id in entries.values():
        raise SystemExit('Database authority still references the target; migrate it before retirement')
members=dict(entry.split('=',1) for entry in values['HETERONETWORK_DB_DCS_MEMBERS'].split(','))
assert len(members)>=2
cmd=['/opt/heteronetwork/postgres-ha/etcdctl','--endpoints='+','.join('https://'+ip+':12379' for ip in members.values()),'--dial-timeout=3s','--command-timeout=8s','--cacert=/etc/heteronetwork/postgres-ha/pki/ca.crt','--cert=/etc/heteronetwork/postgres-ha/pki/node.crt','--key=/etc/heteronetwork/postgres-ha/pki/node.key']
def call(*args):
    p=subprocess.run(cmd+list(args),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=True)
    return json.loads(p.stdout)
live=call('member','list','-w','json')['members']
assert all((not name or x.get('name')!=name) and (not address or all(address not in u for u in x.get('peerURLs',[]))) for x in live)
assert {x.get('name') for x in live}==set(members)
health=call('endpoint','health','-w','json'); assert len(health)==len(members) and all(x.get('health') for x in health)
print(json.dumps({'result':'absent','surviving_voters':len(members)}))
'''
        return self.python(source, ["database-check", identity.get("postgres_name") or "",
                                    identity.get("tailscale_ip") or "", identity["node_id"]])


def load_identity(host, state_dir):
    record = state_dir / "identity.json"
    if record.exists():
        identity = json.loads(record.read_text())
        require(identity.get("hostname") == host, "saved retirement identity does not match the target")
        return identity, None
    roster = json.loads((MODULE / "overlay-boot-peers.json").read_text())
    standard = json.loads((MODULE / "standard-nodes.json").read_text())
    require(host in standard and host in roster["hosts"], "no declared standard node or saved retirement exists")
    node_id = roster["hosts"][host]
    peers = [p for p in roster["peers"] if p.get("node_id") == node_id and p.get("hostname") == host]
    require(len(peers) == 1 and peers[0].get("vpn_ip") == standard[host].get("vpn_ip"),
            "network and infrastructure node identities do not match")
    identity = {"hostname": host, "node_id": node_id, "vpn_ip": peers[0]["vpn_ip"],
                "cluster_id": roster["cluster_id"], "public_ip": standard[host].get("ssh_host"),
                "tailscale_ip": standard[host].get("tailscale_ip"),
                "postgres_name": standard[host].get("postgres_name")}
    return identity, record


def save_identity(record, identity):
    record.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(record.parent, 0o700)
    fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(identity, out, sort_keys=True)
        out.write("\n")


def pending_applications(state_dir, declarations):
    """Keep application work across interrupted commits, pushes and rollouts."""
    path = state_dir / "pending-applications.json"
    allowed = {"heterocloud", "heterocloud-flash", "heterocloud-vpc", "heterocloud-syouyu"}
    previous = json.loads(path.read_text()) if path.exists() else []
    require(isinstance(previous, list) and all(isinstance(name, str) and name in allowed for name in previous),
            "saved application retirement state is invalid")
    changed = {name for name in allowed
               if Path("deploy/gitops/applications/" + name + ".yaml") in declarations}
    changed.update(previous)
    if changed:
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state_dir, 0o700)
        fd, temp = tempfile.mkstemp(prefix=".pending-", dir=state_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump(sorted(changed), out)
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    return {Path("deploy/gitops/applications/" + name + ".yaml") for name in changed}


def fence_offline_node(kube, checked):
    """Cordon only the UID and versions that passed offline preflight."""
    node = checked.get("node_object")
    if node:
        meta = node["metadata"]
        patch = [{"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]}]
        if "labels" not in meta:
            patch.append({"op": "add", "path": "/metadata/labels", "value": {}})
        patch += [{"op": "add", "path": "/metadata/labels/heteronetwork.io~1lifecycle", "value": "stopped"},
                  {"op": "add", "path": "/spec/unschedulable", "value": True}]
        kube.patch(None, "node", meta["name"], patch)
    for node in checked["longhorn"]:
        meta = node["metadata"]
        kube.patch("longhorn-system", "nodes.longhorn.io", meta["name"], [
            {"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
            {"op": "add", "path": "/spec/allowScheduling", "value": False}])


def snapshot_etcd(kube_api, args, executor, directory, remote_host):
    """Copy a validated snapshot to a private directory and erase the remote copy."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    suffix = secrets.token_hex(12)
    # /var/lib/etcd is root-only on the host; a snapshot contains cluster
    # credentials and must not be created in a world-readable directory.
    remote = "/var/lib/etcd/heteronetwork-retirement-" + suffix + ".db"
    local = directory / ("etcd-" + suffix + ".db")
    pod = kube_api.get("pod", "etcd-" + executor, "-n", "kube-system")
    require(pod["spec"].get("nodeName") == executor, "etcd executor pod is on an unexpected host")
    volumes = {v["name"]: v for v in pod["spec"].get("volumes", [])}
    mounts = pod["spec"]["containers"][0].get("volumeMounts", [])
    require(any(m.get("mountPath") == "/var/lib/etcd" and
                volumes.get(m.get("name"), {}).get("hostPath", {}).get("path") == "/var/lib/etcd"
                for m in mounts), "etcd snapshot directory is not the expected host mount")
    kube = [args.kubectl, "--kubeconfig", str(args.kubeconfig), "--request-timeout=180s", "-n", "kube-system",
            "exec", "etcd-" + executor, "--"]
    ctl = ["etcdctl", "--endpoints=https://127.0.0.1:2379", "--dial-timeout=3s", "--command-timeout=120s",
           "--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt",
           "--key=/etc/kubernetes/pki/etcd/healthcheck-client.key"]
    try:
        run(kube + ctl + ["snapshot", "save", remote], capture=True, timeout=240)
        status = json.loads(run(kube + ["etcdutl", "snapshot", "status", remote, "-w", "json"],
                                capture=True, timeout=120))
        require(status.get("totalSize", 0) > 0, "etcd snapshot verification failed")
        fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                remote_host.stream_snapshot(remote, output)
                output.flush()
                os.fsync(output.fileno())
            require(local.stat().st_size >= 1024 * 1024, "etcd snapshot is unexpectedly small")
            digest = hashlib.sha256()
            with local.open("rb") as input_file:
                for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                    digest.update(chunk)
            return {"snapshot_file": local.name, "snapshot_sha256": digest.hexdigest(),
                    "snapshot_created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        except Exception:
            local.unlink(missing_ok=True)
            raise
    finally:
        try:
            remote_host.remove_snapshot(remote)
        except (ValueError, OSError, subprocess.SubprocessError):
            print("Warning: could not remove the temporary etcd snapshot from the executor", file=sys.stderr)


def retire_etcd_member(kube, args, identity, member, state_dir, executor, remote):
    if member is None:
        return
    require(executor != identity["hostname"], "the etcd executor cannot retire itself")
    backup = state_dir / "etcd-backups"
    require(json.loads((MODULE / "edge-nodes.json").read_text())["bootstrap"]["name"] == executor,
            "the etcd executor must match the bootstrap host")
    snapshot = snapshot_etcd(kube, args, executor, backup, remote)
    roster = json.loads((MODULE / "overlay-boot-peers.json").read_text())
    require(roster["hosts"].get(identity["hostname"]) == identity["node_id"],
            "node identity changed before etcd retirement")
    roster.setdefault("node_states", {})[identity["hostname"]] = {
        "state": "stopped", "reason": "operator requested node retirement"}
    intent = {"schema_version": 1, "executor_node": executor,
              "retirements": [{**member, **snapshot}]}
    with tempfile.TemporaryDirectory(prefix="etcd-intent-", dir=state_dir) as temporary:
        root = Path(temporary)
        for name, value in (("intent.json", intent), ("roster.json", roster)):
            path = root / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump(value, out)
        run(["python3", ROOT / "scripts/reconcile-etcd-retirements.py", "--kubeconfig", args.kubeconfig,
             "--kubectl", args.kubectl, "--intent", root / "intent.json", "--roster", root / "roster.json", "--backup-dir", backup])


def commit_retirement(args, inventory, declarations):
    """Prepare a commit away from the operator's checkout, then fast-forward it."""
    if not inventory and not declarations:
        return
    worktrees = args.work_dir / "retirement-worktrees"
    worktrees.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(worktrees, 0o700)
    temporary = Path(tempfile.mkdtemp(prefix=args.hostname + "-", dir=worktrees))
    attached = False
    try:
        run(["git", "worktree", "add", "--detach", temporary, "HEAD"], capture=True)
        attached = True
        changed = []
        if inventory:
            apply_inventory(temporary, inventory)
            run(["python3", temporary / "deploy/terraform/master-only/render.py"])
            run(["python3", temporary / "deploy/gitops/public-dns-quorum/render.py"])
            changed.extend(list(inventory["updates"]) + [Path("deploy/gitops/standard-nodes/nodes.yaml"),
                           Path("deploy/gitops/standard-nodes/node-policy.yaml"),
                           Path("deploy/gitops/public-dns-quorum/workloads.yaml")])
        for path, content in declarations.items():
            (temporary / path).write_text(content)
            changed.append(path)
        run(["git", "-C", temporary, "add", "--", *changed])
        require(not run(["git", "-C", temporary, "diff", "--name-only"], capture=True).strip(),
                "rendering changed files outside the retirement plan")
        run(["git", "-C", temporary, "commit", "-m", "Retire HeteroNetwork node " + args.hostname])
        commit = run(["git", "-C", temporary, "rev-parse", "HEAD"], capture=True).strip()
        require(not run(["git", "status", "--porcelain"], capture=True).strip(),
                "the infrastructure checkout changed during retirement")
        run(["git", "merge", "--ff-only", commit])
    finally:
        if attached:
            run(["git", "worktree", "remove", "--force", temporary], capture=True)
        else:
            shutil.rmtree(temporary, ignore_errors=True)


def require_no_static_references(identity, proposed=None):
    # Refuse to publish an incomplete removal. These files are owned by
    # separate service controllers rather than the shared host inventory.
    paths = ["deploy/environments/heteronet/values.yaml",
             "deploy/gitops/applications/heterocloud.yaml",
             "deploy/gitops/applications/heterocloud-flash.yaml",
             "deploy/gitops/applications/heterocloud-vpc.yaml",
             "deploy/gitops/applications/heterocloud-syouyu.yaml",
             "deploy/gitops/envoy-gateway/public-web-dns.yaml",
             "deploy/gitops/custom-domains/infrastructure.yaml"]
    patterns = [re.compile(r"(?<![A-Za-z0-9-])" + re.escape(identity["hostname"]) + r"(?![A-Za-z0-9-])"),
                re.compile(r"(?<![0-9])" + re.escape(identity["vpn_ip"]) + r"(?![0-9])")]
    proposed = proposed or {}
    pending = [name for name in paths if any(p.search(proposed.get(Path(name), (ROOT / name).read_text())) for p in patterns)]
    require(not pending, "service configuration still references the target: " + ", ".join(pending))


def ensure_application_values(kube, name):
    """Converge the Terraform-owned Helm values even with legacy field owners."""
    desired = yaml.safe_load((ROOT / "deploy/gitops/applications" / (name + ".yaml")).read_text())
    desired_source = desired["spec"]["source"]
    values = desired_source["helm"]["values"]
    for _ in range(3):
        live = kube.get("application", name, "-n", "argocd")
        source = live["spec"]["source"]
        require(source.get("repoURL") == desired_source.get("repoURL") and
                source.get("chart") == desired_source.get("chart"),
                "Argo application source changed during retirement: " + name)
        if yaml.safe_load(source.get("helm", {}).get("values", "")) == yaml.safe_load(values):
            return
        require("helm" in source, "Argo application's Helm configuration is missing: " + name)
        path = "/spec/source/helm/values"
        patch = [{"op": "test", "path": "/metadata/uid", "value": live["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": live["metadata"]["resourceVersion"]},
                 {"op": "replace" if "values" in source["helm"] else "add", "path": path, "value": values}]
        try:
            kube.patch("argocd", "application", name, patch)
        except ValueError:
            # Resource version conflicts are safe to retry only after re-reading.
            continue
    live = kube.get("application", name, "-n", "argocd")
    require(yaml.safe_load(live["spec"]["source"].get("helm", {}).get("values", "")) == yaml.safe_load(values),
            "Argo application values did not converge: " + name)


def gitops(kube, args, password, declarations):
    run(["python3", ROOT / "scripts/publish-master-only.py", "--committed-only", "--work-dir", args.work_dir])
    env = dict(os.environ, KUBECONFIG=str(args.kubeconfig), TF_VAR_kubeconfig_path=str(args.kubeconfig),
               TF_VAR_ssh_private_key_path=str(args.ssh_key), TF_VAR_work_dir=str(args.work_dir),
               HNN_IAC_BECOME_PASSWORD=password)
    command = [args.terraform, "-chdir=" + str(MODULE), "apply", "-auto-approve", "-input=false", "-parallelism=1",
               "-target=terraform_data.git_source", "-target=terraform_data.overlay_boot_recovery",
               "-target=kubernetes_manifest.public_dns_quorum_application"]
    changed_apps = [name for name in ("heterocloud", "heterocloud-flash", "heterocloud-vpc", "heterocloud-syouyu")
                    if Path("deploy/gitops/applications/" + name + ".yaml") in declarations]
    for name in changed_apps:
            command.append('-target=kubernetes_manifest.external_application["' + name + '"]')
    run(command, env=env)
    revision = run(["git", "rev-parse", "HEAD"], capture=True).strip()
    for name in changed_apps:
        ensure_application_values(kube, name)
    for app in ("standard-nodes", "public-dns-quorum", *changed_apps):
        run([args.kubectl, "--kubeconfig", args.kubeconfig, "-n", "argocd", "annotate", "app", app,
             "argocd.argoproj.io/refresh=hard", "--overwrite"], capture=True)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        apps = [kube.get("application", name, "-n", "argocd") for name in ("standard-nodes", "public-dns-quorum")]
        # Standard-node resources marked Prune=false can remain OutOfSync until
        # their explicitly UID-guarded deletion below.
        changed = [kube.get("application", name, "-n", "argocd") for name in changed_apps]
        if (all(a.get("status", {}).get("sync", {}).get("revision") == revision for a in apps) and
                all(a.get("status", {}).get("sync", {}).get("status") == "Synced" and
                    a.get("status", {}).get("health", {}).get("status") == "Healthy" for a in changed)):
            return revision
        time.sleep(2)
    raise ValueError("Argo CD did not observe the published infrastructure revision")


def retire(args):
    require(SAFE_NAME.fullmatch(args.hostname), "invalid node name")
    require(args.kubeconfig.is_file() and args.ssh_key.is_file(), "kubeconfig and SSH key are required")
    require((args.work_dir / "known_hosts").is_file(), "the operator known_hosts file is required")
    os.environ["KUBECONFIG"] = str(args.kubeconfig)
    kube = Kube(args.kubectl)
    state_dir = args.state_dir or args.work_dir / "node-retirements" / args.hostname
    identity, new_record = load_identity(args.hostname, state_dir)
    ipaddress.ip_address(identity["vpn_ip"])
    executor = json.loads((MODULE / "etcd-retirements.json").read_text())["executor_node"]
    checked = kubernetes_preflight(kube, str(args.kubeconfig), executor, identity, offline_retirement=True)
    if checked["node_uid"]:
        identity["kubernetes_uid"] = checked["node_uid"]
    if checked.get("pod_cidr"):
        identity["pod_cidr"] = checked["pod_cidr"]
    password = os.environ.get("HNN_IAC_BECOME_PASSWORD") or getpass.getpass("Bootstrap sudo password: ")
    bootstrap = json.loads((MODULE / "edge-nodes.json").read_text())["bootstrap"]
    remote = Remote(bootstrap["ssh_host"], args.ssh_user, args.ssh_key, args.work_dir / "known_hosts", password)
    database = remote.database_absent(identity)
    registration = remote.registration(identity, False)
    dns = reconcile_dns(args.kubectl, str(args.kubeconfig), identity["vpn_ip"], False)
    declarations = plan_declarations(ROOT, identity, checked.get("pod_cidr"), checked.get("workers", []))
    require_no_static_references(identity, declarations)
    roster = json.loads((MODULE / "overlay-boot-peers.json").read_text())
    # The generated plan is not applied until the existing voter has actually
    # been removed below. Preflight also supports a read-only dry run.
    inventory = plan_inventory(ROOT, args.hostname, etcd_member_absent=True, offline_retirement=True) if args.hostname in roster["hosts"] else None
    if inventory and new_record:
        require(checked["node_present"], "an offline Kubernetes node is required to retire an unrecorded host")
    if inventory is None:
        require(identity["node_id"] not in roster["hosts"].values() and
                all(p.get("vpn_ip") != identity["vpn_ip"] for p in roster["peers"]),
                "saved node identity was reused in the inventory")
    summary = {"node": args.hostname, "database": database["result"], "network": registration["result"],
               "kubernetes_node": checked["node_present"], "etcd_voter": bool(checked.get("etcd_member")),
               "stale_pods": len(checked["pods"]),
               "longhorn_node": bool(checked["longhorn"]), "dns_change": dns["changed"],
               "inventory_change": inventory is not None, "service_declarations": len(declarations)}
    if args.dry_run:
        print(json.dumps({**summary, "result": "preflight_passed"}, ensure_ascii=False))
        return 0
    require(not run(["git", "status", "--porcelain"], capture=True).strip(),
            "the infrastructure checkout has unrelated uncommitted changes")
    require(run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], capture=True).strip() == "master",
            "the infrastructure checkout must be on master")
    if new_record:
        save_identity(new_record, identity)
    pending = pending_applications(state_dir, declarations)
    fence_offline_node(kube, checked)
    retire_etcd_member(kube, args, identity, checked.get("etcd_member"), state_dir, executor, remote)
    kubernetes_preflight(kube, str(args.kubeconfig), executor, identity)
    commit_retirement(args, inventory, declarations)
    if not args.no_push:
        # Also retry a previously failed push when there are no new edits.
        run(["git", "push", "origin", "HEAD:master"])
    revision = gitops(kube, args, password, pending)
    # Distribute the new roster and clear stopped-address firewall rules
    # before releasing the address for assignment to another VPN client.
    remote.registration(identity, True)
    reconcile_dns(args.kubectl, str(args.kubeconfig), identity["vpn_ip"], True)
    result = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        checked = kubernetes_preflight(kube, str(args.kubeconfig), executor, identity)
        if not checked["node_present"] and not checked["longhorn"] and not checked["pods"]:
            break
        try:
            result = delete_kubernetes_objects(kube, args.hostname, checked)
        except ValueError:
            # A controller may concurrently delete an old pod. Re-read all
            # identities and prerequisites before attempting another delete.
            pass
        time.sleep(2)
    else:
        raise ValueError("Kubernetes objects did not disappear; rerun the command to resume")
    while time.monotonic() < deadline:
        effective = kube.get("configmap", "heteronetwork-overlay-dns-effective", "-n", "kube-system")
        zone = json.loads(effective["data"]["records.json"])
        if not contains_address(zone, identity["vpn_ip"]):
            break
        time.sleep(2)
    else:
        raise ValueError("effective overlay DNS still references the retired address")
    require(remote.registration(identity, False)["result"] == "already_absent",
            "network registration reappeared during retirement")
    remote.database_absent(identity)
    (state_dir / "pending-applications.json").unlink(missing_ok=True)
    print(json.dumps({**summary, **(result or {}), "result": "retired", "revision": revision}, ensure_ascii=False))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="kind", required=True)
    node = sub.add_parser("node")
    actions = node.add_subparsers(dest="action", required=True)
    remove = actions.add_parser("retire", help="retire a stopped physical worker")
    remove.add_argument("hostname")
    remove.add_argument("--work-dir", type=Path, default=default_work_dir())
    remove.add_argument("--kubeconfig", type=Path)
    remove.add_argument("--ssh-key", type=Path, default=Path(os.environ.get("TF_VAR_ssh_private_key_path", str(ROOT / ".key"))).expanduser())
    remove.add_argument("--ssh-user", default=os.environ.get("HNN_IAC_SSH_USER", "mizuame"))
    remove.add_argument("--kubectl", default="kubectl")
    remove.add_argument("--terraform", default="terraform")
    remove.add_argument("--state-dir", type=Path)
    remove.add_argument("--dry-run", action="store_true")
    remove.add_argument("--no-push", action="store_true")
    args = parser.parse_args()
    if args.kubeconfig is None:
        args.kubeconfig = default_kubeconfig(args.work_dir)
    try:
        with kube_tunnel(args):
            return retire(args)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print("Node retirement stopped: " + str(error), file=sys.stderr)
        return 1
