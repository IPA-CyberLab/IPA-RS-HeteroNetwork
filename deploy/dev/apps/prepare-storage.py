#!/usr/bin/env python3
"""Fresh guest-only DEV app mount. No repair, adoption, PVs, or service restarts.

Run as root with no arguments, only during an exclusive planned storage window.
An intent without completion requires manual investigation, never deleting state
to retry. This helper defers kubelet guard activation to a planned reboot, without
rebooting or restarting anything itself. The mount is not current consumer
enforcement: it neither constrains existing containers nor prevents a later
external daemon-reload from activating dependencies or starting jobs. Stopping
kubelet does not stop existing containers; their lifecycle remains operator-owned.
Kubernetes identity/readiness checks are bounded, read-only snapshots, not proof
of active dependency enforcement. The helper never reads credential contents;
kubectl alone uses the pinned root-owned admin.conf for these API queries.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid

CLUSTER = "02282a57-784b-4269-90a0-8fda47ee62ec"
K8S_UID = "a39281cb-d273-4c5f-b7a7-fca722fb417b"  # Not the native cluster ID.
MOUNT = Path("/var/lib/heteronetwork-dev-app-storage")
STATE = Path("/var/lib/heteronetwork-dev-app-storage-state")
SYSTEMD = Path("/etc/systemd/system")
KUBECONFIG = Path("/etc/kubernetes/admin.conf")
DROPIN = SYSTEMD / "kubelet.service.d/90-hnapp-storage.conf"
SIZE = 64 * 1024**3
# Same UUID allocation as scripts/provision-dev-libvirt.py and bootstrap-dev-guest.py.
MACHINES = {f"hetero-dev-{i}": uuid.uuid5(
    uuid.NAMESPACE_URL, f"urn:heteronetwork:dev:ichikawap1:domain:hetero-dev-{i}"
).hex for i in range(1, 4)}


def require(value):
    if not value:
        raise ValueError("DEV app storage prerequisites rejected")


def run(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=180, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(result.returncode == 0 and len(result.stdout) < 4 * 1024**2)
    return result.stdout.decode("utf-8")


def root_path(path, directory=False, private=True):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022))
    require(stat.S_ISDIR(info.st_mode) if directory else
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


def mkdir(path):
    root_path(path.parent, directory=True, private=False)
    try:
        path.mkdir(mode=0o700)
        sync_dir(path.parent)
    except FileExistsError:
        pass
    root_path(path, directory=True)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, content):
    root_path(path.parent, directory=True, private=False)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600), "w") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    sync_dir(path.parent)


def read_private(path):
    root_path(path)
    require(path.stat().st_size < 1024**2)
    return path.read_text()


def exists(path):
    return path.exists() or path.is_symlink()


def identity():
    require(os.getuid() == 0 and os.geteuid() == 0)
    host = socket.gethostname()
    require(host in MACHINES)
    machine = MACHINES[host]
    require(Path("/etc/machine-id").read_text().strip() == machine)
    require(Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower()
            == str(uuid.UUID(hex=machine)))
    # This bootstrap manifest contains identity and file hashes, not token contents.
    config = json.loads(read_private(Path("/opt/heteronetwork-dev-bootstrap/bootstrap.json")))
    require(config["cluster_id"] == CLUSTER and config["guest"]["name"] == host
            and config["guest"]["machine_id"] == machine
            and config["guest"]["product_uuid"] == str(uuid.UUID(hex=machine)))
    return {"host": host, "machine_id": machine, "cluster_id": CLUSTER,
            "kube_system_uid_expected": K8S_UID, "serial": "hnapp-" + machine[:12]}


def verify_cluster():
    root_path(KUBECONFIG)
    args = ("kubectl", "--kubeconfig=" + str(KUBECONFIG), "--request-timeout=10s")
    namespace = json.loads(run(*args, "get", "namespace", "kube-system", "--output=json"))
    require(namespace["metadata"]["name"] == "kube-system"
            and namespace["metadata"]["uid"] == K8S_UID
            and not namespace["metadata"].get("deletionTimestamp"))
    nodes = json.loads(run(*args, "get", "nodes", "--output=json"))["items"]
    require(len(nodes) == 3 and {n["metadata"]["name"] for n in nodes} == set(MACHINES))
    for node in nodes:
        require(not node["metadata"].get("deletionTimestamp"))
        ready = [c for c in node["status"]["conditions"] if c["type"] == "Ready"]
        require(len(ready) == 1 and ready[0]["status"] == "True")


def flatten(nodes):
    for node in nodes:
        yield node
        yield from flatten(node.get("children", []))


def validate_device(inventory, serial, mounted, swaps, holders, signatures, fresh=True):
    """Pure validation; reject ambiguous topology and every fresh-disk use/signature."""
    nodes = list(flatten(inventory["blockdevices"]))
    matches = [n for n in nodes if n.get("serial") == serial]
    require(len(matches) == 1)
    disk = matches[0]
    require(disk["type"] == "disk" and disk["size"] == SIZE and not disk["ro"])
    require(re.fullmatch(r"/dev/vd[a-z]+", disk["path"]) is not None)
    require(re.fullmatch(r"[0-9]+:[0-9]+", disk["maj:min"]) is not None)
    require(not disk.get("children") and not disk.get("pkname") and not holders)
    require(not swaps)
    require(all(n is disk or n.get("pkname") not in (disk["path"], disk["name"])
                for n in nodes))
    uses = [m for m in mounted if m["maj:min"] == disk["maj:min"]]
    if fresh:
        require(not uses and not any(disk["mountpoints"]) and not signatures)
        require(not disk.get("fstype") and not disk.get("uuid") and not disk.get("pttype"))
    else:
        require(all(m["target"] == str(MOUNT) for m in uses))
        require(all(p in (None, str(MOUNT)) for p in disk["mountpoints"]))
        require(disk["fstype"] == "ext4" and not disk.get("pttype"))
        require(len(signatures) == 1 and signatures[0]["type"] == "ext4")
        require(signatures[0]["uuid"] == disk["uuid"] and disk["uuid"])
        require(sum(n.get("uuid") == disk["uuid"] for n in nodes) == 1)
    return disk


def mount_inventory():
    return list(flatten(json.loads(run("findmnt", "--json", "--list", "--output",
                                      "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,FSROOT"))["filesystems"]))


def inspect(serial, fresh=True):
    inventory = json.loads(run("lsblk", "--json", "--bytes", "--paths", "--output",
                               "NAME,PATH,TYPE,SIZE,RO,SERIAL,MAJ:MIN,PKNAME,MOUNTPOINTS,FSTYPE,UUID,PTTYPE"))
    candidates = [n for n in flatten(inventory["blockdevices"]) if n.get("serial") == serial]
    require(len(candidates) == 1)
    disk = candidates[0]
    require(re.fullmatch(r"/dev/vd[a-z]+", disk["path"]) is not None)
    require(re.fullmatch(r"[0-9]+:[0-9]+", disk["maj:min"]) is not None)
    props = dict(line.split("=", 1) for line in run(
        "udevadm", "info", "--query=property", "--name", disk["path"]).splitlines() if "=" in line)
    require(props.get("ID_SERIAL") == serial and props.get("DEVTYPE") == "disk")
    info = Path(disk["path"]).stat()
    require(stat.S_ISBLK(info.st_mode) and f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" == disk["maj:min"])
    holders = list((Path("/sys/dev/block") / disk["maj:min"] / "holders").iterdir())
    swaps = json.loads(run("swapon", "--show", "--json", "--output", "NAME"))["swapdevices"]
    # A swapfile can hide storage ancestry; no active swap is allowed in this workflow.
    require(not swaps)
    signatures = json.loads(run("wipefs", "--no-act", "--json", "--output", "TYPE,UUID",
                                disk["path"]))["signatures"]
    return validate_device(inventory, serial, mount_inventory(), [], holders, signatures, fresh)


def unit_files(fs_uuid):
    require(str(uuid.UUID(fs_uuid)) == fs_uuid)
    name = run("systemd-escape", "--path", "--suffix=mount", str(MOUNT)).strip()
    require(re.fullmatch(r"[a-zA-Z0-9\\x.-]+\.mount", name) is not None and "/" not in name)
    device = run("systemd-escape", "--path", "--suffix=device", "/dev/disk/by-uuid/" + fs_uuid).strip()
    require(re.fullmatch(r"[a-zA-Z0-9\\x.-]+\.device", device) is not None)
    unit = ("[Unit]\nDescription=Dedicated DEV app storage\n"
            f"Requires={device}\nBindsTo={device}\nAfter={device}\nJobTimeoutSec=120\n"
            f"[Mount]\nWhat=/dev/disk/by-uuid/{fs_uuid}\nWhere={MOUNT}\n"
            "Type=ext4\nOptions=rw,nodev,nosuid\nTimeoutSec=90\n"
            "[Install]\nWantedBy=local-fs.target\n")
    guard = ("[Unit]\n" + f"RequiresMountsFor={MOUNT}\nRequires={name}\n"
             f"BindsTo={name}\nAfter={name}\nAssertPathIsMountPoint={MOUNT}\n")
    return name, unit, guard


def paths(name):
    return SYSTEMD / name, SYSTEMD / "local-fs.target.wants" / name


def no_runtime_guard():
    require(not exists(Path("/run/systemd/system/kubelet.service.d") / DROPIN.name))


def verify_files(name, unit, guard):
    path, link = paths(name)
    require(read_private(path) == unit and read_private(DROPIN) == guard)
    root_path(link.parent, directory=True, private=False)
    require(link.is_symlink() and link.lstat().st_uid == 0 and os.readlink(link) == str(path))
    require(not exists(SYSTEMD / (name + ".d")))
    require(not exists(Path("/run/systemd/system") / name)
            and not exists(Path("/run/systemd/system") / (name + ".d")))
    no_runtime_guard()
    require(run("systemctl", "show", name, "--property=FragmentPath", "--value").strip() == str(path))
    require(not run("systemctl", "show", name, "--property=DropInPaths", "--value").strip())


def verify_mount(disk, fs_uuid, private=True):
    require(disk["uuid"] == fs_uuid)
    mounts = mount_inventory()
    matches = [m for m in mounts if m["target"] == str(MOUNT)]
    require(len(matches) == 1)
    mounted = matches[0]
    require(mounted["maj:min"] == disk["maj:min"] and mounted["fstype"] == "ext4"
            and mounted["fsroot"] == "/"
            and {"rw", "nodev", "nosuid"} <= set(mounted["options"].split(",")))
    require(not any(m["target"].startswith(str(MOUNT) + "/") for m in mounts))
    root_path(MOUNT, directory=True, private=private)
    require(MOUNT.stat().st_dev == os.makedev(*map(int, disk["maj:min"].split(":"))))


def status(who, created):
    return {**who, "created": created, "mount_only_ready": True,
            "app_provisioning_ready": False, "kubernetes_applied": False,
            "kubernetes_cluster_uid_verified": True,
            "kubernetes_ready_nodes_verified": sorted(MACHINES),
            "kubernetes_verification_is_snapshot": True,
            "active_kubelet_dependency_validated": False,
            "consumer_enforcement_validated": False,
            "guard_activation_deferred_by_helper": True,
            "external_daemon_reload_may_activate_guard": True,
            "planned_reboot_required": True}


def transaction(who):
    intent_path, complete_path = STATE / "intent.json", STATE / "complete.json"
    if exists(intent_path):
        intent = json.loads(read_private(intent_path))
        # Even a successfully formatted/mounted disk is not adopted after interruption.
        require(exists(complete_path))
        require(json.loads(read_private(complete_path)) == intent)
        require(set(intent) == {"identity", "fs_uuid", "size", "purpose"}
                and intent["identity"] == who and intent["size"] == SIZE
                and intent["purpose"] == str(MOUNT))
        verify_cluster()
        name, unit, guard = unit_files(intent["fs_uuid"])
        verify_files(name, unit, guard)
        verify_mount(inspect(who["serial"], fresh=False), intent["fs_uuid"])
        return status(who, False)
    require(not exists(complete_path))
    require(not any(STATE.iterdir()))
    disk = inspect(who["serial"])
    require(not any(m["target"] == str(MOUNT) or m["target"].startswith(str(MOUNT) + "/")
                    for m in mount_inventory()))
    mkdir(MOUNT)
    require(not any(MOUNT.iterdir()))
    fs_uuid = str(uuid.uuid4())
    name, unit, guard = unit_files(fs_uuid)
    path, link = paths(name)
    root_path(SYSTEMD, directory=True, private=False)
    no_runtime_guard()
    require(not any(exists(p) for p in (path, link, DROPIN, SYSTEMD / (name + ".d"),
                Path("/run/systemd/system") / name, Path("/run/systemd/system") / (name + ".d"))))
    require(not run("systemctl", "show", name, "--property=FragmentPath", "--value").strip())
    require(not run("systemctl", "show", name, "--property=DropInPaths", "--value").strip())
    for parent in (DROPIN.parent, link.parent):
        if exists(parent):
            root_path(parent, directory=True, private=False)
    verify_cluster()
    intent = {"identity": who, "fs_uuid": fs_uuid, "size": SIZE, "purpose": str(MOUNT)}
    record = json.dumps(intent, sort_keys=True) + "\n"
    write_new(intent_path, record)
    # Revalidate after the durable, exclusive intent, immediately before the sole mkfs.
    require(inspect(who["serial"]) == disk)
    run("mkfs.ext4", "-q", "-U", fs_uuid, "-m", "0", disk["path"])
    run("udevadm", "settle", "--timeout=30")
    observed = inspect(who["serial"], fresh=False)
    require(observed["uuid"] == fs_uuid and observed["maj:min"] == disk["maj:min"])
    write_new(path, unit)
    if not exists(link.parent):
        mkdir(link.parent)
    os.symlink(str(path), link)
    sync_dir(link.parent)
    # Load/start the mount before adding any new kubelet dependencies.
    run("systemctl", "daemon-reload")
    run("systemctl", "start", name)
    verify_mount(inspect(who["serial"], fresh=False), fs_uuid, private=False)
    os.chmod(MOUNT, 0o700, follow_symlinks=False)
    verify_mount(inspect(who["serial"], fresh=False), fs_uuid)
    if not exists(DROPIN.parent):
        mkdir(DROPIN.parent)
    write_new(DROPIN, guard)
    # Deliberately no reload/restart after installing the guard. A reboot activates it.
    verify_files(name, unit, guard)
    write_new(complete_path, record)
    return status(who, True)


def prepare():
    who = identity()
    mkdir(STATE)
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return transaction(who)
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 1)
        print(json.dumps(prepare(), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DEV app storage stopped; preserve disk, journal, and units for manual review",
              file=sys.stderr)
        sys.exit(1)
