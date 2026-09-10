#!/usr/bin/env python3
"""Prepare only a fresh identity PV directory on its pinned DEV guest."""
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import sys

CLUSTER = "02282a57-784b-4269-90a0-8fda47ee62ec"
PARENT = Path("/var/lib/heteronetwork-dev-storage")
DATA = PARENT / "identity-postgres"
MARKER = PARENT / "identity-postgres-allocation.json"
MACHINES = {
    "hetero-dev-1": "381d1ae16f555c59b738d8d01dd14c94",
    "hetero-dev-2": "acc5151b6b245b63864372933dab97da",
    "hetero-dev-3": "165a6e8acc3a56fdbf9bef8c90d6cf4d",
}


def require(condition):
    if not condition:
        raise ValueError("DEV storage prerequisites rejected")


def root_path(path, directory=False):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o077)
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


def prepare():
    require(os.getuid() == 0 and os.geteuid() == 0)
    host = socket.gethostname()
    require(host in MACHINES)
    machine = Path("/etc/machine-id").read_text().strip()
    require(machine == MACHINES[host])
    require(Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower().replace("-", "") == machine)
    bootstrap = Path("/opt/heteronetwork-dev-bootstrap/bootstrap.json")
    root_path(bootstrap)
    require(bootstrap.stat().st_size < 1024 * 1024)
    config = json.loads(bootstrap.read_bytes())
    require(config["cluster_id"] == CLUSTER and config["guest"]["name"] == host
            and config["guest"]["machine_id"] == machine)
    for path in (Path("/var"), Path("/var/lib")):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    try:
        PARENT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    root_path(PARENT, directory=True)
    fd = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        created = False
        if MARKER.exists() or MARKER.is_symlink():
            root_path(MARKER)
            require(MARKER.stat().st_size < 4096)
            record = json.loads(MARKER.read_bytes())
            info = DATA.lstat()
            require(record == {"cluster_id": CLUSTER, "host": host, "machine_id": machine,
                               "path": str(DATA), "device": info.st_dev, "inode": info.st_ino})
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 26 and info.st_gid == 26
                    and not info.st_mode & 0o007)
        else:
            require(not DATA.exists() and not DATA.is_symlink())
            disk = os.statvfs(PARENT)
            require(disk.f_bavail * disk.f_frsize >= 12 * 1024**3 and disk.f_favail >= 10000)
            DATA.mkdir(mode=0o700)
            os.chown(DATA, 26, 26, follow_symlinks=False)
            info = DATA.lstat()
            record = {"cluster_id": CLUSTER, "host": host, "machine_id": machine,
                      "path": str(DATA), "device": info.st_dev, "inode": info.st_ino}
            with os.fdopen(os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as output:
                json.dump(record, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(fd)
            created = True
        return {"host": host, "created": created, "directory_prepared": True,
                "quota_enforced": False, "kubernetes_applied": False}
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 1:
            raise ValueError("no arguments accepted")
        print(json.dumps(prepare(), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError):
        print("DEV storage stopped; preserve existing directories and marker", file=sys.stderr)
        sys.exit(1)
