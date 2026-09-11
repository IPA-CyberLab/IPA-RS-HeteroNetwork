#!/usr/bin/env python3
"""Provision inactive host attestation keys locally on the three pinned DEV guests."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.dont_write_bytecode = True
ROOT = Path("/etc/ipars-sudo-v2")
DKG_HELPER = Path("/opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py")
DKG_SHA = "0fc2ac15c65cb2a69fee5a15157d02476afdc0284629c44d45f299d4d48c7cfe"
MANIFEST_SHA = "ec4d9c6cccac45a8afa56544279b28382af6dd9e885c25a3f478da9e61e99235"


def require(value):
    if not value:
        raise ValueError("DEV inactive host-key provisioning rejected")


def trusted(path, mode=None, directory=False):
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
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                and not info.st_mode & 0o7022 and info.st_size <= limit)
        require(mode is None or stat.S_IMODE(info.st_mode) == mode)
        data = stream.read(limit + 1)
        require(len(data) <= limit)
        return data


def load_dkg():
    require(hashlib.sha256(read(DKG_HELPER, 65536)).hexdigest() == DKG_SHA)
    spec = importlib.util.spec_from_file_location("dev_dkg", DKG_HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sudo_snapshot():
    for value in ("/run/ipars-sudo-v2", "/var/lib/ipars-sudo-v2"):
        require(not os.path.lexists(value))
    paths = [Path("/etc/sudoers"), Path("/etc/sudo.conf")]
    directory = Path("/etc/sudoers.d")
    if os.path.lexists(directory):
        trusted(directory, directory=True)
        paths.extend(sorted(directory.iterdir()))
    result = {}
    for path in paths:
        if not os.path.lexists(path):
            result[str(path)] = None
            continue
        info = trusted(path)
        data = read(path, 1048576)
        if path == Path("/etc/sudo.conf"):
            for line in data.decode("utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                require(not line.endswith("\\") and (not line or line.split()[0].lower() != "plugin"))
        result[str(path)] = (info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                             hashlib.sha256(data).hexdigest())
    return result


def record(dkg, member, public_key):
    name, machine, node = dkg.GUESTS[member - 1]
    require(len(public_key) == 32)
    return {"schema_version": 1, "guest": name, "machine_id": machine,
            "cluster_id": dkg.CLUSTER, "host_node_id": node,
            "manifest_file_sha256": MANIFEST_SHA, "attestation_key_epoch": 1,
            "attestation_public_key": list(public_key)}


def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def provision(dkg, member):
    before = sudo_snapshot()
    trusted(ROOT.parent, directory=True)
    created = not os.path.lexists(ROOT)
    if created:
        ROOT.mkdir(mode=0o700)
        parent = os.open(ROOT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    trusted(ROOT, mode=0o700, directory=True)
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require({p.name for p in ROOT.iterdir()} == (set() if created else {"host.key", "host-public.json"}))
        if created:
            key = Ed25519PrivateKey.generate()
            seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())
            write_new(ROOT / "host.key", seed)
            del seed
            value = record(dkg, member, public_bytes(key))
            write_new(ROOT / "host-public.json", (json.dumps(value, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        # Always derive the public pin from the actual stored private key locally.
        seed = read(ROOT / "host.key", 32, mode=0o600)
        require(len(seed) == 32)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        del seed
        value = record(dkg, member, public_bytes(key))
        observed = dkg.decode(read(ROOT / "host-public.json", 8192, mode=0o600))
        require(observed == value)
        require(sudo_snapshot() == before)
        return {"created": created, "public_record": value,
                "sudo_configuration_unchanged": True, "activation_performed": False,
                "private_key_exported": False}
    finally:
        os.close(fd)


def main():
    require(len(sys.argv) == 1 and os.getuid() == 0 and os.geteuid() == 0)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    dkg = load_dkg()
    member = dkg.check_identity()
    require(dkg.inspect(member)["manifest_file_sha256"] == MANIFEST_SHA)
    print(json.dumps(provision(dkg, member), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("DEV host-key provisioning stopped; preserve existing files for inspection", file=sys.stderr)
        sys.exit(1)
