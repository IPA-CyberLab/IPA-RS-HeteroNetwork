#!/usr/bin/env python3
"""Deploy and run the inactive DEV host-key provisioner on exactly three guests."""
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time

SOURCE = Path("/opt/heteronetwork-dev-sudo-host-keys/provision-dev-sudo-host-key.py")
SOURCE_SHA = "f0e8c9437d3a9e108de253bf3aff1cd66c30078e52b363168bc32cf6254f2fff"
DEST = "/opt/heteronetwork-dev-sudo-host-key-f0e8c943/provision-dev-sudo-host-key.py"
SSH = ["/usr/bin/ssh", "-F", "/dev/null", "-i", "/var/lib/hetero-dev-provisioner/admin_ed25519",
       "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=/var/lib/hetero-dev-provisioner/known_hosts"]
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
GUESTS = (
    ("hetero-dev-1", "381d1ae16f555c59b738d8d01dd14c94", "node-e52856163b2fb3a1d67fc03943cbdda2"),
    ("hetero-dev-2", "acc5151b6b245b63864372933dab97da", "node-65bbb4982793bf94af58d9a2506c4fca"),
    ("hetero-dev-3", "165a6e8acc3a56fdbf9bef8c90d6cf4d", "node-dfdf53799602bd2aa9006121c33af69a"),
)
LIMIT = 128 * 1024


def require(value):
    if not value:
        raise ValueError("DEV host-key deployment rejected")


def trusted(path, private=False):
    path = Path(path)
    require(path.is_absolute())
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
            and not info.st_mode & (0o077 if private else 0o022))
    return info


def invoke(member, arguments, data=None):
    require(member in (1, 2, 3) and (data is None or len(data) <= LIMIT))
    process = subprocess.Popen([*SSH, f"devadmin@172.28.240.{10 + member}", shlex.join(arguments)],
                               stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=ENV, start_new_session=True)
    output = bytearray()
    remaining = memoryview(data or b"")
    deadline = time.monotonic() + 80
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            if process.stdin is not None:
                if remaining:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE)
                else:
                    process.stdin.close()
            while selector.get_map():
                left = deadline - time.monotonic()
                require(left > 0)
                for key, _ in selector.select(left):
                    if key.fileobj is process.stdout:
                        chunk = os.read(key.fd, min(4096, LIMIT + 1 - len(output)))
                        if chunk:
                            output.extend(chunk)
                            require(len(output) <= LIMIT)
                        else:
                            selector.unregister(key.fileobj)
                    else:
                        written = os.write(key.fd, remaining[:4096])
                        remaining = remaining[written:]
                        if not remaining:
                            selector.unregister(key.fileobj)
                            process.stdin.close()
            require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0)
        return bytes(output)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        process.stdout.close()
        if process.stdin is not None:
            process.stdin.close()


INSTALL = r'''import hashlib,json,os,pathlib,socket,stat,sys
guests={
 "hetero-dev-1":"381d1ae16f555c59b738d8d01dd14c94",
 "hetero-dev-2":"acc5151b6b245b63864372933dab97da",
 "hetero-dev-3":"165a6e8acc3a56fdbf9bef8c90d6cf4d"}
dest=pathlib.Path("/opt/heteronetwork-dev-sudo-host-key-f0e8c943")
path=dest/"provision-dev-sudo-host-key.py"
expected="f0e8c9437d3a9e108de253bf3aff1cd66c30078e52b363168bc32cf6254f2fff"
assert os.getuid()==0 and os.geteuid()==0 and socket.gethostname() in guests
assert pathlib.Path("/etc/machine-id").read_text().strip()==guests[socket.gethostname()]
raw=sys.stdin.buffer.read(131073); assert len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==expected
for parent in reversed(dest.parents):
 s=parent.lstat(); assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
created=not os.path.lexists(dest)
if created: dest.mkdir(mode=0o700)
s=dest.lstat(); assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
if created:
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as target: target.write(raw); target.flush(); os.fsync(target.fileno())
 parent=os.open(dest,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(parent); os.close(parent)
s=path.lstat(); assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
assert path.read_bytes()==raw
print(json.dumps({"guest":socket.gethostname(),"script_created":created,"source_sha256":expected}))
'''


def deploy(member, raw):
    expected_name, expected_machine, expected_node = GUESTS[member - 1]
    receipt = json.loads(invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B", "-c", INSTALL], raw))
    require(receipt["guest"] == expected_name and receipt["source_sha256"] == SOURCE_SHA
            and type(receipt["script_created"]) is bool)
    result = json.loads(invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B", DEST]))
    public = result["public_record"]
    require(public["guest"] == expected_name and public["machine_id"] == expected_machine
            and public["host_node_id"] == expected_node and public["attestation_key_epoch"] == 1
            and len(public["attestation_public_key"]) == 32
            and result["sudo_configuration_unchanged"] is True
            and result["private_key_exported"] is False and result["activation_performed"] is False)
    return {"member": member, "script_created": receipt["script_created"],
            "key_created": result["created"], "public_record": public,
            "activation_performed": False, "private_key_exported": False}


def main():
    try:
        require(len(sys.argv) == 1 and os.getuid() == 0 and os.geteuid() == 0
                and socket.gethostname() == "ichikawap1")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        trusted(SOURCE, private=True)
        raw = SOURCE.read_bytes()
        require(len(raw) <= LIMIT and hashlib.sha256(raw).hexdigest() == SOURCE_SHA)
        for path in (Path(SSH[4]), Path("/var/lib/hetero-dev-provisioner/known_hosts")):
            trusted(path, private=True)
        results = [deploy(member, raw) for member in (1, 2, 3)]
        keys = [bytes(value["public_record"]["attestation_public_key"]) for value in results]
        require(len(set(keys)) == 3)
        print(json.dumps({"results": results, "unique_public_keys": True,
                          "activation_performed": False, "private_key_exported": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DEV host-key deployment stopped; preserve existing state for inspection", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
