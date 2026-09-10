#!/usr/bin/env python3
"""Explicit, bounded DKG phases for the existing private dev guests only."""
import argparse
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

ROOT = "/var/lib/heteronetwork-dev-sudo-dkg"
HELPER = "/opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py"
SSH = ["/usr/bin/ssh", "-F", "/dev/null", "-i", "/var/lib/hetero-dev-provisioner/admin_ed25519",
       "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=/var/lib/hetero-dev-provisioner/known_hosts"]
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LIMIT = 65536


def require(condition):
    if not condition:
        raise ValueError("DEV transport check failed")


def invoke(member, arguments, data=None):
    require(member in (1, 2, 3))
    require(data is None or len(data) <= LIMIT)
    process = subprocess.Popen([*SSH, f"devadmin@172.28.240.{10 + member}", shlex.join(arguments)],
                               stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=ENV, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + 80
    remaining = memoryview(data or b"")
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
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            require(len(output) <= LIMIT)
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


def phase(member, name):
    require(name in ("preflight", "part1", "part2", "part3", "inspect"))
    result = json.loads(invoke(member, ["sudo", "-n", "/usr/bin/python3", HELPER, name]))
    require(result["member_id"] == member and result["sudo_activation_performed"] is False
            and result["signer_start_performed"] is False)
    if name != "inspect":
        require(result["phase"] == name)
    return result


def transfer(sender, recipient, round_number):
    require(sender in (1, 2, 3) and recipient in (1, 2, 3) and sender != recipient)
    require(round_number in (1, 2))
    source = f"round1-{sender}.json" if round_number == 1 else f"outgoing-round2/to-{recipient}.json"
    target = f"round1-{sender}.json" if round_number == 1 else f"round2-from-{sender}.json"
    # Only fixed protocol packet names are readable. States and final shares are never transferred.
    common = """import os,stat,sys,json,hashlib,resource
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
root='/var/lib/heteronetwork-dev-sudo-dkg'
assert os.getuid()==0
def check(path,directory=False):
 from pathlib import Path
 p=Path(path)
 for parent in reversed(p.parents):
  s=parent.lstat(); assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
 s=p.lstat(); assert s.st_uid==0 and not s.st_mode&0o077
 assert stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1
check(root,True)
"""
    send = common + f"""
path=root+{('/' + source)!r}
check(path)
with open(path,'rb') as stream: data=stream.read(65537)
assert len(data)<=65536
sys.stdout.buffer.write(data)
"""
    raw = invoke(sender, ["sudo", "-n", "/usr/bin/python3", "-c", send])
    packet = json.loads(raw)
    if round_number == 1:
        require(packet["member_id"] == sender)
    else:
        require(packet["sender"] == sender and packet["recipient"] == recipient)
    expected = hashlib.sha256(raw).hexdigest()
    receive = common + f"""
data=sys.stdin.buffer.read(65537)
assert len(data)<=65536
path=root+{('/' + target)!r}
try:
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
except FileExistsError:
 check(path)
 with open(path,'rb') as stream: assert stream.read(65537)==data
else:
 with os.fdopen(fd,'wb') as stream:
  stream.write(data); stream.flush(); os.fsync(stream.fileno())
print(json.dumps({{'received':True,'sha256':hashlib.sha256(data).hexdigest()}}))
"""
    receipt = json.loads(invoke(recipient, ["sudo", "-n", "/usr/bin/python3", "-c", receive], raw))
    require(receipt == {"received": True, "sha256": expected})
    # Never log confidential packet contents or their hashes.
    return {"sender": sender, "recipient": recipient, "round": round_number, "delivered": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("preflight", "part1", "exchange-round1", "part2",
                                          "exchange-round2", "part3", "inspect"))
    args = parser.parse_args()
    try:
        require(os.getuid() == 0 and os.geteuid() == 0 and socket.gethostname() == "ichikawap1")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for path in (Path(SSH[4]), Path("/var/lib/hetero-dev-provisioner/known_hosts")):
            for parent in reversed(path.parents):
                info = parent.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077)
        for member in (1, 2, 3):
            phase(member, "preflight")
        results = []
        if args.phase.startswith("exchange-"):
            for sender in (1, 2, 3):
                for recipient in (1, 2, 3):
                    if sender != recipient:
                        results.append(transfer(sender, recipient, int(args.phase[-1])))
        else:
            results = [phase(member, args.phase) for member in (1, 2, 3)]
            if args.phase == "inspect":
                require(len({result["manifest_file_sha256"] for result in results}) == 1)
        print(json.dumps({"phase": args.phase, "results": results}, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DEV DKG transport stopped; inspect existing phase state before retry", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
