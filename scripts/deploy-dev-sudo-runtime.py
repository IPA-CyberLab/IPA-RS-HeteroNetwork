#!/usr/bin/env python3
"""Deploy verified inactive sudo runtime files to exactly three DEV guests."""
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

BUNDLE = Path("/opt/heteronetwork-dev-sudo-runtime-deploy-v2")
FILES = {
    "provision-dev-sudo-runtime.py": ("2981556b78c5ae556278f7c2b2796c4dd262b8753a4c1649134455043bb00af6", 8754),
    "iparsd": ("dd26e9907c426fe1f2b628a5010441a4127ef26ab763195c353a8c7e09cf05bb", 64022456),
    "sudo-hosts.json": ("c28d3c1fe54d7016752bad8f3fb92652f3f1dd96b81a9271ac6b9aac95b688c8", 2117),
    "heteronetwork-sudo-local.service": ("1a7c9f32574555230056389d2b413e9db57f13a7dc4ccca3236a3735a229853d", 1180),
    "heteronetwork-sudo-quorum-signer.service": ("a7c966d14295d62ff14f645092a161b846f7b6a8b993a9d686cc8fa8849a8328", 1490),
}
SSH = ["/usr/bin/ssh", "-F", "/dev/null", "-i", "/var/lib/hetero-dev-provisioner/admin_ed25519",
       "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=/var/lib/hetero-dev-provisioner/known_hosts"]
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
INPUT_LIMIT = 128 * 1024 * 1024
OUTPUT_LIMIT = 65536


def require(value):
    if not value:
        raise ValueError("DEV inactive sudo runtime deployment rejected")


def trusted(path):
    path = Path(path)
    require(path.is_absolute())
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600)


def invoke(member, arguments, data=None):
    require(member in (1, 2, 3) and (data is None or len(data) <= INPUT_LIMIT))
    process = subprocess.Popen([*SSH, f"devadmin@172.28.240.{10 + member}", shlex.join(arguments)],
                               stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=ENV, start_new_session=True)
    output = bytearray()
    remaining = memoryview(data or b"")
    deadline = time.monotonic() + 120
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
                        chunk = os.read(key.fd, min(65536, OUTPUT_LIMIT + 1 - len(output)))
                        if chunk:
                            output.extend(chunk)
                            require(len(output) <= OUTPUT_LIMIT)
                        else:
                            selector.unregister(key.fileobj)
                    else:
                        written = os.write(key.fd, remaining[:65536])
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


REMOTE = r'''import hashlib,json,os,pathlib,socket,stat,sys
files={
 "provision-dev-sudo-runtime.py":("2981556b78c5ae556278f7c2b2796c4dd262b8753a4c1649134455043bb00af6",8754),
 "iparsd":("dd26e9907c426fe1f2b628a5010441a4127ef26ab763195c353a8c7e09cf05bb",64022456),
 "sudo-hosts.json":("c28d3c1fe54d7016752bad8f3fb92652f3f1dd96b81a9271ac6b9aac95b688c8",2117),
 "heteronetwork-sudo-local.service":("1a7c9f32574555230056389d2b413e9db57f13a7dc4ccca3236a3735a229853d",1180),
 "heteronetwork-sudo-quorum-signer.service":("a7c966d14295d62ff14f645092a161b846f7b6a8b993a9d686cc8fa8849a8328",1490)}
guests={"hetero-dev-1":"381d1ae16f555c59b738d8d01dd14c94","hetero-dev-2":"acc5151b6b245b63864372933dab97da","hetero-dev-3":"165a6e8acc3a56fdbf9bef8c90d6cf4d"}
name=sys.argv[1];action=sys.argv[2];assert name in files and action in ("check","install")
assert os.getuid()==0 and os.geteuid()==0 and socket.gethostname() in guests
assert pathlib.Path("/etc/machine-id").read_text().strip()==guests[socket.gethostname()]
root=pathlib.Path("/opt/heteronetwork-dev-sudo-runtime-v2");path=root/name;digest,size=files[name]
if os.path.lexists(root):
 s=root.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
 assert {p.name for p in root.iterdir()}<=set(files)
if os.path.lexists(path):
 s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==size
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,"rb") as source:raw=source.read(size+1)
 assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest
 print(json.dumps({"name":name,"state":"verified"}));raise SystemExit
assert action=="install"
raw=sys.stdin.buffer.read(size+1);assert len(raw)==size and hashlib.sha256(raw).hexdigest()==digest
if not os.path.lexists(root):root.mkdir(mode=0o700)
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"wb") as target:target.write(raw);target.flush();os.fsync(target.fileno())
parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(parent);os.close(parent)
print(json.dumps({"name":name,"state":"installed"}))
'''


def deliver(member, name, raw):
    try:
        result = json.loads(invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B", "-c", REMOTE,
                                                   name, "check"]))
        require(result == {"name": name, "state": "verified"})
        return False
    except ValueError:
        result = json.loads(invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B", "-c", REMOTE,
                                                   name, "install"], raw))
        require(result == {"name": name, "state": "installed"})
        return True


def deploy(member, payloads):
    installed = [name for name, raw in payloads.items() if deliver(member, name, raw)]
    result = json.loads(invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B",
                                        "/opt/heteronetwork-dev-sudo-runtime-v2/provision-dev-sudo-runtime.py"]))
    require(result["member"] == member and result["services_started"] is False
            and result["services_enabled"] is False and result["activation_performed"] is False
            and result["sudo_configuration_unchanged"] is True)
    return {"member": member, "bundle_files_installed": installed, "result": result}


def main():
    try:
        require(len(sys.argv) == 1 and os.getuid() == 0 and os.geteuid() == 0
                and socket.gethostname() == "ichikawap1")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        for path in (Path(SSH[4]), Path("/var/lib/hetero-dev-provisioner/known_hosts")):
            trusted(path)
        payloads = {}
        for name, (digest, size) in FILES.items():
            path = BUNDLE / name
            trusted(path)
            raw = path.read_bytes()
            require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest)
            payloads[name] = raw
        results = [deploy(member, payloads) for member in (1, 2, 3)]
        print(json.dumps({"results": results, "services_started": False,
                          "services_enabled": False, "activation_performed": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DEV sudo runtime deployment stopped; preserve existing state for inspection", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
