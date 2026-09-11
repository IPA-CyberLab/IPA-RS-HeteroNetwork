#!/usr/bin/env python3
"""Deploy and run non-activation phases on exactly three DEV guests."""

import argparse
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


BUNDLE = Path("/opt/heteronetwork-dev-sudo-active-v3")
FILES = {
    "release.json": 2 * 1024 * 1024,
    "native/ipars": 128 * 1024 * 1024,
    "native/iparsd": 128 * 1024 * 1024,
    "sudo/local-sudo-v2": 32 * 1024 * 1024,
    "sudo/quorum_v2_gate.so": 1024 * 1024,
    "sudo/NOT_ENABLED.txt": 65536,
    "sudo-manifest.json": 1024 * 1024,
    "sudo-policy.json": 2 * 1024 * 1024,
    "units/heteronetwork-sudo-local.service": 65536,
    "units/heteronetwork-sudo-quorum-signer.service": 65536,
    "helpers/heteronetwork-sudo-login": 256 * 1024,
    "helpers/heteronetwork-sudo-approve": 256 * 1024,
    "provision-dev-sudo-active.py": 512 * 1024,
}
SSH = ["/usr/bin/ssh", "-F", "/dev/null",
       "-i", "/var/lib/hetero-dev-provisioner/admin_ed25519",
       "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
       "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
       "-o", "UserKnownHostsFile=/var/lib/hetero-dev-provisioner/known_hosts"]
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
OUTPUT_LIMIT = 256 * 1024


def require(value, reason="DEV sudo cluster deployment rejected"):
    if not value:
        raise ValueError(reason)


def trusted(path, directory=False, mode=None):
    path = Path(path)
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, "unsafe_path_ancestor")
    info = path.lstat()
    require(info.st_uid == 0 and (stat.S_ISDIR(info.st_mode) if directory else
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1), "unsafe_bundle_path")
    require(mode is None or stat.S_IMODE(info.st_mode) == mode, "wrong_bundle_mode")


def invoke(member, arguments, data=None, timeout=180):
    require(member in (1, 2, 3) and (data is None or len(data) <= 128 * 1024 * 1024))
    process = subprocess.Popen(
        [*SSH, f"devadmin@172.28.240.{10 + member}", shlex.join(arguments)],
        stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True)
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    remaining = memoryview(data or b"")
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            if process.stdin is not None:
                if remaining:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE)
                else:
                    process.stdin.close()
            while selector.get_map():
                left = deadline - time.monotonic()
                require(left > 0, "guest_command_timeout")
                for key, _ in selector.select(left):
                    if key.fileobj is process.stdin:
                        count = os.write(key.fd, remaining[:65536])
                        remaining = remaining[count:]
                        if not remaining:
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            target = output if key.fileobj is process.stdout else errors
                            target.extend(chunk)
                            require(len(target) <= OUTPUT_LIMIT, "guest_output_too_large")
            require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                    "guest_command_failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
        if process.stdin is not None:
            process.stdin.close()


REMOTE_INSTALL = r'''import os,pathlib,socket,stat,sys
limits=%s
machines={"hetero-dev-1":"381d1ae16f555c59b738d8d01dd14c94","hetero-dev-2":"acc5151b6b245b63864372933dab97da","hetero-dev-3":"165a6e8acc3a56fdbf9bef8c90d6cf4d"}
name=sys.argv[1];limit=limits[name];host=socket.gethostname();assert os.geteuid()==0 and host in machines
assert pathlib.Path("/etc/machine-id").read_text().strip()==machines[host]
root=pathlib.Path("/opt/heteronetwork-dev-sudo-active-v3");path=root/name
for directory in [root,*reversed(path.parents[:-3])]:
 if not os.path.lexists(directory):directory.mkdir(mode=0o700)
 info=directory.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700
raw=sys.stdin.buffer.read(limit+1);assert 0<len(raw)<=limit
if os.path.lexists(path):
 info=path.lstat();assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
 assert info.st_size<=limit
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,"rb") as source:existing=source.read(limit+1)
 assert existing==raw
else:
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as out:out.write(raw);out.flush();os.fchmod(out.fileno(),0o600);os.fsync(out.fileno())
print(name)
''' % repr(FILES)


def payloads():
    trusted(BUNDLE, directory=True, mode=0o700)
    result = {}
    for name, limit in FILES.items():
        path = BUNDLE / name
        trusted(path, mode=0o600)
        raw = path.read_bytes()
        require(0 < len(raw) <= limit, "bundle_file_size")
        result[name] = raw
    return result


def deliver(member, contents):
    for name, raw in contents.items():
        response = invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B", "-c",
                                   REMOTE_INSTALL, name], raw)
        require(response.decode().strip() == name, "guest_bundle_install_failed")


def phase(member, name):
    raw = invoke(member, ["sudo", "-n", "/usr/bin/python3", "-B",
                          str(BUNDLE / "provision-dev-sudo-active.py"), name])
    result = json.loads(raw)
    require(result.get("guest") == f"hetero-dev-{member}" and result.get("member") == member,
            "wrong_guest_result")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "check", "start", "status"))
    args = parser.parse_args()
    require(os.getuid() == 0 and os.geteuid() == 0 and socket.gethostname() == "ichikawap1",
            "physical_dev_coordinator_required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for path in (Path(SSH[4]), Path("/var/lib/hetero-dev-provisioner/known_hosts")):
        trusted(path, mode=0o600)
    contents = payloads()
    for member in (1, 2, 3):
        deliver(member, contents)
    results = [phase(member, args.phase) for member in (1, 2, 3)]
    print(json.dumps({"phase": args.phase, "results": results,
                      "activation_performed": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError):
        print("DEV sudo cluster deployment stopped without plugin activation", file=sys.stderr)
        sys.exit(1)
