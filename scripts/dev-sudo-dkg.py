#!/usr/bin/env python3
"""Guest-local DKG for the three exclusive DEV VMs; never enable sudo or a service."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import urllib.request

CLUSTER = "02282a57-784b-4269-90a0-8fda47ee62ec"
ROOT = Path("/var/lib/heteronetwork-dev-sudo-dkg")
BUNDLE = Path("/opt/heteronetwork-dev-sudo-dkg")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
GUESTS = (
    ("hetero-dev-1", "381d1ae16f555c59b738d8d01dd14c94", "node-e52856163b2fb3a1d67fc03943cbdda2"),
    ("hetero-dev-2", "acc5151b6b245b63864372933dab97da", "node-65bbb4982793bf94af58d9a2506c4fca"),
    ("hetero-dev-3", "165a6e8acc3a56fdbf9bef8c90d6cf4d", "node-dfdf53799602bd2aa9006121c33af69a"),
)
CLI_SHA256 = "11a02f292963a864adae9f5fb883b624ecd106f2b5d5f2e0d146afee532fb3c4"


def require(condition):
    if not condition:
        raise ValueError("DEV ceremony prerequisite failed")


def trusted(path, private=False, directory=False):
    path = Path(path)
    require(path.is_absolute())
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022))
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


def read(path, maximum=1024 * 1024, private=False):
    trusted(path, private=private)
    with Path(path).open("rb") as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum)
    return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def expected_roster():
    return {"schema_version": 1, "ceremony_id": "hetero-dev-sudo-20260910-epoch-1",
            "cluster_id": CLUSTER, "epoch": 1,
            "members": [{"identifier": i, "node_id": guest[2], "endpoint": f"http://10.251.0.{i}:8981"}
                        for i, guest in enumerate(GUESTS, 1)]}


def check_identity():
    require(os.getuid() == 0 and os.geteuid() == 0)
    name = socket.gethostname()
    matches = [(i, guest) for i, guest in enumerate(GUESTS, 1) if guest[0] == name]
    require(len(matches) == 1)
    member, guest = matches[0]
    require(read("/etc/machine-id", 128).decode().strip() == guest[1])
    # DMI lives under sysfs symlinks, so read only this fixed kernel attribute.
    dmi = Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower().replace("-", "")
    require(dmi == guest[1])
    bootstrap = decode(read("/opt/heteronetwork-dev-bootstrap/bootstrap.json", private=True))
    require(bootstrap["cluster_id"] == CLUSTER and bootstrap["guest"]["machine_id"] == guest[1])
    token = read("/etc/heteronetwork/kubernetes/agent-api-token", 4096, private=True).decode().strip()
    request = urllib.request.Request("http://127.0.0.1:9780/v1/status",
                                    headers={"Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=5) as response:
        data = response.read(65537)
    require(len(data) <= 65536)
    status = decode(data)
    require(status["node_id"] == guest[2] and status["vpn_ip"] == f"10.251.0.{member}")
    trusted(BUNDLE, private=True, directory=True)
    require(decode(read(BUNDLE / "roster.json")) == expected_roster())
    require(hashlib.sha256(read(BUNDLE / "ipars", maximum=128 * 1024 * 1024)).hexdigest() == CLI_SHA256)
    require(os.access(BUNDLE / "ipars", os.X_OK))
    return member


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("DEV agent redirect rejected")


def write_new(path, raw):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


@contextlib.contextmanager
def locked_root():
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def run_part(part, member):
    roster_bytes = read(BUNDLE / "roster.json")
    if part == "part1":
        # mkdir is exclusive: interrupted ceremonies are inspected, never reset.
        trusted(ROOT.parent, directory=True)
        ROOT.mkdir(mode=0o700)
        write_new(ROOT / "roster.json", roster_bytes)
    trusted(ROOT, private=True, directory=True)
    with locked_root():
        require(read(ROOT / "roster.json") == roster_bytes)
        command = [str(BUNDLE / "ipars"), "quorum", "dkg", part,
                   "--roster", str(ROOT / "roster.json")]
        if part == "part1":
            command += ["--member-id", str(member), "--secret-out", str(ROOT / "round1.secret.json"),
                        "--packet-out", str(ROOT / f"round1-{member}.json")]
        else:
            for i in range(1, 4):
                packet = ROOT / f"round1-{i}.json"
                value = decode(read(packet, private=True))
                require(value["member_id"] == i)
                command += ["--round1-packet", str(packet)]
            if part == "part2":
                read(ROOT / "round1.secret.json", private=True)
                command += ["--secret", str(ROOT / "round1.secret.json"),
                            "--secret-out", str(ROOT / "round2.secret.json"),
                            "--packets-out", str(ROOT / "outgoing-round2")]
            else:
                read(ROOT / "round2.secret.json", private=True)
                for sender in range(1, 4):
                    if sender == member:
                        continue
                    packet = ROOT / f"round2-from-{sender}.json"
                    value = decode(read(packet, private=True))
                    require(value["sender"] == sender and value["recipient"] == member)
                    command += ["--round2-packet", str(packet)]
                command += ["--secret", str(ROOT / "round2.secret.json"),
                            "--key-share-out", str(ROOT / "key-share.json"),
                            "--manifest-out", str(ROOT / "manifest.json")]
        # CLI output can contain private paths; never relay subprocess diagnostics.
        result = subprocess.run(command, env=ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        require(result.returncode == 0)


def inspect(member):
    trusted(ROOT, private=True, directory=True)
    require(decode(read(ROOT / "roster.json")) == expected_roster())
    read(ROOT / "key-share.json", private=True)
    raw = read(ROOT / "manifest.json", private=True)
    manifest = decode(raw)
    roster = expected_roster()
    for field in ("schema_version", "cluster_id", "epoch", "members"):
        require(manifest[field] == roster[field])
    require(manifest["public_key_package"])
    return {"member_id": member, "cluster_id": CLUSTER, "voters": 3, "threshold": 2,
            "manifest_file_sha256": hashlib.sha256(raw).hexdigest(),
            "sudo_activation_performed": False, "signer_start_performed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("preflight", "part1", "part2", "part3", "inspect"))
    args = parser.parse_args()
    try:
        member = check_identity()
        if args.phase.startswith("part"):
            run_part(args.phase, member)
        result = inspect(member) if args.phase == "inspect" else {
            "member_id": member, "phase": args.phase, "sudo_activation_performed": False,
            "signer_start_performed": False}
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DEV DKG stopped; inspect locally and preserve all ceremony files", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
