#!/usr/bin/env python3
"""Download and verify the pinned dev image inside a newly allocated private temp directory."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import time

MAX_IMAGE = 2 * 1024**3
MAX_METADATA = 2 * 1024**2
URL = "https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-amd64.img"
KEYRING = "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def check_space(root, reserve, needed=0):
    info = os.statvfs(root)
    require(info.f_bavail * info.f_frsize >= reserve + needed, "disk reserve unavailable")


def run(args, env, seconds, limit, root, reserve, output=None):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    deadline = time.monotonic() + seconds
    count, result = 0, bytearray()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "bounded command timed out")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(chunk)
                    require(count <= limit, "bounded output size exceeded")
                    if output is not None:
                        check_space(root, reserve, len(chunk))
                        output.write(chunk)
                    else:
                        result.extend(chunk)
            require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                    "bounded command failed")
        return bytes(result), count
    finally:
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=2)
        finally:
            process.stdout.close()


def download(root, name, url, limit, seconds, env, reserve):
    destination = root / name
    require(not destination.exists(), "download destination already exists")
    temporary = root / (name + ".partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    print(json.dumps({"stage": "download", "file": name}), flush=True)
    with os.fdopen(fd, "wb") as output:
        _, count = run(["/usr/bin/curl", "--disable", "--proto", "=https", "--proto-redir", "=https",
                        "--fail", "--silent", "--show-error", "--location", "--max-redirs", "3",
                        "--connect-timeout", "15", "--max-time", str(seconds),
                        "--speed-limit", "1024", "--speed-time", "30", "--max-filesize", str(limit), url],
                       env, seconds + 5, limit, root, reserve, output)
        require(count > 0, "empty download")
        output.flush()
        os.fsync(output.fileno())
    os.link(temporary, destination)
    temporary.unlink()
    return destination, count


def file_hash(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    deadline = time.monotonic() + 90
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                "invalid input file")
        digest, count = hashlib.sha256(), 0
        while chunk := source.read(1024 * 1024):
            require(time.monotonic() < deadline, "hash timeout")
            count += len(chunk)
            require(count <= limit, "hash size bound exceeded")
            digest.update(chunk)
        after = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and count == before.st_size, "file changed during hash")
        return digest.hexdigest(), count


def main():
    os.umask(0o077)
    root = Path(__file__).absolute().parent
    require(root.parent == Path("/tmp") and root.name.startswith("hetero-dev-base-image."), "new staging temp directory required")
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "private owned staging directory required")
    require(os.geteuid() != 0 and pwd.getpwuid(os.geteuid()).pw_name == "mizuame", "mizuame non-root execution required")
    require({entry.name for entry in root.iterdir()} == {"prepare-dev-base-image.py", "profile.json"},
            "staging directory must contain only the new script and profile")
    profile_path = root / "profile.json"
    require(profile_path.stat().st_size <= 16384 and not profile_path.is_symlink(), "invalid profile input")
    profile = json.loads(profile_path.read_bytes())
    require(profile["host"] == socket.gethostname() == "ichikawap1", "wrong target host")
    require(profile["image_url"] == URL and profile["image_keyring"] == KEYRING, "unexpected image source or trust root")
    require(re.fullmatch(r"[0-9a-f]{64}", profile["image_sha256"]), "invalid image pin")
    reserve = max(128, profile["host_disk_reserve_gib"]) * 1024**3
    check_space(root, reserve, MAX_IMAGE + 8 * MAX_METADATA)
    keyring = Path(KEYRING)
    for part in [*reversed(keyring.parents), keyring]:
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "untrusted keyring ancestry or ownership")
    keyring_hash, _ = file_hash(keyring, MAX_METADATA)
    home = root / "gnupg"
    home.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root), "GNUPGHOME": str(home), "TMPDIR": str(root)}
    base = URL.rsplit("/", 1)[0]
    sums, sums_size = download(root, "SHA256SUMS", base + "/SHA256SUMS", MAX_METADATA, 60, env, reserve)
    signature, signature_size = download(root, "SHA256SUMS.gpg", base + "/SHA256SUMS.gpg", MAX_METADATA, 60, env, reserve)
    status, _ = run(["/usr/bin/gpgv", "--homedir", str(home), "--status-fd", "1", "--keyring", KEYRING,
                     str(signature), str(sums)], env, 30, MAX_METADATA, root, reserve)
    signers = [line.split()[2] for line in status.decode("ascii").splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    require(signers and all(re.fullmatch(r"[0-9A-F]{40,64}", value) for value in signers), "authenticated checksum signature required")
    name = URL.rsplit("/", 1)[1]
    records = [line.split() for line in sums.read_text(encoding="ascii").splitlines()]
    require([row[0] for row in records if len(row) == 2 and row[1].lstrip("*") == name] == [profile["image_sha256"]],
            "signed checksum does not match profile pin")
    print(json.dumps({"stage": "signed_checksum_verified", "signers": signers}), flush=True)
    image, image_size = download(root, name, URL, MAX_IMAGE, 600, env, reserve)
    digest, size = file_hash(image, MAX_IMAGE)
    require(digest == profile["image_sha256"] and size == image_size, "image hash does not match signed profile pin")
    with image.open("rb") as source:
        header = source.read(104)
    require(len(header) == 104 and header[:4] == b"QFI\xfb", "QCOW2 image required")
    version = struct.unpack_from(">I", header, 4)[0]
    require(version in (2, 3), "unsupported QCOW2 version")
    require(struct.unpack_from(">Q", header, 8)[0] == 0 and struct.unpack_from(">I", header, 16)[0] == 0,
            "external backing file rejected before qemu inspection")
    require(struct.unpack_from(">I", header, 32)[0] == 0, "encrypted QCOW2 rejected")
    if version == 3:
        require(struct.unpack_from(">Q", header, 72)[0] & 0b111 == 0, "dirty, corrupt or external-data QCOW2 rejected")
    for path in (sums, signature, image):
        path.chmod(0o400)
    raw, _ = run(["/usr/bin/qemu-img", "info", "--output=json", "--backing-chain", "-f", "qcow2", str(image)],
                 env, 30, MAX_METADATA, root, reserve)
    chain = json.loads(raw)
    require(isinstance(chain, list) and len(chain) == 1 and chain[0].get("format") == "qcow2",
            "unexpected image backing chain")
    require(not chain[0].get("backing-filename") and not chain[0].get("full-backing-filename"), "backing file not permitted")
    require(0 < chain[0]["virtual-size"] <= profile["disk_gib"] * 1024**3, "guest disk smaller than image")
    require(not chain[0].get("encrypted", False), "encrypted image not permitted")
    final_hash, _ = file_hash(image, MAX_IMAGE)
    require(final_hash == digest, "image changed during inspection")
    result = {"host": socket.gethostname(), "user": "mizuame", "directory": str(root), "image": str(image),
              "image_sha256": digest, "image_bytes": size, "checksum_bytes": sums_size,
              "signature_bytes": signature_size, "keyring": KEYRING, "keyring_sha256": keyring_hash,
              "signers": signers, "signature_verified": True, "profile_pin_verified": True,
              "qcow2": chain[0], "backing_chain_length": 1, "disk_reserve_bytes": reserve,
              "activation_performed": False, "guest_created": False}
    with (root / "verification.json").open("x", encoding="ascii") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
