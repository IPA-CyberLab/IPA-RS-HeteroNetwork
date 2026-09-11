#!/usr/bin/env python3
"""Build a root-only DEV activation bundle from immutable release assets."""

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.15-dev.8"
SOURCE_COMMIT = "04ec0371dae8efad1b24efac192e016b0f8a14b1"
MAX_FILE = 256 * 1024 * 1024
FILES = {
    "sudo-manifest.json": ROOT / "deploy/dev/native/sudo-manifest.json",
    "sudo-policy.json": ROOT / "deploy/dev/native/sudo-policy.json",
    "units/heteronetwork-sudo-local.service":
        ROOT / "deploy/systemd/heteronetwork-sudo-local.service",
    "units/heteronetwork-sudo-quorum-signer.service":
        ROOT / "deploy/systemd/heteronetwork-sudo-quorum-signer.service",
    "helpers/heteronetwork-sudo-login": ROOT / "scripts/heteronetwork-sudo-device-login.py",
    "helpers/heteronetwork-sudo-approve": ROOT / "scripts/heteronetwork-sudo-approve.py",
    "provision-dev-sudo-active.py": ROOT / "scripts/provision-dev-sudo-active.py",
    "deploy-dev-sudo-active.py": ROOT / "scripts/deploy-dev-sudo-active.py",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def load_module(name):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source(path, maximum=MAX_FILE):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_size <= maximum and not info.st_mode & 0o022, "unsafe_input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "input_too_large")
    return raw


def native_payloads(raw, manifest):
    stage = load_module("native-release-stage.py")
    expected = manifest["native"]["linux-amd64"]
    require(hashlib.sha256(raw).hexdigest() == expected["sha256"], "native_archive_hash")
    payloads = {}
    total = 0
    with gzip.GzipFile(fileobj=__import__("io").BytesIO(raw), mode="rb") as stream:
        while True:
            header = stream.read(512)
            require(len(header) == 512, "truncated_native_archive")
            if header == bytes(512):
                require(stream.read(512) == bytes(512), "native_end_marker")
                trailing = stream.read(65537)
                require(len(trailing) <= 65536 and not any(trailing), "native_trailing_data")
                break
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            require(member.name in expected["files"] and member.name not in payloads
                    and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and not member.linkname and 0 < member.size <= MAX_FILE,
                    "invalid_native_member")
            total += member.size
            require(total <= stage.MAX_TOTAL, "native_total_size")
            data = stream.read(member.size)
            require(len(data) == member.size
                    and hashlib.sha256(data).hexdigest() == expected["files"][member.name],
                    "native_member_hash")
            if member.name in stage.REQUIRED_BINARIES:
                stage.verify_binary_header(data[:64])
            require(stream.read((-member.size) % 512) == bytes((-member.size) % 512),
                    "native_padding")
            payloads[member.name] = data
    require(set(payloads) == set(expected["files"]), "incomplete_native_archive")
    return payloads


def write(root, name, raw):
    path = root / name
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(stat.S_IMODE(path.parent.lstat().st_mode) == 0o700, "unsafe_output_directory")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fchmod(output.fileno(), 0o600)
        os.fsync(output.fileno())


def build(args):
    require(os.geteuid() == 0 and not os.path.lexists(args.output), "root_and_new_output_required")
    release_raw = source(args.release, 2 * 1024 * 1024)
    stage = load_module("native-release-stage.py")
    manifest, canonical = stage.validated_catalog(release_raw)
    require(canonical and manifest["version"] == VERSION
            and manifest["commit"] == SOURCE_COMMIT, "wrong_release_document")
    native = native_payloads(source(args.native_archive, stage.MAX_ARCHIVE), manifest)
    sudo_validator = load_module("sudo-quorum-v2-artifact.py")
    sudo_raw = source(args.sudo_archive, sudo_validator.MAX_TOTAL)
    sudo_payloads = stage.sudo_payloads(sudo_raw, manifest)
    args.output.mkdir(mode=0o700)
    write(args.output, "release.json", release_raw)
    write(args.output, "native/ipars", native["bin/ipars"])
    write(args.output, "native/iparsd", native["bin/iparsd"])
    write(args.output, "sudo/local-sudo-v2", sudo_payloads["bin/local-sudo-v2"])
    write(args.output, "sudo/quorum_v2_gate.so", sudo_payloads["lib/quorum_v2_gate.so"])
    write(args.output, "sudo/NOT_ENABLED.txt", sudo_payloads["NOT_ENABLED.txt"])
    for name, path in FILES.items():
        write(args.output, name, source(path, 2 * 1024 * 1024))
    print(json.dumps({
        "output": str(args.output),
        "release_document_sha256": hashlib.sha256(release_raw).hexdigest(),
        "login_helper_sha256": hashlib.sha256(source(FILES["helpers/heteronetwork-sudo-login"])).hexdigest(),
        "approve_helper_sha256": hashlib.sha256(source(FILES["helpers/heteronetwork-sudo-approve"])).hexdigest(),
        "files": sum(1 for path in args.output.rglob("*") if path.is_file()),
        "activation_performed": False,
    }, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--native-archive", required=True, type=Path)
    parser.add_argument("--sudo-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    build(parser.parse_args())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            EOFError, tarfile.TarError) as error:
        print(f"DEV sudo activation bundle rejected: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
