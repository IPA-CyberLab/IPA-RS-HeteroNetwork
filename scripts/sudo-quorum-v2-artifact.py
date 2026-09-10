#!/usr/bin/env python3
"""Build or copy a disabled sudo-v2 artifact. No policy, keys, units or activation."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER_SHA256 = "11234d6e47e6da95adcb3ace71dc93f1d94b759aeca4cd938d829c076adfb35f"
MANIFEST = "manifest.json"
FILES = {"bin/local-sudo-v2": 0o755, "lib/quorum_v2_gate.so": 0o644,
         "NOT_ENABLED.txt": 0o644}
MAX_BINARY = 256 * 1024 * 1024
MAX_TOTAL = 300 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
NOTE = b"""NOT ENABLED. This directory is an inactive build artifact, not a sudo installation.
No sudoers, PAM, sudo.conf, systemd units, keys, policies or live state are included.
Never set setuid/setgid bits on these files. Never use this as a generic executor.
Activation requires separate reviewed provisioning and exact sudo approval ABI checks.
Existing sudoers authorization and password authentication must remain in force.
Missing/invalid local policy, attestation key, quorum token or PoP must deny approval.
See docs/SUDO_QUORUM_V2_ARTIFACT.md in the matching source tree.
"""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def host_platform():
    require(sys.platform == "linux", "Linux is required")
    machines = {"x86_64": ("linux-amd64", 62), "aarch64": ("linux-arm64", 183)}
    require(platform.machine() in machines, "unsupported build/install architecture")
    return machines[platform.machine()]


def regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum, "expected bounded single-link regular input")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(data) == before.st_size and after.st_size == before.st_size
                and after.st_mtime_ns == before.st_mtime_ns
                and after.st_ctime_ns == before.st_ctime_ns, "input changed while reading")
        return data


def validate_elf(data, machine, shared=False):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "expected ELF64 little-endian")
    kind, actual = struct.unpack_from("<HH", data, 16)
    require(actual == machine and kind in ((3,) if shared else (2, 3)), "ELF type/architecture mismatch")
    require(struct.unpack_from("<I", data, 20)[0] == 1
            and struct.unpack_from("<H", data, 52)[0] == 64, "invalid ELF header")


def parent_fd(destination):
    """Pin ancestors without symlinks. Root installations require trusted ancestry."""
    destination = Path(os.path.abspath(destination))
    require(destination.name not in ("", ".", ".."), "a new destination directory is required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in destination.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            meta = os.fstat(fd)
            if os.geteuid() == 0:
                require(meta.st_uid == 0 and not meta.st_mode & 0o022, "root destination ancestry is untrusted")
        meta = os.fstat(fd)
        require(meta.st_uid == os.geteuid() and not meta.st_mode & 0o022,
                "destination parent must be owned by installer and not group/world writable")
        return fd, destination.name
    except BaseException:
        os.close(fd)
        raise


def write_file(directory, name, data, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())


def publish_directory(destination, contents):
    """Exclusive new directory, manifest last. Never selects a current/active version."""
    parent, name = parent_fd(destination)
    directory = None
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        directories = {}
        try:
            for filename, (data, mode) in contents.items():
                parts = filename.split("/")
                require(len(parts) <= 2 and all(p not in ("", ".", "..") for p in parts), "invalid output path")
                target = directory
                if len(parts) == 2:
                    if parts[0] not in directories:
                        os.mkdir(parts[0], 0o755, dir_fd=directory)
                        directories[parts[0]] = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    target = directories[parts[0]]
                write_file(target, parts[-1], data, mode)
            for child in directories.values():
                os.fchmod(child, 0o755)
                os.fsync(child)
            os.fchmod(directory, 0o755)
            os.fsync(directory)
            os.fsync(parent)
        finally:
            for child in directories.values():
                os.close(child)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)
    # On failure leave the new incomplete directory for explicit operator inspection.
    # Never recursively delete or replace an existing installation.


def manifest_for(payloads, provenance, target):
    return {"schema_version": 1, "component": "sudo-quorum-v2", "enabled": False,
            "platform": target, "sudo_plugin_symbol": "quorum_v2_gate",
            "sudo_plugin_header_sha256": HEADER_SHA256, "provenance": provenance,
            "files": {name: {"sha256": digest(data), "size": len(data), "mode": FILES[name]}
                      for name, data in sorted(payloads.items())}}


def encode_archive(payloads, manifest):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        members = {**payloads, MANIFEST: (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
        for name, data in sorted(members.items()):
            entry = tarfile.TarInfo(name)
            entry.mode = FILES.get(name, 0o644)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    require(raw.tell() <= MAX_TOTAL, "uncompressed artifact exceeds bound")
    return gzip.compress(raw.getvalue(), mtime=0)


def decode_archive(data, expected_sha256):
    require(HEX.fullmatch(expected_sha256) is not None and digest(data) == expected_sha256,
            "archive SHA256 does not match independently supplied value")
    target, machine = host_platform()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        raw = compressed.read(MAX_TOTAL + 1)
    require(len(raw) <= MAX_TOTAL, "uncompressed artifact exceeds bound")
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for entry in archive:
            require(entry.name in {*FILES, MANIFEST} and entry.name not in members,
                    "unexpected/duplicate artifact member")
            require(entry.isfile() and not entry.pax_headers and entry.mode == FILES.get(entry.name, 0o644)
                    and entry.uid == 0 and entry.gid == 0, "invalid member type, owner or mode")
            require(0 < entry.size <= (MAX_BINARY if entry.name.startswith(("bin/", "lib/")) else 65536),
                    "artifact member exceeds bound")
            stream = archive.extractfile(entry)
            require(stream is not None, "missing member bytes")
            members[entry.name] = stream.read(entry.size + 1)
            require(len(members[entry.name]) == entry.size, "truncated artifact member")
    require(set(members) == {*FILES, MANIFEST}, "incomplete artifact")
    manifest = json.loads(members.pop(MANIFEST))
    require(isinstance(manifest, dict) and set(manifest) == {
        "schema_version", "component", "enabled", "platform", "sudo_plugin_symbol",
        "sudo_plugin_header_sha256", "provenance", "files"}, "invalid manifest fields")
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1
            and manifest.get("enabled") is False and manifest.get("platform") == target
            and manifest.get("component") == "sudo-quorum-v2"
            and manifest.get("sudo_plugin_symbol") == "quorum_v2_gate"
            and manifest.get("sudo_plugin_header_sha256") == HEADER_SHA256, "incompatible or enabled artifact")
    require(manifest.get("files") == manifest_for(members, {}, target)["files"], "payload manifest mismatch")
    require(members["NOT_ENABLED.txt"] == NOTE, "activation notice mismatch")
    validate_elf(members["bin/local-sudo-v2"], machine)
    validate_elf(members["lib/quorum_v2_gate.so"], machine, shared=True)
    return members, manifest


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, timeout=1800, **kwargs)


def release_identity(source_commit, version, profile):
    require(isinstance(source_commit, str) and COMMIT.fullmatch(source_commit) is not None,
            "release requires full lowercase source commit SHA")
    require(isinstance(version, str) and len(version) <= 128 and "+" not in version
            and SEMVER.fullmatch(version.removeprefix("v")) is not None,
            "release requires SemVer without build metadata (optional v prefix)")
    require(profile == "release", "release contract requires release profile")


def check_release_source(source_commit):
    actual = run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    require(actual == source_commit, "release source commit does not match HEAD")
    status = run(["git", "status", "--porcelain", "--untracked-files=all"],
                 cwd=ROOT, capture_output=True, text=True).stdout
    require(not status, "release requires a clean worktree including untracked files")


def release_contract(archive, source_commit, version):
    _, manifest = decode_archive(archive, digest(archive))
    provenance = manifest.get("provenance")
    require(isinstance(provenance, dict), "missing release provenance")
    release_identity(source_commit, version, provenance.get("profile"))
    require(provenance.get("source_commit") == source_commit
            and provenance.get("source_dirty") is False
            and provenance.get("ack_regression") == "passed", "release provenance mismatch")
    require(manifest["platform"] == "linux-amd64", "release catalog supports linux-amd64 only")
    asset = f"heteronetwork-{version.removeprefix('v')}-sudo-v2-linux-amd64.tar.gz"
    return {
        "asset": asset, "sha256": digest(archive),
        "files": manifest["files"],
        "plugin_header_sha256": HEADER_SHA256, "source_commit": source_commit, "profile": "release"}


def build(args):
    target, machine = host_platform()
    releasing = args.source_commit is not None or args.version is not None
    if releasing:
        release_identity(args.source_commit, args.version, args.profile)
        check_release_source(args.source_commit)
    header = regular(args.sudo_header, 1024 * 1024)
    require(digest(header) == HEADER_SHA256, "sudo header does not match pinned ABI input")
    for tool in ("cargo", "cc", "nm", "git"):
        require(shutil.which(tool) is not None, "missing build dependency: " + tool)
    source_names = ["Cargo.toml", "Cargo.lock", "crates/ipars-quorum/Cargo.toml",
                    "prototypes/sudo-quorum/Cargo.toml",
                    "prototypes/sudo-quorum/Cargo.lock", "scripts/sudo-quorum-v2-artifact.py"]
    if (ROOT / "rust-toolchain.toml").exists():
        source_names.append("rust-toolchain.toml")
    for folder in ("crates/ipars-quorum/src", "prototypes/sudo-quorum/src"):
        source_names.extend(str(path.relative_to(ROOT)) for path in sorted((ROOT / folder).rglob("*.rs")))
    sources = ("privilege_gate.c", "privilege_v2_gate.c", "privilege_v2_ack_test.c")
    source_names.extend("prototypes/sudo-quorum/lifecycle/" + name for name in sources)
    snapshot = {name: digest(regular(ROOT / name, 4 * 1024 * 1024)) for name in source_names}
    commit = run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(run(["git", "status", "--porcelain", "--", *source_names], cwd=ROOT,
                     capture_output=True, text=True).stdout)
    with tempfile.TemporaryDirectory(prefix="sudo-v2-build-") as work:
        work = Path(work)
        with (work / "cargo.jsonl").open("wb") as output:
            run(["cargo", "build", "--locked", "-j2", "--manifest-path", "prototypes/sudo-quorum/Cargo.toml",
                 "--bin", "local-sudo-v2", "--profile", args.profile,
                 "--message-format=json-render-diagnostics"], cwd=ROOT, stdout=output)
        artifacts = set()
        for line in (work / "cargo.jsonl").read_text().splitlines():
            event = json.loads(line)
            if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == "local-sudo-v2" and event.get("executable"):
                artifacts.add(event["executable"])
        require(len(artifacts) == 1, "missing/ambiguous freshly built executable")
        # Cargo may hard-link its own executable. Copy it before single-link validation.
        shutil.copyfile(next(iter(artifacts)), work / "local-sudo-v2")
        (work / "sudo_plugin.h").write_bytes(header)
        for name in sources:
            (work / name).write_bytes(regular(ROOT / "prototypes/sudo-quorum/lifecycle" / name, 1024 * 1024))
        common = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(work)]
        run([*common, "-fPIC", "-shared", "privilege_v2_gate.c", "-o", "quorum_v2_gate.so"], cwd=work)
        run([*common, "privilege_v2_ack_test.c", "-o", "ack-test"], cwd=work)
        run([str(work / "ack-test")], cwd=work)
        symbols = run(["nm", "-D", "--defined-only", str(work / "quorum_v2_gate.so")], capture_output=True, text=True).stdout
        require(any(line.split()[-1:] == ["quorum_v2_gate"] for line in symbols.splitlines()), "missing approval plugin symbol")
        require(snapshot == {name: digest(regular(ROOT / name, 4 * 1024 * 1024)) for name in source_names},
                "source changed during build")
        payloads = {"bin/local-sudo-v2": regular(work / "local-sudo-v2", MAX_BINARY),
                    "lib/quorum_v2_gate.so": regular(work / "quorum_v2_gate.so", MAX_BINARY), "NOT_ENABLED.txt": NOTE}
        validate_elf(payloads["bin/local-sudo-v2"], machine)
        validate_elf(payloads["lib/quorum_v2_gate.so"], machine, shared=True)
        provenance = {"source_commit": commit, "source_dirty": dirty, "source_sha256": snapshot,
                      "profile": args.profile, "ack_regression": "passed",
                      "compiler": run(["cc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]}
        manifest = manifest_for(payloads, provenance, target)
        archive = encode_archive(payloads, manifest)
        decode_archive(archive, digest(archive))
        name = f"sudo-quorum-v2-{target}.tar.gz"
        contract = None
        if releasing:
            check_release_source(args.source_commit)
            contract = release_contract(archive, args.source_commit, args.version)
            name = contract["asset"]
        contents = {name: (archive, 0o644), name + ".sha256": ((digest(archive) + "  " + name + "\n").encode(), 0o644)}
        if contract is not None:
            contents["release-contract.json"] = ((json.dumps(contract, sort_keys=True, indent=2) + "\n").encode(), 0o644)
        contents[MANIFEST] = ((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o644)
        publish_directory(args.out_dir, contents)
        print(f"NOT ENABLED: {Path(args.out_dir).absolute() / name}\nSHA256: {digest(archive)}\nsource_commit: {commit}\nsource_dirty: {str(dirty).lower()}\nrelease_contract: {str(releasing).lower()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build")
    make.add_argument("--sudo-header", type=Path, required=True)
    make.add_argument("--out-dir", type=Path, required=True, help="new directory under an existing trusted parent")
    make.add_argument("--profile", choices=("release", "dev"), default="release")
    make.add_argument("--source-commit", help="expected full release source SHA; requires --version")
    make.add_argument("--version", help="release SemVer; requires --source-commit")
    install = commands.add_parser("install", help="copy only; never enable or start")
    install.add_argument("--archive", type=Path, required=True)
    install.add_argument("--sha256", required=True, help="independently trusted archive hash")
    install.add_argument("--destination", type=Path, required=True, help="new inactive artifact directory")
    args = parser.parse_args()
    host_platform()
    if args.command == "build":
        build(args)
    else:
        payloads, manifest = decode_archive(regular(args.archive, MAX_TOTAL), args.sha256)
        contents = {name: (data, FILES[name]) for name, data in payloads.items()}
        contents[MANIFEST] = ((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o644)
        publish_directory(args.destination, contents)
        print("Copied verified artifact only; NOT ENABLED. No sudo/PAM/systemd configuration was changed.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(f"sudo-v2 artifact rejected: {error}") from None
