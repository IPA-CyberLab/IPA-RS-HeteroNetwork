#!/usr/bin/env python3
"""Verify and select native release bytes. Never install or execute them."""

import argparse
import contextlib
import gzip
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import tarfile
import zlib

MAX_BINARY = 256 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_HELPER = 2 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_BINARIES = {"bin/ipars", "bin/iparsd", "bin/ipars-k8s-controller"}
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    require(type(value) is str and HASH.fullmatch(value), "Invalid SHA-256")
    return value


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("Non-finite JSON number")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=invalid_constant)


def validated_catalog(raw, channel=None, revision=None):
    require(len(raw) <= MAX_JSON, "Catalog input too large")
    decode(raw)  # Reject duplicate keys/non-finite values before the shared JS parser.
    bridge = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native-release-stage.catalog.mjs")
    arguments = ["node", bridge, "artifact"] if channel is None else [
        "node", bridge, "selection", channel, str(revision)]
    result = subprocess.run(arguments, input=raw, capture_output=True, timeout=10,
                            check=False, env={"PATH": os.defpath})
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON, "Shared catalog validation failed")
    manifest = decode(result.stdout)
    require(type(manifest["version"]) is str and len(manifest["version"]) <= 128,
            "Release version too long")
    require(re.fullmatch(r"ghcr\.io/ipa-cyberlab/heteronetwork@sha256:[0-9a-f]{64}", manifest["image"]),
            "Wrong native source image repository")
    def no_controls(value):
        if isinstance(value, str):
            require(not any(ord(c) < 32 or ord(c) == 127 for c in value), "Control characters in catalog")
        elif isinstance(value, dict):
            for key, item in value.items():
                no_controls(key)
                no_controls(item)
    no_controls(manifest)
    return manifest, result.stdout


def native(manifest):
    return manifest["native"]["linux-amd64"]


def sudo_validator():
    # Import only trusted checkout code, never anything from an archive or slot.
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sudo-quorum-v2-artifact.py")
    spec = importlib.util.spec_from_file_location("sudo_artifact_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sudo_payloads(raw, manifest):
    validator = sudo_validator()
    binding = manifest["sudo_native"]["linux-amd64"]
    payloads, metadata = validator.decode_archive(raw, binding["sha256"])
    provenance = metadata.get("provenance")
    require(isinstance(provenance, dict)
            and provenance.get("source_commit") == binding["source_commit"] == manifest["commit"]
            and provenance.get("profile") == binding["profile"] == "release"
            and provenance.get("source_dirty") is False
            and provenance.get("ack_regression") == "passed",
            "Sudo source provenance mismatch")
    require(metadata["sudo_plugin_header_sha256"] == binding["plugin_header_sha256"]
            and metadata["files"] == binding["files"], "Sudo payload binding mismatch")
    return payloads


def stage_sudo(slot, raw, payloads):
    os.mkdir("sudo", 0o700, dir_fd=slot)
    directory = os.open("sudo", DIRECTORY, dir_fd=slot)
    try:
        write_bytes(directory, "archive.tar.gz", raw)
        for group in ("bin", "lib"):
            os.mkdir(group, 0o700, dir_fd=directory)
            child = os.open(group, DIRECTORY, dir_fd=directory)
            try:
                for path, data in payloads.items():
                    if path.startswith(group + "/"):
                        write_bytes(child, path.split("/")[1], data)
                os.fchmod(child, 0o500)
                os.fsync(child)
            finally:
                os.close(child)
        write_bytes(directory, "NOT_ENABLED.txt", payloads["NOT_ENABLED.txt"])
        os.fchmod(directory, 0o500)
        os.fsync(directory)
    finally:
        os.close(directory)


def inspect_sudo(slot, manifest):
    directory = os.open("sudo", DIRECTORY, dir_fd=slot)
    try:
        trusted_directory(directory, private=True)
        require(set(os.listdir(directory)) == {"archive.tar.gz", "NOT_ENABLED.txt", "bin", "lib"},
                "Unexpected sudo slot contents")
        raw = read_owned(directory, "archive.tar.gz", sudo_validator().MAX_TOTAL, mode=0o400)
        payloads = sudo_payloads(raw, manifest)
        for group in ("bin", "lib"):
            child = os.open(group, DIRECTORY, dir_fd=directory)
            try:
                trusted_directory(child, private=True)
                expected = {path.split("/")[1]: data for path, data in payloads.items()
                            if path.startswith(group + "/")}
                require(set(os.listdir(child)) == set(expected), "Unexpected sudo payload files")
                for name, data in expected.items():
                    require(read_owned(child, name, len(data), mode=0o400) == data, "Staged sudo payload mismatch")
            finally:
                os.close(child)
        notice = payloads["NOT_ENABLED.txt"]
        require(read_owned(directory, "NOT_ENABLED.txt", len(notice), mode=0o400) == notice,
                "Staged sudo notice mismatch")
    finally:
        os.close(directory)


def trusted_directory(fd, private=False):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode), "Directory required")
    if private:
        require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
                "Staging directories must be private and owned by the current user")
    else:
        require(info.st_uid in (0, os.geteuid()), "Untrusted directory owner")
        require(info.st_mode & 0o022 == 0 or
                (info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                "Writable untrusted directory ancestor")


def open_directory(filename, trusted=False):
    filename = os.path.abspath(filename)
    require(not any(ord(c) < 32 or ord(c) == 127 for c in filename), "Control characters in path")
    fd = os.open("/", DIRECTORY)
    try:
        for part in filename.split("/")[1:]:
            if not part:
                continue
            if trusted:
                trusted_directory(fd)
            next_fd = os.open(part, DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if trusted:
            trusted_directory(fd, private=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def source_file(filename):
    parent, name = os.path.split(os.path.abspath(filename))
    directory = open_directory(parent)
    fd = None
    try:
        fd = os.open(name, READ, dir_fd=directory)
        require(stat.S_ISREG(os.fstat(fd).st_mode), "Input must be a regular non-symlink file")
        with os.fdopen(fd, "rb") as source:
            fd = None
            yield source
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def read_source(filename, maximum):
    with source_file(filename) as source:
        require(os.fstat(source.fileno()).st_size <= maximum, "Input too large")
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "Input too large")
    return raw


def open_owned(directory, name):
    fd = os.open(name, READ, dir_fd=directory)
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_nlink == 1 and info.st_mode & 0o077 == 0):
        os.close(fd)
        raise ValueError("Unsafe staged file")
    return fd


def read_owned(directory, name, maximum, mode=None):
    with os.fdopen(open_owned(directory, name), "rb") as source:
        require(mode is None or stat.S_IMODE(os.fstat(source.fileno()).st_mode) == mode,
                "Staged file mode mismatch")
        require(os.fstat(source.fileno()).st_mode & 0o222 == 0, "Writable staged manifest")
        require(os.fstat(source.fileno()).st_size <= maximum, "Stored JSON too large")
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "Stored JSON too large")
    return raw


def write_bytes(directory, name, data, mode=0o400):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())


def checked_copy(source, directory, name, expected_sha256):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(fd, "wb") as output:
        while chunk := source.read(min(1024 * 1024, MAX_ARCHIVE + 1 - total)):
            total += len(chunk)
            require(total <= MAX_ARCHIVE, "Archive exceeds size limit")
            digest.update(chunk)
            output.write(chunk)
        require(total > 0 and digest.hexdigest() == expected_sha256, "Archive checksum mismatch")
        output.flush()
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())


def bounded_digest(source, maximum):
    digest = hashlib.sha256()
    total = 0
    while chunk := source.read(min(1024 * 1024, maximum + 1 - total)):
        total += len(chunk)
        require(total <= maximum, "Artifact grew beyond its size limit")
        digest.update(chunk)
    return digest.hexdigest()


def verify_binary_header(header):
    require(len(header) >= 64 and header[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<H", header, 16)[0] in (2, 3)
            and struct.unpack_from("<H", header, 18)[0] == 62
            and struct.unpack_from("<I", header, 20)[0] == 1
            and struct.unpack_from("<H", header, 52)[0] == 64,
            "Binary is not a native ELF64 little-endian amd64 executable")


def payload_directory(slot, group):
    require(group in ("bin", "libexec"), "Invalid payload directory")
    fd = os.open(group, DIRECTORY, dir_fd=slot)
    try:
        trusted_directory(fd, private=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def unpack_verified_archive(directory, manifest):
    # TarInfo parses each header; no extract API or archive-provided path is used.
    # PAX/GNU extension records and sparse encodings are rejected before payload reads.
    files = native(manifest)["files"]
    for group in {name.split("/")[0] for name in files}:
        os.mkdir(group, 0o700, dir_fd=directory)
    with os.fdopen(open_owned(directory, "archive.tar.gz"), "rb") as raw:
        require(bounded_digest(raw, MAX_ARCHIVE) == native(manifest)["sha256"],
                "Archive changed before extraction")
        raw.seek(0)
        with gzip.GzipFile(fileobj=raw, mode="rb") as source:
            seen = set()
            total = 0
            while True:
                header = source.read(512)
                require(len(header) == 512, "Truncated tar header")
                if header == bytes(512):
                    require(source.read(512) == bytes(512), "Missing tar end marker")
                    trailing = source.read(65537)
                    require(len(trailing) <= 65536 and not any(trailing), "Unexpected tar trailing data")
                    break
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                require(member.name in files and member.name not in seen, "Unexpected or duplicate archive path")
                require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.linkname,
                        "Only ordinary files are permitted")
                maximum = MAX_BINARY if member.name in REQUIRED_BINARIES else MAX_HELPER
                require(0 < member.size <= maximum, "Archive member size limit")
                total += member.size
                require(total <= MAX_TOTAL, "Total extracted size limit")
                group, name = member.name.split("/")
                parent = payload_directory(directory, group)
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                    digest = hashlib.sha256()
                    remaining = member.size
                    with os.fdopen(fd, "wb") as output:
                        first = True
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            require(chunk, "Truncated archive member")
                            if first and member.name in REQUIRED_BINARIES:
                                verify_binary_header(chunk)
                            first = False
                            output.write(chunk)
                            digest.update(chunk)
                            remaining -= len(chunk)
                        require(digest.hexdigest() == files[member.name], "Payload checksum mismatch")
                        output.flush()
                        os.fchmod(output.fileno(), 0o400)
                        os.fsync(output.fileno())
                    os.fsync(parent)
                finally:
                    os.close(parent)
                padding = (-member.size) % 512
                require(source.read(padding) == bytes(padding), "Invalid tar padding")
                seen.add(member.name)
            require(seen == set(files), "Archive does not match the complete file catalog")
    for group in {name.split("/")[0] for name in files}:
        parent = payload_directory(directory, group)
        try:
            os.fchmod(parent, 0o500)
            os.fsync(parent)
        finally:
            os.close(parent)


@contextlib.contextmanager
def locked_root(root):
    directory = open_directory(root, trusted=True)
    lock = None
    try:
        lock = os.open(".lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=directory)
        os.write(lock, json.dumps({"pid": os.getpid()}).encode())
        os.fsync(lock)
        yield directory
    finally:
        if lock is not None:
            os.close(lock)
            os.unlink(".lock", dir_fd=directory)
            os.fsync(directory)
        os.close(directory)


def slots_directory(root, create=False):
    if create:
        try:
            os.mkdir("slots", 0o700, dir_fd=root)
            os.fsync(root)
        except FileExistsError:
            pass
    fd = os.open("slots", DIRECTORY, dir_fd=root)
    try:
        trusted_directory(fd, private=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def inspect_slot(slots, artifact):
    sha(artifact)
    slot = os.open(artifact, DIRECTORY, dir_fd=slots)
    try:
        trusted_directory(slot, private=True)
        raw = read_owned(slot, "manifest.json", MAX_JSON)
        require(hashlib.sha256(raw).hexdigest() == artifact, "Staged manifest checksum mismatch")
        manifest, canonical = validated_catalog(raw)
        require(raw == canonical, "Noncanonical staged manifest")
        files = native(manifest)["files"]
        groups = {name.split("/")[0] for name in files}
        companion = {"sudo"} if "sudo_native" in manifest else set()
        require(set(os.listdir(slot)) == {"manifest.json", "archive.tar.gz"} | groups | companion,
                "Unexpected slot contents")
        with os.fdopen(open_owned(slot, "archive.tar.gz"), "rb") as source:
            info = os.fstat(source.fileno())
            require(0 < info.st_size <= MAX_ARCHIVE and info.st_mode & 0o222 == 0,
                    "Staged archive size or permissions changed")
            require(bounded_digest(source, MAX_ARCHIVE) == native(manifest)["sha256"],
                    "Staged archive checksum mismatch")
        total = 0
        for group in groups:
            parent = payload_directory(slot, group)
            try:
                expected = {name.split("/")[1] for name in files if name.startswith(group + "/")}
                require(set(os.listdir(parent)) == expected, "Unexpected payload files")
                for name in expected:
                    full_name = group + "/" + name
                    with os.fdopen(open_owned(parent, name), "rb") as source:
                        info = os.fstat(source.fileno())
                        maximum = MAX_BINARY if full_name in REQUIRED_BINARIES else MAX_HELPER
                        require(0 < info.st_size <= maximum and info.st_mode & 0o222 == 0,
                                "Staged payload size or permissions changed")
                        total += info.st_size
                        require(total <= MAX_TOTAL, "Total staged size limit")
                        if full_name in REQUIRED_BINARIES:
                            verify_binary_header(source.read(64))
                            source.seek(0)
                        require(bounded_digest(source, maximum) == files[full_name],
                                "Staged payload checksum mismatch")
            finally:
                os.close(parent)
        if companion:
            inspect_sudo(slot, manifest)
        return manifest
    finally:
        os.close(slot)


def selection_snapshot(channels_path, environment, expected_revision=None):
    require(environment in ("dev", "prod"), "Unknown environment")
    raw = read_source(channels_path, MAX_JSON)
    state = decode(raw)
    require(type(state) is dict and type(state.get("revision")) is int and state["revision"] >= 0,
            "Invalid channel revision")
    revision = state["revision"]
    require(expected_revision is None or expected_revision == revision, "Channel revision changed")
    manifest, canonical = validated_catalog(raw, environment, revision)
    return manifest, canonical, revision


def result_for(root, artifact, manifest, environment=None, revision=None):
    result = {"artifact_id": artifact, "archive_sha256": native(manifest)["sha256"],
              "image": manifest["image"], "slot": os.path.join(os.path.abspath(root), "slots", artifact),
              "prepared": True, "activation_performed": False, "manifest": manifest}
    result["sudo_prepared"] = "sudo_native" in manifest
    if environment is not None:
        result.update({"environment": environment, "selected_revision": revision})
    return result


def remove_temporary(slot):
    # Only operates inside this process's newly-created private temporary directory.
    os.fchmod(slot, 0o700)
    for name in os.listdir(slot):
        info = os.stat(name, dir_fd=slot, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, DIRECTORY, dir_fd=slot)
            try:
                remove_temporary(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=slot)
        else:
            os.unlink(name, dir_fd=slot)


def prepare(root, channels_path, environment, archive_path, sudo_archive_path=None):
    manifest, canonical, revision = selection_snapshot(channels_path, environment)
    require((sudo_archive_path is not None) == ("sudo_native" in manifest),
            "Sudo archive is required exactly when the catalog binds a companion")
    sudo_raw = None
    if sudo_archive_path is not None:
        sudo_raw = read_source(sudo_archive_path, sudo_validator().MAX_TOTAL)
        payloads = sudo_payloads(sudo_raw, manifest)
    artifact = hashlib.sha256(canonical).hexdigest()
    with locked_root(root) as directory:
        slots = slots_directory(directory, create=True)
        temporary = None
        slot = None
        try:
            try:
                os.stat(artifact, dir_fd=slots, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                inspect_slot(slots, artifact)
                return result_for(root, artifact, manifest, environment, revision)
            temporary = ".prepare-" + secrets.token_hex(16)
            os.mkdir(temporary, 0o700, dir_fd=slots)
            slot = os.open(temporary, DIRECTORY, dir_fd=slots)
            write_bytes(slot, "manifest.json", canonical)
            with source_file(archive_path) as source:
                checked_copy(source, slot, "archive.tar.gz", native(manifest)["sha256"])
            unpack_verified_archive(slot, manifest)
            if sudo_raw is not None:
                stage_sudo(slot, sudo_raw, payloads)
                inspect_sudo(slot, manifest)
            os.fchmod(slot, 0o500)
            os.fsync(slot)
            os.rename(temporary, artifact, src_dir_fd=slots, dst_dir_fd=slots)
            temporary = None
            os.fsync(slots)
            return result_for(root, artifact, manifest, environment, revision)
        finally:
            if temporary is not None and slot is not None:
                remove_temporary(slot)
                os.rmdir(temporary, dir_fd=slots)
            if slot is not None:
                os.close(slot)
            os.close(slots)


def inspect(root, artifact):
    with locked_root(root) as directory:
        slots = slots_directory(directory)
        try:
            manifest = inspect_slot(slots, artifact)
            return result_for(root, artifact, manifest)
        finally:
            os.close(slots)


def select(root, channels_path, environment, expected_revision=None):
    manifest, canonical, revision = selection_snapshot(channels_path, environment, expected_revision)
    artifact = hashlib.sha256(canonical).hexdigest()
    result = inspect(root, artifact)
    require(result["manifest"] == manifest, "Prepared catalog differs from selection")
    result.update({"environment": environment, "selected_revision": revision})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command_name in ("prepare", "select"):
        command = commands.add_parser(command_name)
        command.add_argument("--root", required=True)
        command.add_argument("--channels", required=True)
        command.add_argument("--environment", choices=("dev", "prod"), required=True)
        if command_name == "prepare":
            command.add_argument("--archive", required=True)
            command.add_argument("--sudo-archive", help="required for catalogs with sudo_native; inactive bytes only")
        else:
            command.add_argument("--expected-revision", type=int)
    command = commands.add_parser("inspect")
    command.add_argument("--root", required=True)
    command.add_argument("--artifact", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.root, args.channels, args.environment, args.archive, args.sudo_archive)
    elif args.command == "inspect":
        result = inspect(args.root, args.artifact)
    else:
        result = select(args.root, args.channels, args.environment, args.expected_revision)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, EOFError, RecursionError, zlib.error, tarfile.TarError, subprocess.SubprocessError):
        # Do not echo untrusted archive paths, JSON values, or terminal control bytes.
        print("Native staging failed validation or filesystem checks; no activation performed.", file=sys.stderr)
        sys.exit(1)
