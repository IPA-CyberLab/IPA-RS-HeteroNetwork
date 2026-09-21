#!/usr/bin/env python3
"""Transactionally demote a retired database member to a proxy-only client."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile


MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_ENTRIES = 32
EXPECTED_FILES = {
    ".proxy-only": 0o600,
    "manifest.env": 0o600,
    "cluster-id": 0o600,
    "ca/ca.crt": 0o644,
    "secrets/application.password": 0o600,
}
EXPECTED_DIRECTORIES = {"ca", "secrets"}
EXPECTED_MEMBERS = {
    "db-b": "100.96.127.54",
    "db-e": "100.111.33.52",
}
SAFE_KEY = re.compile(r"HETERONETWORK_DB_[A-Z0-9_]+\Z")
SAFE_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
SAFE_NODE_ID = re.compile(r"node-[0-9a-f]{16,128}\Z")


class RecoveryError(ValueError):
    """A fail-closed validation error whose message contains no input data."""


def require(condition, message):
    if not condition:
        raise RecoveryError(message)


def regular_file(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "expected a regular file")
    require(info.st_uid == os.geteuid(), "file owner is invalid")
    require(0 < info.st_size <= maximum, "file size is outside the accepted bound")
    return info


def secure_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode), "expected a directory")
    require(info.st_uid == os.geteuid(), "directory owner is invalid")
    require(stat.S_IMODE(info.st_mode) & 0o022 == 0,
            "directory permissions are too broad")


def read_json(path, maximum=1024 * 1024):
    regular_file(path, maximum)
    return json.loads(path.read_text(encoding="utf-8"))


def parse_manifest(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("database manifest is not UTF-8") from error
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        require("=" in line, "database manifest contains a malformed line")
        key, value = line.split("=", 1)
        require(SAFE_KEY.fullmatch(key) and key not in values,
                "database manifest contains an invalid or duplicate key")
        require("\x00" not in value and "\r" not in value,
                "database manifest contains an invalid value")
        values[key] = value
    return values


def parse_mapping(value):
    result = {}
    for field in value.split(","):
        require("=" in field, "database member mapping is malformed")
        name, item = field.split("=", 1)
        require(SAFE_NAME.fullmatch(name) and name not in result and item,
                "database member mapping is invalid")
        result[name] = item
    require(result, "database member mapping is empty")
    return result


def normalized_member_name(name):
    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts,
            "proxy archive contains an unsafe path")
    return path.as_posix()


def extract_proxy_archive(archive, destination):
    info = regular_file(archive, MAX_ARCHIVE_BYTES)
    require(stat.S_IMODE(info.st_mode) & 0o077 == 0,
            "proxy archive permissions are too broad")
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(0 < len(members) <= MAX_ENTRIES,
                "proxy archive entry count is outside the accepted bound")
        seen = set()
        total = 0
        for member in members:
            name = normalized_member_name(member.name)
            require(name not in seen, "proxy archive contains a duplicate path")
            seen.add(name)
            require(member.isfile() or member.isdir(),
                    "proxy archive contains a non-regular entry")
            if member.isfile():
                require(0 <= member.size <= MAX_FILE_BYTES,
                        "proxy archive file size is outside the accepted bound")
                total += member.size
                require(total <= MAX_ARCHIVE_BYTES,
                        "proxy archive expands beyond the accepted bound")
        source.extractall(destination, filter="data")

    paths = {
        path.relative_to(destination).as_posix(): path
        for path in destination.rglob("*")
    }
    require(set(paths) == set(EXPECTED_FILES) | EXPECTED_DIRECTORIES,
            "proxy archive does not match the credential allowlist")
    for relative, mode in EXPECTED_FILES.items():
        path = paths[relative]
        regular_file(path, MAX_FILE_BYTES)
        path.chmod(mode)
    for relative in EXPECTED_DIRECTORIES:
        path = paths[relative]
        require(path.is_dir() and not path.is_symlink(),
                "proxy archive contains an invalid directory")
        path.chmod(0o700)
    destination.chmod(0o700)


def directory_digest(root):
    require(root.is_dir() and not root.is_symlink(), "database bundle is not a directory")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        require(not path.is_symlink(), "database bundle contains a symbolic link")
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(f"{stat.S_IMODE(info.st_mode):04o}".encode() + b"\0")
        if path.is_file():
            regular_file(path, MAX_FILE_BYTES)
            digest.update(path.read_bytes())
        else:
            require(path.is_dir(), "database bundle contains an invalid entry")
        digest.update(b"\0")
    return digest.hexdigest()


def proxy_metadata(directory, identity):
    require((directory / ".proxy-only").read_text(encoding="utf-8").strip() == "1",
            "proxy bundle marker is invalid")
    cluster_id = (directory / "cluster-id").read_text(encoding="utf-8").strip()
    require(cluster_id == identity["cluster_id"], "proxy bundle belongs to another cluster")
    manifest = parse_manifest((directory / "manifest.env").read_bytes())
    members = parse_mapping(manifest.get("HETERONETWORK_DB_MEMBERS", ""))
    identities = parse_mapping(manifest.get("HETERONETWORK_DB_MEMBER_IDENTITIES", ""))
    require(members == EXPECTED_MEMBERS,
            "proxy bundle does not match the declared database topology")
    require(set(members) == set(identities), "database member identities do not match members")
    require(all(SAFE_NODE_ID.fullmatch(value) for value in identities.values()),
            "database member identity is invalid")
    require(identity["node_id"] not in identities.values(),
            "active database members cannot be demoted to proxy-only clients")
    revision = manifest.get("HETERONETWORK_DB_TOPOLOGY_REVISION", "")
    require(revision.isascii() and revision.isdigit() and int(revision) > 0,
            "database topology revision is invalid")
    password = (directory / "secrets/application.password").read_bytes()
    require(16 <= len(password.strip()) <= 4096,
            "proxy application credential length is invalid")
    certificate = (directory / "ca/ca.crt").read_text(encoding="ascii")
    require("-----BEGIN CERTIFICATE-----" in certificate
            and "-----END CERTIFICATE-----" in certificate,
            "proxy CA certificate is invalid")
    return {"revision": int(revision), "members": sorted(members)}


def current_bundle_mode(bundle, identity):
    if not bundle.exists():
        return "missing"
    require(bundle.is_dir() and not bundle.is_symlink(),
            "existing database bundle is invalid")
    cluster = bundle / "cluster-id"
    manifest_path = bundle / "manifest.env"
    require(cluster.is_file() and manifest_path.is_file(),
            "existing database bundle is incomplete")
    require(cluster.read_text(encoding="utf-8").strip() == identity["cluster_id"],
            "existing database bundle belongs to another cluster")
    if (bundle / ".proxy-only").exists():
        return "proxy-only"
    manifest = parse_manifest(manifest_path.read_bytes())
    identities = parse_mapping(manifest.get("HETERONETWORK_DB_MEMBER_IDENTITIES", ""))
    require(identity["node_id"] in identities.values(),
            "existing full bundle is not owned by this retired member")
    return "retired-member"


def fsync_tree(root):
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            with path.open("rb") as source:
                os.fsync(source.fileno())
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def recover(bundle, archive, agent_state, backup_dir, retired_archive=None, apply=False):
    state = read_json(agent_state)
    registered = state.get("registered_node")
    require(isinstance(registered, dict), "Agent identity is unavailable")
    identity = {key: registered.get(key) for key in ("cluster_id", "node_id")}
    require(all(isinstance(value, str) and value for value in identity.values()),
            "Agent identity is incomplete")
    require(SAFE_NODE_ID.fullmatch(identity["node_id"]), "Agent node identity is invalid")

    bundle_parent = bundle.parent
    secure_directory(bundle_parent)
    with tempfile.TemporaryDirectory(prefix=".proxy-recovery-", dir=bundle_parent) as temporary:
        candidate = Path(temporary) / "bundle"
        candidate.mkdir(mode=0o700)
        extract_proxy_archive(archive, candidate)
        metadata = proxy_metadata(candidate, identity)
        candidate_digest = directory_digest(candidate)
        mode = current_bundle_mode(bundle, identity)
        current_digest = directory_digest(bundle) if mode == "proxy-only" else None
        if mode == "proxy-only" and current_digest == candidate_digest:
            return {"result": "unchanged", "mode": mode, **metadata}
        result = {"result": "migration-required", "mode": mode, **metadata}
        if not apply:
            return result

        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup_dir.chmod(0o700)
        secure_directory(backup_dir)
        retired_bundle_backup = backup_dir / "retired-member-bundle"
        retired_archive_backup = backup_dir / "retired-member-bundle.tar.gz"
        require(mode != "retired-member" or not retired_bundle_backup.exists(),
                "retired member bundle backup already exists")
        if retired_archive is not None and retired_archive.exists():
            regular_file(retired_archive, MAX_ARCHIVE_BYTES)
            require(not retired_archive_backup.exists(),
                    "retired member archive backup already exists")

        displaced = bundle_parent / f".bundle-displaced-{os.getpid()}"
        archive_moved = False
        candidate_installed = False
        try:
            if retired_archive is not None and retired_archive.exists():
                os.rename(retired_archive, retired_archive_backup)
                retired_archive_backup.chmod(0o600)
                archive_moved = True
            if bundle.exists():
                os.rename(bundle, displaced)
            fsync_tree(candidate)
            os.rename(candidate, bundle)
            candidate_installed = True
            if mode == "retired-member":
                os.rename(displaced, retired_bundle_backup)
            elif displaced.exists():
                shutil.rmtree(displaced)
            parent_fd = os.open(bundle_parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except Exception:
            if candidate_installed and bundle.exists():
                shutil.rmtree(bundle)
            if displaced.exists():
                os.rename(displaced, bundle)
            elif mode == "retired-member" and retired_bundle_backup.exists():
                os.rename(retired_bundle_backup, bundle)
            if archive_moved and not retired_archive.exists():
                os.rename(retired_archive_backup, retired_archive)
            raise
        return {"result": "changed", "mode": "proxy-only", **metadata}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--agent-state", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--retired-archive", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(recover(
        args.bundle,
        args.archive,
        args.agent_state,
        args.backup_dir,
        args.retired_archive,
        args.apply,
    ), separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except RecoveryError as error:
        print(json.dumps({
            "result": "rejected",
            "reason": str(error),
        }, separators=(",", ":")), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, tarfile.TarError):
        print("Database proxy-client recovery failed validation; no secrets were printed.", file=sys.stderr)
        sys.exit(1)
