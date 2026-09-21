#!/usr/bin/env python3
"""Retire stale database members from the protected HA authority safely."""

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


EXPECTED_MEMBERS = {
    "db-b": "100.96.127.54",
    "db-e": "100.111.33.52",
}
EXPECTED_DCS = {
    **EXPECTED_MEMBERS,
    "db-g": "100.94.130.38",
}
EXPECTED_RETIRED_MEMBERS = 4
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
SECRET_NAMES = (
    "superuser",
    "replication",
    "rewind",
    "application",
    "rest-api",
    "keycloak",
    "keycloak-bootstrap-admin",
)
PROXY_BUNDLE_FILES = {
    ".proxy-only": 0o600,
    "manifest.env": 0o600,
    "cluster-id": 0o600,
    "ca/ca.crt": 0o644,
    "secrets/application.password": 0o600,
}


class RecoveryError(Exception):
    """A fail-closed validation error with no protected value attached."""


def require(condition, message):
    if not condition:
        raise RecoveryError(message)


def regular(path, private=False):
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise RecoveryError("required protected file is missing") from error
    require(stat.S_ISREG(info.st_mode), "protected path is not a regular file")
    require(info.st_uid == os.geteuid(), "protected file owner is invalid")
    require(info.st_size <= MAX_FILE_BYTES, "protected file is unexpectedly large")
    if private:
        require(stat.S_IMODE(info.st_mode) & 0o077 == 0, "protected file permissions are too broad")
    return info


def secure_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode), "protected directory is invalid")
    require(info.st_uid == os.geteuid(), "protected directory owner is invalid")
    require(stat.S_IMODE(info.st_mode) & 0o022 == 0, "protected directory is writable by another user")


def read_limited(path, private=False):
    info = regular(path, private=private)
    with path.open("rb") as source:
        value = source.read(MAX_FILE_BYTES + 1)
    require(len(value) == info.st_size and len(value) <= MAX_FILE_BYTES,
            "protected file changed while it was read")
    return value


def parse_manifest(raw):
    require(len(raw) <= 1024 * 1024, "protected manifest is unexpectedly large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RecoveryError("protected manifest is not UTF-8") from error
    values = {}
    order = []
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        require(separator and KEY.fullmatch(key) and key not in values,
                "protected manifest shape is invalid")
        require("\x00" not in value and "\r" not in value and "\n" not in value,
                "protected manifest value is invalid")
        values[key] = value
        order.append(key)
    required = {
        "HETERONETWORK_DB_CLUSTER_NAME",
        "HETERONETWORK_DB_MEMBERS",
        "HETERONETWORK_DB_MEMBER_IDENTITIES",
        "HETERONETWORK_DB_DCS_MEMBERS",
        "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS",
        "HETERONETWORK_DB_CLIENT_CIDRS",
        "HETERONETWORK_DB_EXTRA_HBA_ENTRIES",
        "HETERONETWORK_DB_SERVICE_NAME",
        "HETERONETWORK_DB_POSTGRES_PORT",
        "HETERONETWORK_DB_REST_PORT",
        "HETERONETWORK_DB_TOPOLOGY_REVISION",
        "HETERONETWORK_DB_NETWORK_PLANE",
    }
    require(required <= set(values), "protected manifest is incomplete")
    return values, order


def parse_mapping(value, identity=False):
    result = {}
    for row in value.split(",") if value else []:
        name, separator, mapped = row.partition("=")
        require(separator and NAME.fullmatch(name) and name not in result,
                "protected topology mapping is invalid")
        if identity:
            require(IDENTITY.fullmatch(mapped), "protected member identity is invalid")
        else:
            require(re.fullmatch(r"[0-9a-fA-F:.]+", mapped),
                    "protected member address is invalid")
        result[name] = mapped
    require(result, "protected topology mapping is empty")
    return result


def normalized_member_name(name):
    while name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return None
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and "." not in path.parts,
            "protected archive contains an unsafe path")
    return path.as_posix()


def tree_digest(root):
    secure_directory(root)
    files = {}
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        info = path.lstat()
        require(info.st_uid == os.geteuid(), "protected bundle owner is invalid")
        require(not stat.S_ISLNK(info.st_mode), "protected bundle contains a symbolic link")
        if stat.S_ISDIR(info.st_mode):
            require(stat.S_IMODE(info.st_mode) & 0o022 == 0,
                    "protected bundle directory permissions are too broad")
            continue
        require(stat.S_ISREG(info.st_mode), "protected bundle contains an unsupported object")
        require(info.st_size <= MAX_FILE_BYTES, "protected bundle file is unexpectedly large")
        total += info.st_size
        require(total <= MAX_BUNDLE_BYTES, "protected bundle is unexpectedly large")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        files[path.relative_to(root).as_posix()] = (info.st_size, digest.hexdigest())
    require(files, "protected bundle is empty")
    return files


def archive_digest(path):
    regular(path, private=True)
    files = {}
    total = 0
    manifest = None
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = normalized_member_name(member.name)
            if name is None:
                require(member.isdir(), "protected archive root is invalid")
                continue
            require(name not in files, "protected archive contains duplicate files")
            if member.isdir():
                continue
            require(member.isfile(), "protected archive contains an unsupported object")
            require(0 <= member.size <= MAX_FILE_BYTES,
                    "protected archive member is unexpectedly large")
            total += member.size
            require(total <= MAX_BUNDLE_BYTES, "protected archive is unexpectedly large")
            source = archive.extractfile(member)
            require(source is not None, "protected archive member cannot be read")
            digest = hashlib.sha256()
            captured = io.BytesIO() if name == "manifest.env" else None
            size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
                if captured is not None:
                    captured.write(chunk)
            require(size == member.size, "protected archive member changed while it was read")
            files[name] = (size, digest.hexdigest())
            if captured is not None:
                manifest = captured.getvalue()
    require(manifest is not None, "protected archive manifest is missing")
    return files, manifest


def openssl(*arguments, capture=False):
    result = subprocess.run(
        ["openssl", *map(str, arguments)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    require(result.returncode == 0, "protected certificate validation failed")
    return result.stdout if capture else b""


def validate_credentials(bundle):
    ca_cert = bundle / "ca" / "ca.crt"
    ca_key = bundle / "ca" / "ca.key"
    read_limited(ca_cert)
    read_limited(ca_key, private=True)
    require(
        openssl("x509", "-in", ca_cert, "-pubkey", "-noout", capture=True)
        == openssl("pkey", "-in", ca_key, "-pubout", capture=True),
        "protected CA key does not match its certificate",
    )
    openssl("verify", "-CAfile", ca_cert, ca_cert)
    for name, address in EXPECTED_DCS.items():
        node = bundle / "nodes" / name
        secure_directory(node)
        node_ca = node / "ca.crt"
        certificate = node / "node.crt"
        key = node / "node.key"
        require(read_limited(node_ca) == read_limited(ca_cert),
                "protected node CA does not match the bundle CA")
        read_limited(certificate)
        read_limited(key, private=True)
        openssl("verify", "-CAfile", ca_cert, certificate)
        openssl("x509", "-in", certificate, "-noout", "-checkend", "86400")
        openssl("x509", "-in", certificate, "-noout", "-checkip", address)
        require(
            openssl("x509", "-in", certificate, "-pubkey", "-noout", capture=True)
            == openssl("pkey", "-in", key, "-pubout", capture=True),
            "protected node key does not match its certificate",
        )
    for name in SECRET_NAMES:
        value = read_limited(bundle / "secrets" / f"{name}.password", private=True)
        require(1 <= len(value) <= 4096, "protected database secret has an invalid size")
    cluster_id = read_limited(bundle / "cluster-id", private=True)
    require(1 <= len(cluster_id) <= 4096, "protected database cluster identity is invalid")


def inspect_authority(bundle, archive):
    tree = tree_digest(bundle)
    archived, archived_manifest = archive_digest(archive)
    expanded_manifest = read_limited(bundle / "manifest.env", private=True)
    require(tree == archived, "protected archive and expanded bundle differ")
    require(expanded_manifest == archived_manifest,
            "protected archive and expanded manifests differ")
    values, order = parse_manifest(expanded_manifest)
    members = parse_mapping(values["HETERONETWORK_DB_MEMBERS"])
    identities = parse_mapping(values["HETERONETWORK_DB_MEMBER_IDENTITIES"], identity=True)
    dcs = parse_mapping(values["HETERONETWORK_DB_DCS_MEMBERS"])
    bootstrap = parse_mapping(values["HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS"])
    require(dcs == EXPECTED_DCS and bootstrap == EXPECTED_DCS,
            "protected DCS authority does not match the recovered quorum")
    require(all(members.get(name) == address for name, address in EXPECTED_MEMBERS.items()),
            "protected authority is missing a recovered database member")
    require(set(identities) == set(members),
            "protected member identities do not match database members")
    require(set(EXPECTED_MEMBERS) <= set(identities),
            "protected authority is missing a recovered member identity")
    require(len(set(identities.values())) == len(identities),
            "protected member identities are not unique")
    retired_members = set(members) - set(EXPECTED_MEMBERS)
    retired_identities = set(identities) - set(EXPECTED_MEMBERS)
    require(retired_members == retired_identities,
            "retired member and identity sets do not match")
    require(len(retired_members) in (0, EXPECTED_RETIRED_MEMBERS),
            "protected authority has an unexpected retired member count")
    require(values["HETERONETWORK_DB_NETWORK_PLANE"] == "underlay-v1",
            "protected authority uses an unexpected network plane")
    revision = values["HETERONETWORK_DB_TOPOLOGY_REVISION"]
    require(re.fullmatch(r"[1-9][0-9]{0,17}", revision),
            "protected topology revision is invalid")
    validate_credentials(bundle)
    return {
        "values": values,
        "order": order,
        "members": members,
        "identities": identities,
        "retired": retired_members,
        "revision": int(revision),
        "manifest": expanded_manifest,
    }


def render_manifest(authority):
    values = dict(authority["values"])
    values["HETERONETWORK_DB_MEMBERS"] = ",".join(
        f"{name}={address}" for name, address in EXPECTED_MEMBERS.items()
    )
    values["HETERONETWORK_DB_MEMBER_IDENTITIES"] = ",".join(
        f"{name}={authority['identities'][name]}" for name in EXPECTED_MEMBERS
    )
    values["HETERONETWORK_DB_DCS_MEMBERS"] = ",".join(
        f"{name}={address}" for name, address in EXPECTED_DCS.items()
    )
    values["HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS"] = values[
        "HETERONETWORK_DB_DCS_MEMBERS"
    ]
    values["HETERONETWORK_DB_TOPOLOGY_REVISION"] = str(authority["revision"] + 1)
    return ("".join(f"{key}={values[key]}\n" for key in authority["order"])).encode()


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path, value, mode):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.recovery-", dir=path.parent)
    temporary = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def pack_bundle(bundle, destination):
    with destination.open("wb") as raw:
        os.fchmod(raw.fileno(), 0o600)
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                paths = [bundle, *sorted(bundle.rglob("*"), key=lambda item: item.relative_to(bundle).as_posix())]
                for path in paths:
                    relative = path.relative_to(bundle).as_posix()
                    arcname = "." if relative == "." else f"./{relative}"
                    info = archive.gettarinfo(str(path), arcname=arcname)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    if info.isfile():
                        with path.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)
        raw.flush()
        os.fsync(raw.fileno())


def ensure_backup(backup_root, authority, archive):
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_root, 0o700)
    secure_directory(backup_root)
    archive_hash = hashlib.sha256(read_limited(archive, private=True)).hexdigest()
    destination = backup_root / f"revision-{authority['revision']}-{archive_hash[:12]}"
    require(not destination.exists(), "protected recovery backup already exists unexpectedly")
    destination.mkdir(mode=0o700)
    atomic_write(destination / "manifest.env", authority["manifest"], 0o600)
    with archive.open("rb") as source:
        descriptor = os.open(
            destination / "bundle.tar.gz",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
    metadata = json.dumps({
        "archive_sha256": archive_hash,
        "revision": authority["revision"],
        "retired_members": EXPECTED_RETIRED_MEMBERS,
    }, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    atomic_write(destination / "metadata.json", metadata, 0o600)
    fsync_directory(destination)
    fsync_directory(backup_root)
    return destination


def replace_archive(path, source):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.recovery-", dir=path.parent)
    temporary = Path(temporary)
    try:
        os.fchmod(descriptor, 0o600)
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output:
            shutil.copyfileobj(input_file, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def publish_proxy_archive(bundle, destination):
    secure_directory(destination.parent)
    stage_root = Path(tempfile.mkdtemp(prefix=".database-proxy-", dir=destination.parent))
    stage_bundle = stage_root / "bundle"
    staged_archive = stage_root / "proxy-bundle.tar.gz"
    try:
        stage_bundle.mkdir(mode=0o700)
        (stage_bundle / "ca").mkdir(mode=0o700)
        (stage_bundle / "secrets").mkdir(mode=0o700)
        values = {
            ".proxy-only": b"1\n",
            "manifest.env": read_limited(bundle / "manifest.env", private=True),
            "cluster-id": read_limited(bundle / "cluster-id", private=True),
            "ca/ca.crt": read_limited(bundle / "ca/ca.crt"),
            "secrets/application.password": read_limited(
                bundle / "secrets/application.password", private=True),
        }
        for relative, mode in PROXY_BUNDLE_FILES.items():
            atomic_write(stage_bundle / relative, values[relative], mode)
        pack_bundle(stage_bundle, staged_archive)
        staged_value = read_limited(staged_archive, private=True)
        if destination.exists():
            current_value = read_limited(destination, private=True)
            if current_value == staged_value:
                return False
        replace_archive(destination, staged_archive)
        require(read_limited(destination, private=True) == staged_value,
                "published proxy bundle did not converge")
        return True
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def apply_recovery(bundle, archive, backup_root, authority):
    require(len(authority["retired"]) == EXPECTED_RETIRED_MEMBERS,
            "protected authority does not require the reviewed recovery")
    new_manifest = render_manifest(authority)
    stage_root = Path(tempfile.mkdtemp(prefix=".database-authority-", dir=bundle.parent))
    stage_bundle = stage_root / "bundle"
    staged_archive = stage_root / "bundle.tar.gz"
    backup = None
    try:
        shutil.copytree(bundle, stage_bundle, symlinks=False)
        atomic_write(stage_bundle / "manifest.env", new_manifest, 0o600)
        pack_bundle(stage_bundle, staged_archive)
        staged = inspect_authority(stage_bundle, staged_archive)
        require(not staged["retired"] and staged["revision"] == authority["revision"] + 1,
                "staged protected authority did not converge")
        backup = ensure_backup(backup_root, authority, archive)
        try:
            atomic_write(bundle / "manifest.env", new_manifest, 0o600)
            replace_archive(archive, staged_archive)
            applied = inspect_authority(bundle, archive)
            require(not applied["retired"] and applied["revision"] == authority["revision"] + 1,
                    "applied protected authority did not converge")
        except Exception:
            atomic_write(bundle / "manifest.env", authority["manifest"], 0o600)
            replace_archive(archive, backup / "bundle.tar.gz")
            raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)
    return authority["revision"] + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--proxy-archive", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    require(args.bundle.is_absolute() and args.archive.is_absolute() and args.backup_dir.is_absolute(),
            "protected recovery paths must be absolute")
    require(args.proxy_archive is None or args.proxy_archive.is_absolute(),
            "protected proxy archive path must be absolute")
    require(args.proxy_archive is None or args.apply,
            "publishing the protected proxy archive requires apply mode")
    def execute():
        authority = inspect_authority(args.bundle, args.archive)
        if authority["retired"] and not args.apply:
            result = {
                "result": "migration-required",
                "revision": authority["revision"],
                "retired_members": len(authority["retired"]),
            }
        elif authority["retired"]:
            revision = apply_recovery(args.bundle, args.archive, args.backup_dir, authority)
            result = {
                "result": "changed",
                "revision": revision,
                "retired_members": EXPECTED_RETIRED_MEMBERS,
            }
        else:
            result = {
                "result": "unchanged",
                "revision": authority["revision"],
                "retired_members": 0,
            }
        if args.proxy_archive is not None:
            current = inspect_authority(args.bundle, args.archive)
            require(not current["retired"],
                    "proxy bundle cannot be published before authority recovery")
            result["proxy_bundle"] = (
                "changed" if publish_proxy_archive(args.bundle, args.proxy_archive)
                else "unchanged"
            )
        return result

    if not args.apply:
        result = execute()
    else:
        lock_path = args.archive.parent / ".database-authority-recovery.lock"
        lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(lock_descriptor, 0o600)
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            result = execute()
        finally:
            os.close(lock_descriptor)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RecoveryError, subprocess.SubprocessError, tarfile.TarError, ValueError):
        print("Database authority recovery failed; no protected value was printed.", file=sys.stderr)
        sys.exit(1)
