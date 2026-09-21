#!/usr/bin/env python3
"""Verify a published native release and prepare its console Ansible inputs."""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/terraform/master-only"
TAG = re.compile(r"v[0-9][A-Za-z0-9._-]{0,127}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
TARGET_BINARIES = ("ipars", "iparsd")


def load_stage_module():
    source = ROOT / "scripts/native-release-stage.py"
    spec = importlib.util.spec_from_file_location("heteronetwork_native_release_stage", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STAGE = load_stage_module()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    info = path.stat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "Work directory must be private")


def read_json(path, maximum=STAGE.MAX_JSON):
    raw = STAGE.read_source(path, maximum)
    return STAGE.decode(raw), raw


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def copy_and_unpack(manifest, archive_path, verified):
    directory = os.open(verified, STAGE.DIRECTORY)
    try:
        with STAGE.source_file(archive_path) as source:
            STAGE.checked_copy(source, directory, "archive.tar.gz", STAGE.native(manifest)["sha256"])
        STAGE.unpack_verified_archive(directory, manifest)
        os.fsync(directory)
    finally:
        os.close(directory)


def package_console_binaries(manifest, verified, destination):
    expected = STAGE.native(manifest)["files"]
    checksums = {name: expected[f"bin/{name}"] for name in TARGET_BINARIES}
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for name in TARGET_BINARIES:
                    source_path = verified / "bin" / name
                    info = source_path.stat(follow_symlinks=False)
                    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= STAGE.MAX_BINARY,
                            "Verified binary is unavailable")
                    item = tarfile.TarInfo(name)
                    item.size = info.st_size
                    item.mode = 0o755
                    item.uid = item.gid = 0
                    item.uname = item.gname = ""
                    item.mtime = 0
                    with source_path.open("rb") as source:
                        archive.addfile(item, source)
        raw.flush()
        os.fsync(raw.fileno())
    return checksums


def inventory(repo_root, work_dir, ssh_key, checksums):
    nodes, _ = read_json(MODULE / "nodes.json")
    standard_nodes, _ = read_json(MODULE / "standard-nodes.json")
    edge_nodes, _ = read_json(MODULE / "edge-nodes.json")
    bootstrap = edge_nodes["bootstrap"]
    issuer = edge_nodes["enrollment_issuer"]
    for path in (repo_root, work_dir, ssh_key):
        require(SAFE_PATH.fullmatch(str(path)), "Deployment paths must use safe absolute characters")
    common = (f"-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes "
              f"-o UserKnownHostsFile={work_dir / 'known_hosts'}")
    proxy = (common + " -o 'ProxyCommand=ssh " + common +
             f" -i {ssh_key} -W %h:%p mizuame@{bootstrap['ssh_host']}'")
    return {
        "all": {
            "vars": {
                "ansible_user": "mizuame",
                "ansible_ssh_private_key_file": str(ssh_key),
                "ansible_ssh_common_args": common,
                "hnn_repo_root": str(repo_root),
                "hnn_work_dir": str(work_dir),
                "hnn_control_planes": ["10.250.0.2", "10.250.0.4", "10.250.0.5",
                                       "10.250.0.6", "10.250.0.10"],
                "hnn_native_binary_sha256": checksums,
                "hnn_git_revision": "master",
            },
            "children": {
                "master_only": {"hosts": {
                    name: {**node, "ansible_host": node["ssh_host"]}
                    for name, node in nodes.items()
                }},
                "standard": {"hosts": {
                    name: {**node, "ansible_host": node["ssh_host"]}
                    for name, node in standard_nodes.items()
                }},
                "bootstrap": {"hosts": {
                    bootstrap["name"]: {"ansible_host": bootstrap["ssh_host"]}
                }},
                "enrollment_issuer": {"hosts": {
                    issuer["name"]: {
                        "ansible_host": issuer["ssh_host"],
                        "ansible_ssh_common_args": proxy,
                    }
                }},
            },
        }
    }


def known_hosts_lines():
    nodes, _ = read_json(MODULE / "nodes.json")
    standard_nodes, _ = read_json(MODULE / "standard-nodes.json")
    edge_nodes, _ = read_json(MODULE / "edge-nodes.json")
    records = [*nodes.values(), *standard_nodes.values(), *edge_nodes.values()]
    return "".join(f"{node['ssh_host']} {node['ssh_host_key']}\n" for node in records).encode()


def prepare(manifest_path, archive_path, work_dir, ssh_key, expected_version, expected_commit):
    require(TAG.fullmatch(expected_version), "Invalid expected release version")
    require(COMMIT.fullmatch(expected_commit), "Invalid expected release commit")
    require(ssh_key.is_file() and not ssh_key.is_symlink(), "SSH key must be a regular file")
    require(stat.S_IMODE(ssh_key.stat().st_mode) & 0o077 == 0, "SSH key permissions are too broad")
    raw = STAGE.read_source(manifest_path, STAGE.MAX_JSON)
    manifest, _ = STAGE.validated_catalog(raw)
    native = STAGE.native(manifest)
    require(manifest["version"] == expected_version.removeprefix("v")
            and manifest["commit"] == expected_commit,
            "Release identity does not match the requested immutable source")
    require(Path(native["asset"]).name == archive_path.name and "/" not in native["asset"],
            "Native archive filename does not match the manifest")
    private_directory(work_dir)
    verified = work_dir / "verified"
    private_directory(verified)
    copy_and_unpack(manifest, archive_path, verified)
    checksums = package_console_binaries(manifest, verified, work_dir / "native-bin.tar.gz")
    write_private(work_dir / "known_hosts", known_hosts_lines())
    rendered = inventory(ROOT, work_dir, ssh_key.resolve(), checksums)
    write_private(work_dir / "inventory.json", (json.dumps(rendered, separators=(",", ":")) + "\n").encode())
    return {
        "result": "prepared",
        "version": manifest["version"],
        "commit": manifest["commit"],
        "native_archive_sha256": native["sha256"],
        "binary_sha256": checksums,
        "targets": sorted(
            name for group in rendered["all"]["children"].values()
            for name in group["hosts"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    result = prepare(args.manifest, args.archive, args.work_dir, args.ssh_key,
                     args.expected_version, args.expected_commit)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, tarfile.TarError,
            gzip.BadGzipFile):
        print("Console release preparation failed validation; no host was changed.", file=sys.stderr)
        sys.exit(1)
