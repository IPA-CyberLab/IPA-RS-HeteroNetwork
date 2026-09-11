#!/usr/bin/env python3
"""Read-only preflight, NOT activation clearance. Never starts sudo services.

Expected JSON: {policy: <exact public SudoPolicy>, guests: {hetero-dev-1:
{node_id, voter_identifier, endpoint, machine_id}, ...}, service_sha256: <reviewed hash>}.
All three guests and their exact public policy pins are required. No private inputs
belong in this expectation file. Missing native read-only validation is reported
as a blocker unless --native-check is selected. The native checker reads host.key
but never opens the ledger. This Python wrapper never reads the key contents.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True

GUESTS = {f"hetero-dev-{i}" for i in range(1, 4)}
NATIVE_CONFIG = "/etc/ipars-sudo-v2/config.json"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def read(path, limit, mode=None):
    path = Path(path)
    require(path.is_absolute(), "absolute_path_required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            require(part not in (".", ".."), "unsafe_path")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            metadata = os.fstat(directory)
            require(metadata.st_uid == 0 and not metadata.st_mode & 0o022, "unsafe_parent")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    and metadata.st_uid == 0 and not metadata.st_mode & 0o022
                    and not metadata.st_mode & 0o7000 and metadata.st_size <= limit,
                    "unsafe_file")
            require(mode is None or stat.S_IMODE(metadata.st_mode) == mode, "wrong_file_mode")
            data = stream.read(limit + 1)
            require(len(data) <= limit, "file_too_large")
            return data
    finally:
        os.close(directory)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def document(path):
    return json.loads(read(path, 2 * 1024 * 1024), object_pairs_hook=unique_object)


def validate_expected(expected, cluster, hostname, machine_id):
    require(set(expected) == {"policy", "guests", "service_sha256"}, "unexpected_expectation_fields")
    guests = expected["guests"]
    require(set(guests) == GUESTS and hostname in GUESTS, "not_exact_dev_inventory")
    require(guests[hostname]["machine_id"] == machine_id, "guest_machine_identity_mismatch")
    require(len({g["machine_id"] for g in guests.values()}) == 3 and all(
        re.fullmatch(r"[0-9a-f]{32}", g["machine_id"]) for g in guests.values()), "invalid_machine_ids")
    policy = expected["policy"]
    manifest = policy["manifest"]
    require(policy["schema_version"] == 2 and manifest["cluster_id"] == cluster
            and manifest["schema_version"] == 1 and manifest["epoch"] > 0,
            "wrong_cluster_or_schema")
    require(isinstance(manifest["public_key_package"], list) and manifest["public_key_package"]
            and len(manifest["public_key_package"]) <= 262144 and all(
                type(b) is int and 0 <= b <= 255 for b in manifest["public_key_package"]),
            "missing_public_key_package")
    members = [{"node_id": g["node_id"], "identifier": g["voter_identifier"], "endpoint": g["endpoint"]}
               for g in guests.values()]
    require(len({m["node_id"] for m in members}) == 3 and
            len({m["identifier"] for m in members}) == 3 and
            sorted(manifest["members"], key=lambda m: m["node_id"]) == sorted(members, key=lambda m: m["node_id"]),
            "voter_mapping_mismatch")
    require(set(policy["hosts"]) == {m["node_id"] for m in members}, "host_mapping_mismatch")
    host_keys = set()
    for host in policy["hosts"].values():
        require(host["callers"] and len(host["callers"]) <= 256
                and type(host["attestation_key_epoch"]) is int
                and 0 < host["attestation_key_epoch"] <= 2**64 - 1, "missing_host_pins")
        require(len(host["attestation_public_key"]) == 32 and all(
            type(b) is int and 0 <= b <= 255 for b in host["attestation_public_key"]), "invalid_host_public_pin")
        key = bytes(host["attestation_public_key"])
        require(key not in host_keys, "duplicate_host_public_pin")
        host_keys.add(key)
        for uid, identity in host["callers"].items():
            require(isinstance(uid, str) and re.fullmatch(r"[1-9][0-9]{0,9}", uid)
                    and int(uid) <= 2**32 - 1, "invalid_caller_uid")
            require(isinstance(identity["issuer"], str) and len(identity["issuer"].encode("utf-8")) <= 2048
                    and not any(c.isspace() for c in identity["issuer"])
                    and isinstance(identity["subject"], str)
                    and 0 < len(identity["subject"].encode("utf-8")) <= 256
                    and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in identity["subject"]),
                    "invalid_owner_identity")
            issuer = urlsplit(identity["issuer"])
            require(issuer.scheme == "https" and issuer.hostname and not issuer.username
                    and not issuer.password and not issuer.query and not issuer.fragment
                    and identity["subject"], "invalid_owner_https_pin")
    require(re.fullmatch(r"[0-9a-f]{64}", expected["service_sha256"]), "missing_service_pin")


def native_check(installed, config, verified_binary):
    # The native CLI deliberately has no path overrides; check the policy we inspected.
    require(str(config) == NATIVE_CONFIG, "native_check_requires_fixed_config_path")
    binary = Path(installed) / "bin/local-sudo-v2"
    require(read(binary, len(verified_binary), 0o755) == verified_binary,
            "native_checker_changed")
    result = subprocess.run(
        [str(binary), "--check-config"], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        cwd="/", timeout=15, check=False,
    )
    require(result.returncode == 0, "native_configuration_rejected")


def validate_inactive_unit(properties, unit):
    require(set(properties) == {"LoadState", "ActiveState", "SubState", "FragmentPath",
                                "DropInPaths", "UnitFileState", "NeedDaemonReload"},
            "unexpected_unit_properties")
    require(properties["LoadState"] == "loaded"
            and properties["FragmentPath"] == str(unit), "effective_unit_path_mismatch")
    require(not properties["DropInPaths"] and properties["NeedDaemonReload"] == "no",
            "effective_unit_overridden_or_stale")
    require(properties["ActiveState"] == "inactive" and properties["SubState"] == "dead"
            and properties["UnitFileState"] == "disabled", "service_not_disabled_and_stopped")


def validate_inactive_plugins(data):
    # This inactive-only check refuses even legitimate explicit plugins for review.
    for line in data.decode("utf-8").splitlines():
        directive = line.split("#", 1)[0].strip()
        require(not directive.endswith("\\"), "sudo_config_continuation_requires_review")
        require(not directive or directive.split()[0].lower() != "plugin",
                "explicit_sudo_plugin_requires_review")


def inactive_runtime_check(service_unit):
    unit = Path(service_unit)
    require(unit.is_absolute() and re.fullmatch(r"[A-Za-z0-9_.-]+\.service", unit.name)
            and not unit.name.startswith("-"), "invalid_service_unit_path")
    fields = ("LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths",
              "UnitFileState", "NeedDaemonReload")
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(fields), unit.name],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        cwd="/", timeout=15, check=False,
    )
    require(result.returncode == 0 and len(result.stdout) <= 65536, "unit_inspection_failed")
    pairs = []
    for line in result.stdout.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator, "invalid_unit_property")
        pairs.append((key, value))
    validate_inactive_unit(unique_object(pairs), unit)
    try:
        config = read("/etc/sudo.conf", 65536)
    except FileNotFoundError:
        config = b""  # sudo's compiled defaults apply when the config is absent.
    validate_inactive_plugins(config)


def verify(args):
    require(os.geteuid() == 0, "root_readonly_required")
    expected = document(args.expected)
    hostname = socket.gethostname().split(".")[0]
    machine_id = read("/etc/machine-id", 128).decode().strip()
    validate_expected(expected, args.expected_cluster_id, hostname, machine_id)
    config = json.loads(read(args.config, 2 * 1024 * 1024, 0o600), object_pairs_hook=unique_object)
    require(set(config) == {"host_node_id", "policy"} and config["policy"] == expected["policy"]
            and config["host_node_id"] == expected["guests"][hostname]["node_id"], "local_policy_pin_mismatch")
    # Reuse the established archive validator, not another archive/ELF implementation.
    helper = Path(__file__).with_name("sudo-quorum-v2-artifact.py")
    read(helper, 128 * 1024)
    spec = importlib.util.spec_from_file_location("sudo_artifact", helper)
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    payloads, manifest = artifact.decode_archive(read(args.archive, artifact.MAX_TOTAL), args.archive_sha256)
    for name, data in payloads.items():
        require(read(Path(args.installed) / name, artifact.MAX_BINARY, artifact.FILES[name]) == data,
                "installed_companion_mismatch")
    require(document(Path(args.installed) / artifact.MANIFEST) == manifest, "installed_manifest_mismatch")
    unit = read(args.service_unit, 65536)
    require(hashlib.sha256(unit).hexdigest() == expected["service_sha256"], "service_definition_pin_mismatch")
    checks = ["exact_dev_guest", "public_policy_and_owner_pins", "installed_companion_integrity",
              "reviewed_service_definition_hash"]
    blockers = ["sudoers_and_other_root_access_bypasses_not_audited",
                "authenticated_quorum_issuance_and_enforcement_not_verified"]
    if args.inactive_runtime_check:
        inactive_runtime_check(args.service_unit)
        checks.append("effective_unit_disabled_without_overrides_and_no_explicit_sudo_plugins")
    else:
        blockers.insert(0, "effective_service_dropins_and_plugin_disabled_state_not_verified")
    if args.native_check:
        native_check(args.installed, args.config, payloads["bin/local-sudo-v2"])
        checks.append("native_readonly_policy_and_host_key_check")
    else:
        blockers.insert(0, "native_readonly_policy_and_host_key_check_not_performed")
    return {"static_checks_passed": True, "ready_to_enable": False,
            "checks": checks, "blockers": blockers,
            "private_keys_read": args.native_check, "native_checker_executed": args.native_check,
            "services_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("expected", "expected-cluster-id", "config", "archive", "archive-sha256", "installed", "service-unit"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--native-check", action="store_true",
                        help="Run the verified native read-only checker; never grants activation clearance")
    parser.add_argument("--inactive-runtime-check", action="store_true",
                        help="Inspect systemd and sudo.conf without starting or enabling anything")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args), sort_keys=True))
        return 2  # Static success is intentionally not full activation clearance.
    except Exception as error:
        print(json.dumps({"static_checks_passed": False, "ready_to_enable": False,
                          "error_type": type(error).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
