#!/usr/bin/env python3
"""Bounded local evidence for native activation. Never activate or execute payloads."""

import argparse
import errno
import hashlib
import json
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time

INSTALL = "/opt/heteronetwork"
BINARIES = ("ipars", "iparsd", "ipars-k8s-controller")
HELPERS = (
    "public-services-bootstrap.sh", "public-services-autopilot.sh",
    "postgres-ha-node.sh", "postgres-ha-autopilot.sh",
    "keycloak-ha-node.sh", "keycloak-autopilot.sh",
    "kubeadm-ha-node.sh", "kubeadm-ha-autopilot.sh",
    "reconcile-owner-console-auth.sh",
)
ARTIFACTS = tuple(f"{INSTALL}/bin/{name}" for name in BINARIES) + tuple(
    f"{INSTALL}/libexec/{name}" for name in HELPERS)
CADDY = f"{INSTALL}/bin/caddy"
UNIT_ROOTS = ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system")
UNIT = re.compile(r"[A-Za-z0-9_.:@-]{1,240}\.(?:service|timer|target|socket|path|slice|scope|mount|automount|device|swap)\Z")
DEPENDENCY_UNIT = re.compile(r"(?:[A-Za-z0-9_.:@-]|\\x[0-9a-f]{2})+\.(?:service|timer|target|socket|path|slice|scope|mount|automount|device|swap)\Z")
DEPENDENCY_WORD = r'(?:[A-Za-z0-9_.:@-]+|"(?:[A-Za-z0-9_.:@-]|\\\\x[0-9a-f]{2})+")'
DEPENDENCY_WORDS = re.compile(DEPENDENCY_WORD + r"(?: +" + DEPENDENCY_WORD + r")*\Z")
PATH = re.compile(r"/[A-Za-z0-9_./:@-]{1,1023}\Z")
DEPENDENCIES = ("Requires", "Wants", "BindsTo", "PartOf", "After", "Before",
                "RequiredBy", "WantedBy", "BoundBy", "ConsistsOf", "Triggers", "TriggeredBy")
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState",
              "FragmentPath", "DropInPaths", "MainPID", "ControlPID") + DEPENDENCIES
STATES = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
KNOWN_ROLES = {
    "agent", "agent-private", "gateway", "control-plane", "signal", "stun", "relay",
    "quorum-signer", "sudo-quorum-signer", "db", "db-proxy", "db-backchannel",
    "keycloak", "keycloak-backchannel", "keycloak-prepare", "keycloak-autopilot",
    "postgres-autopilot", "public-services-bootstrap", "public-services-autopilot",
    "relay-autopilot", "kubeadm-autopilot", "kubeadm-stage", "kubeadm-join-bundle",
    "overlay-dns", "kubernetes-pod-routing", "monitoring-io-priority",
}
MAX_UNITS = 256
MAX_ENTRIES = 8192
MAX_PROCESSES = 4096
MAX_UNIT_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_HELPER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SYSTEMCTL_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
COMMAND_SECONDS = 5
TOTAL_SECONDS = 120
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Incomplete(Exception):
    """Only fixed reason codes are exposed, never subprocess/file contents."""


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + TOTAL_SECONDS
        self.remaining = MAX_TOTAL_BYTES

    def check(self, size=0):
        self.remaining -= size
        if self.remaining < 0 or time.monotonic() >= self.deadline:
            raise Incomplete("inventory_bound_exceeded")


def bounded_systemctl(arguments, budget):
    """Only internal, fixed read-only verbs; bounded stdout and discarded stderr."""
    if arguments[0] != "show":
        raise Incomplete("unsupported_systemctl_operation")
    budget.check()
    command = ["/usr/bin/systemctl", "--system", "--no-pager", "--no-ask-password"] + arguments
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_COLORS": "0"})
    except OSError:
        raise Incomplete("systemctl_unavailable") from None
    deadline = min(budget.deadline, time.monotonic() + COMMAND_SECONDS)
    output = bytearray()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Incomplete("systemctl_timeout")
                for key, _ in selector.select(left):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_SYSTEMCTL_BYTES:
                            raise Incomplete("systemctl_output_bound_exceeded")
            try:
                result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise Incomplete("systemctl_timeout") from None
        if result != 0:
            raise Incomplete("systemctl_failed")
        return bytes(output)
    finally:
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise Incomplete("systemctl_cleanup_timeout") from None
        finally:
            process.stdout.close()


def scoped(name):
    return bool(UNIT.fullmatch(name) and name.startswith("heteronetwork-"))


def valid_dependency(name):
    # Keep systemd's escaped bytes literal: dependency names are not query targets
    # or filesystem paths. Reject partial escapes and encoded controls/separators.
    if len(name) > 255 or not DEPENDENCY_UNIT.fullmatch(name):
        return False
    return all(int(value, 16) >= 0x20 and int(value, 16) not in (0x2f, 0x7f)
               for value in re.findall(r"\\x([0-9a-f]{2})", name))


def parse_dependencies(value):
    if len(value) > MAX_UNITS * (2 * 255 + 3):
        raise Incomplete("invalid_systemctl_dependencies")
    value = value.strip(" ")
    if not value:
        return []
    # systemctl quotes escaped names and doubles their backslashes. Validate that
    # representation before shlex so bare backslashes cannot silently disappear.
    if not DEPENDENCY_WORDS.fullmatch(value):
        raise Incomplete("invalid_systemctl_dependencies")
    try:
        names = shlex.split(value, comments=False, posix=True)
    except ValueError:
        raise Incomplete("invalid_systemctl_dependencies") from None
    if len(names) > MAX_UNITS or any(not valid_dependency(name) for name in names):
        raise Incomplete("invalid_systemctl_dependencies")
    return sorted(set(names))


def parse_show(raw, expected=None):
    if len(raw) > MAX_SYSTEMCTL_BYTES:
        raise Incomplete("systemctl_output_bound_exceeded")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise Incomplete("invalid_systemctl_encoding") from None
    if any(ord(c) < 32 and c != "\n" for c in text) or "\x7f" in text:
        raise Incomplete("invalid_systemctl_encoding")
    records = []
    for block in text.strip().split("\n\n"):
        if not block:
            continue
        values = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in PROPERTIES or key in values:
                raise Incomplete("invalid_systemctl_properties")
            values[key] = value
        name = values.get("Id", "")
        if not scoped(name) or (expected is not None and name != expected):
            raise Incomplete("unexpected_systemctl_unit")
        required = set(PROPERTIES) - {"MainPID", "ControlPID"}
        if name.endswith(".service") and values.get("LoadState") == "loaded":
            required.update(("MainPID", "ControlPID"))
        if not required.issubset(values):
            raise Incomplete("missing_systemctl_properties")
        record = {"name": name}
        for key in ("LoadState", "ActiveState", "SubState", "UnitFileState"):
            value = values[key]
            if value and not STATES.fullmatch(value):
                raise Incomplete("invalid_systemctl_state")
            record[key] = value
        for key in ("MainPID", "ControlPID"):
            value = values.get(key, "0")
            if not re.fullmatch(r"[0-9]{1,10}", value):
                raise Incomplete("invalid_systemctl_pid")
            record[key] = int(value)
        for key in DEPENDENCIES:
            record[key] = parse_dependencies(values[key])
        # Paths are validated separately and never copied to output on rejection.
        record["FragmentPath"] = values["FragmentPath"]
        record["DropInPaths"] = values["DropInPaths"].split()
        if len(record["DropInPaths"]) > 64:
            raise Incomplete("dropin_bound_exceeded")
        records.append(record)
        if len(records) > MAX_UNITS:
            raise Incomplete("unit_bound_exceeded")
    if len({item["name"] for item in records}) != len(records):
        raise Incomplete("duplicate_systemctl_unit")
    return records


def error_code(error):
    if isinstance(error, Incomplete):
        return str(error)
    if isinstance(error, FileNotFoundError):
        return "missing"
    if isinstance(error, PermissionError):
        return "inaccessible"
    if isinstance(error, OSError) and error.errno in (errno.ELOOP, errno.ENOTDIR):
        return "symlink_or_not_directory"
    return "read_failed"


def open_directory(path):
    if not PATH.fullmatch(path) or any(part in (".", "..") for part in path.split("/")):
        raise Incomplete("unsafe_path")
    descriptor = os.open("/", DIRECTORY)
    trusted = True
    try:
        for part in path.split("/")[1:]:
            if not part:
                continue
            info = os.fstat(descriptor)
            trusted &= info.st_uid == 0 and info.st_mode & 0o022 == 0
            child = os.open(part, DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        trusted &= info.st_uid == 0 and info.st_mode & 0o022 == 0
        return descriptor, bool(trusted)
    except BaseException:
        os.close(descriptor)
        raise


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def hash_descriptor(descriptor, maximum, budget, references=False):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise Incomplete("not_regular")
    if before.st_size > maximum:
        raise Incomplete("file_bound_exceeded")
    digest = hashlib.sha256()
    total = 0
    reference_bytes = bytearray()
    while True:
        budget.check()
        chunk = os.read(descriptor, min(65536, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        budget.check(len(chunk))
        if total > maximum:
            raise Incomplete("file_bound_exceeded")
        digest.update(chunk)
        if references:
            reference_bytes.extend(chunk)
    after = os.fstat(descriptor)
    if identity(before) != identity(after) or total != before.st_size:
        raise Incomplete("file_changed_during_read")
    found = []
    if references:
        for path in ARTIFACTS + (CADDY,):
            pattern = rb"(?<![A-Za-z0-9_./-])" + re.escape(path.encode("ascii")) + rb"(?![A-Za-z0-9_./-])"
            if re.search(pattern, reference_bytes):
                found.append(path)
    return {"sha256": digest.hexdigest(), "size": total, "uid": before.st_uid,
            "gid": before.st_gid, "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "device": before.st_dev, "inode": before.st_ino, "links": before.st_nlink,
            "root_owned_nonwritable": before.st_uid == 0 and before.st_mode & 0o022 == 0,
            "references": sorted(found)}


def inspect_file(path, maximum, budget, references=False):
    result = {"path": path}
    directory = descriptor = None
    try:
        directory, trusted = open_directory(os.path.dirname(path))
        descriptor = os.open(os.path.basename(path), READ, dir_fd=directory)
        result.update(hash_descriptor(descriptor, maximum, budget, references))
        current = os.stat(os.path.basename(path), dir_fd=directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (result["device"], result["inode"]):
            raise Incomplete("file_path_changed_during_read")
        result["trusted_ancestry"] = trusted
        result["status"] = "observed" if trusted and result["root_owned_nonwritable"] and result["links"] == 1 else "untrusted_metadata"
        if current.st_mode & 0o7000:
            result["status"] = "special_permission_bits"
        if path in ARTIFACTS + (CADDY,) and not current.st_mode & 0o111:
            result["status"] = "not_executable"
    except (OSError, Incomplete) as error:
        result["status"] = error_code(error)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
    return result


def unit_path(path, dropin=False):
    if not PATH.fullmatch(path) or any(part in (".", "..") for part in path.split("/")):
        raise Incomplete("unsupported_unit_path")
    # /lib is a conventional vendor alias, but do not follow arbitrary aliases.
    if path.startswith("/lib/systemd/system/") and os.path.realpath("/lib") == "/usr/lib":
        path = "/usr" + path
    root = next((root for root in UNIT_ROOTS if path.startswith(root + "/")), None)
    if root is None:
        raise Incomplete("unsupported_unit_path")
    relative = path[len(root) + 1:]
    parts = relative.split("/")
    if dropin:
        if len(parts) != 2 or not parts[0].endswith(".d") or not parts[1].endswith(".conf"):
            raise Incomplete("unsupported_unit_path")
    elif len(parts) != 1 or not scoped(parts[0]):
        raise Incomplete("unsupported_unit_path")
    return path


def discover_files(budget):
    names, issues = set(), []
    for root in UNIT_ROOTS:
        directory = None
        try:
            directory, trusted = open_directory(root)
            if not trusted:
                issues.append({"scope": root, "reason": "untrusted_directory"})
            with os.scandir(directory) as entries:
                for index, entry in enumerate(entries):
                    budget.check()
                    if index >= MAX_ENTRIES:
                        raise Incomplete("directory_bound_exceeded")
                    if entry.name.startswith("heteronetwork-") and not entry.name.endswith((".d", ".wants", ".requires")):
                        if not scoped(entry.name):
                            issues.append({"scope": root, "reason": "unsupported_unit_name"})
                        else:
                            names.add(entry.name)
                    if len(names) > MAX_UNITS:
                        raise Incomplete("unit_bound_exceeded")
        except (OSError, Incomplete) as error:
            issues.append({"scope": root, "reason": error_code(error)})
        finally:
            if directory is not None:
                os.close(directory)
    return names, issues


def inspect_process(pid, budget):
    result = {"pid": pid}
    directory = descriptor = None
    try:
        directory = os.open(f"/proc/{pid}", DIRECTORY)
        # Only this kernel-provided magic link is followed, never a caller path.
        descriptor = os.open("exe", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        result.update(hash_descriptor(descriptor, MAX_BINARY_BYTES, budget))
        current = os.stat("exe", dir_fd=directory)
        if (current.st_dev, current.st_ino) != (result["device"], result["inode"]):
            raise Incomplete("process_executable_changed")
        result["status"] = "observed"
    except (OSError, Incomplete) as error:
        result["status"] = error_code(error)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
    return result


def scan_consumers(files, unit_pids, budget):
    known = {(item["device"], item["inode"]): item["path"] for item in files
             if "device" in item and "inode" in item}
    result = {"status": "observed", "unknown_consumers": [], "unobservable_processes": 0,
              "scope": "visible_proc_exe_inodes_and_fixed_native_paths_only"}
    try:
        with os.scandir("/proc") as entries:
            count = 0
            for entry in entries:
                if not entry.name.isascii() or not entry.name.isdigit():
                    continue
                budget.check()
                count += 1
                if count > MAX_PROCESSES:
                    raise Incomplete("process_bound_exceeded")
                pid = int(entry.name)
                directory = None
                try:
                    directory = os.open(entry.path, DIRECTORY)
                    info = os.stat("exe", dir_fd=directory)
                    target = os.readlink("exe", dir_fd=directory)
                    path = known.get((info.st_dev, info.st_ino))
                    if path is None and target.removesuffix(" (deleted)") in ARTIFACTS:
                        path = target.removesuffix(" (deleted)")
                    if path and pid not in unit_pids:
                        process = inspect_process(pid, budget)
                        result["unknown_consumers"].append({"artifact": path, "process": process})
                except (OSError, Incomplete):
                    result["unobservable_processes"] += 1
                finally:
                    if directory is not None:
                        os.close(directory)
        if result["unknown_consumers"] or result["unobservable_processes"]:
            result["status"] = "incomplete"
    except (OSError, Incomplete) as error:
        result["status"] = error_code(error)
    return result


def dependency_closure(records):
    by_name = {record["name"]: record for record in records}
    edges = {name: set() for name in by_name}
    boundary = set()
    outside_dependents = set()
    outside_by_unit = {}
    for record in records:
        for prop in DEPENDENCIES:
            boundary.update(name for name in record[prop] if name not in by_name)
        for dependency in record["Requires"] + record["BindsTo"] + record["PartOf"]:
            if dependency in edges:
                edges[dependency].add(record["name"])
        edges[record["name"]].update(name for name in record["RequiredBy"] + record["BoundBy"] + record["ConsistsOf"] if name in by_name)
        outside_by_unit[record["name"]] = {
            name for name in record["RequiredBy"] + record["BoundBy"] + record["ConsistsOf"]
            if name not in by_name}
        outside_dependents.update(outside_by_unit[record["name"]])
    closure = {}
    outside_by_origin = {}
    for origin in edges:
        found, pending = set(), list(edges[origin])
        while pending:
            name = pending.pop()
            if name not in found and name != origin:
                found.add(name)
                pending.extend(edges[name])
        closure[origin] = sorted(found)
        # Propagate known boundary edges without claiming to inspect beyond them.
        outside_by_origin[origin] = sorted(set().union(
            *(outside_by_unit[name] for name in found | {origin})))
    return {"requires_binds_to_partof_dependents": closure,
            "uninspected_stop_dependents_by_origin": outside_by_origin,
            "uninspected_boundary_units": sorted(boundary),
            "uninspected_stop_dependents": sorted(outside_dependents), "scope": "heteronetwork_units_only"}


def inventory():
    budget = Budget()
    report = {"schema_version": 1, "activation_performed": False, "deployment_ready": False,
              "snapshot_atomic": False, "evidence_complete": False, "issues": [],
              "units": [], "artifacts": [], "preserve": [],
              "limitations": ["not_release_provenance_or_rollout_authorization", "not_live_health_or_state_compatibility",
                              "no_config_environment_or_command_arguments_output",
                              "consumer_scan_cannot_identify_interpreted_helpers_or_other_pid_namespaces"]}
    issues = report["issues"]
    names, discovered_issues = discover_files(budget)
    issues.extend(discovered_issues)
    records = {}
    property_arg = "--property=" + ",".join(PROPERTIES)
    try:
        for record in parse_show(bounded_systemctl(["show", "--all", property_arg, "--", "heteronetwork-*"], budget)):
            records[record["name"]] = record
    except (OSError, Incomplete) as error:
        issues.append({"scope": "systemd", "reason": error_code(error)})
    names.update(records)
    for name in sorted(names - records.keys())[:max(0, MAX_UNITS - len(records))]:
        try:
            result = parse_show(bounded_systemctl(["show", "--all", property_arg, "--", name], budget), name)
            if len(result) != 1:
                raise Incomplete("missing_systemctl_unit")
            records[name] = result[0]
        except (OSError, Incomplete) as error:
            issues.append({"scope": name, "reason": error_code(error)})
    if len(names) > MAX_UNITS:
        issues.append({"scope": "systemd", "reason": "unit_bound_exceeded"})
    if not records:
        issues.append({"scope": "systemd", "reason": "no_heteronetwork_units"})
    report["dependencies"] = dependency_closure(list(records.values()))
    if report["dependencies"]["uninspected_stop_dependents"]:
        issues.append({"scope": "dependencies", "reason": "uninspected_stop_dependents"})
    for path in ARTIFACTS:
        maximum = MAX_BINARY_BYTES if path.endswith(BINARIES) else MAX_HELPER_BYTES
        report["artifacts"].append(inspect_file(path, maximum, budget))
    report["preserve"].append(inspect_file(CADDY, MAX_BINARY_BYTES, budget))
    files = report["artifacts"] + report["preserve"]
    pids = set()
    for name, record in sorted(records.items()):
        unit = {key: value for key, value in record.items() if key not in ("FragmentPath", "DropInPaths")}
        role = name.removeprefix("heteronetwork-").rsplit(".", 1)[0]
        if role not in KNOWN_ROLES:
            issues.append({"scope": name, "reason": "unreviewed_unit_role"})
        unit["files"] = []
        for raw, dropin in [(record["FragmentPath"], False)] + [(path, True) for path in record["DropInPaths"]]:
            try:
                path = unit_path(raw, dropin)
                item = inspect_file(path, MAX_UNIT_BYTES, budget, references=True)
                unit["files"].append(item)
                if item["status"] != "observed":
                    issues.append({"scope": name, "reason": item["status"]})
            except Incomplete as error:
                issues.append({"scope": name, "reason": error_code(error)})
        unit["processes"] = []
        native_daemon = role in {"agent", "agent-private", "control-plane", "signal", "stun", "relay", "quorum-signer", "sudo-quorum-signer"}
        for pid in sorted({record["MainPID"], record["ControlPID"]} - {0}):
            process = inspect_process(pid, budget)
            pids.add(pid)
            process["matching_artifacts"] = [item["path"] for item in files if process.get("sha256") and process.get("sha256") == item.get("sha256")]
            unit["processes"].append(process)
            if process["status"] != "observed":
                issues.append({"scope": name, "reason": "process_" + process["status"]})
            expected = f"{INSTALL}/bin/iparsd" if native_daemon else CADDY if role == "gateway" else None
            if expected and pid == record["MainPID"] and expected not in process["matching_artifacts"]:
                issues.append({"scope": name, "reason": "running_executable_mismatch_or_unverified"})
            if not expected and any(path in ARTIFACTS for path in process["matching_artifacts"]):
                issues.append({"scope": name, "reason": "unexpected_native_consumer"})
        if record["ActiveState"] == "active" and name.endswith(".service"):
            references = {path for item in unit["files"] for path in item.get("references", [])}
            if any("/libexec/" in path for path in references) and unit["processes"]:
                issues.append({"scope": name, "reason": "interpreted_helper_process_binding_unverified"})
            if (native_daemon or role == "gateway") and not record["MainPID"]:
                issues.append({"scope": name, "reason": "active_service_without_main_pid"})
        if not record["UnitFileState"]:
            issues.append({"scope": name, "reason": "unit_file_state_unavailable"})
        if record["LoadState"] != "loaded":
            issues.append({"scope": name, "reason": "unit_not_loaded"})
        report["units"].append(unit)
    for item in files:
        if item["status"] != "observed":
            issues.append({"scope": item["path"], "reason": item["status"]})
    report["consumers"] = scan_consumers(files, pids, budget)
    if report["consumers"]["status"] != "observed":
        issues.append({"scope": "consumers", "reason": report["consumers"]["status"]})
    report["evidence_complete"] = not issues
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if sys.platform != "linux":
        result = {"schema_version": 1, "activation_performed": False, "deployment_ready": False,
                  "evidence_complete": False, "issues": [{"scope": "platform", "reason": "linux_required"}]}
    else:
        try:
            result = inventory()
        except (OSError, Incomplete):
            result = {"schema_version": 1, "activation_performed": False, "deployment_ready": False,
                      "evidence_complete": False, "issues": [{"scope": "inventory", "reason": "collection_failed"}]}
    output = json.dumps(result, sort_keys=True, indent=2)
    if len(output.encode("utf-8")) > MAX_REPORT_BYTES:
        result = {"schema_version": 1, "activation_performed": False, "deployment_ready": False,
                  "evidence_complete": False, "issues": [{"scope": "inventory", "reason": "report_bound_exceeded"}]}
        output = json.dumps(result, sort_keys=True, indent=2)
    print(output)
    return 0 if result["evidence_complete"] else 2


if __name__ == "__main__":
    sys.exit(main())
