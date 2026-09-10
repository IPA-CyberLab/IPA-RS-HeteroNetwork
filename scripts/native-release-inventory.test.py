#!/usr/bin/env python3
"""Read-only collector tests with mocked systemd/proc and inert local files."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("native_inventory", Path(__file__).with_name("native-release-inventory.py"))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)
SECRET = "DO_NOT_OUTPUT_OWNER_TOKEN_OR_COMMAND_ARGUMENTS"


def properties(name="heteronetwork-agent.service", **changes):
    values = {key: "" for key in inventory.PROPERTIES}
    values.update(Id=name, LoadState="loaded", ActiveState="active", SubState="running",
                  UnitFileState="enabled", MainPID="0", ControlPID="0",
                  FragmentPath=f"/etc/systemd/system/{name}")
    values.update(changes)
    return values


def encode(*records):
    return ("\n\n".join("\n".join(f"{key}={value}" for key, value in record.items())
                        for record in records) + "\n").encode("ascii")


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-inventory-")
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "inert-unit.service"
        self.payload = ("[Service]\nEnvironment=OWNER=" + SECRET + "\nExecStart=" +
                        inventory.ARTIFACTS[1] + " --secret=" + SECRET + "\n").encode()
        self.path.write_bytes(self.payload)
        self.path.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_file_hash_modes_without_content_or_execution(self):
        with mock.patch.object(inventory.subprocess, "Popen", side_effect=AssertionError("no subprocess")):
            result = inventory.inspect_file(str(self.path), 4096, inventory.Budget(), references=True)
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result["mode"], "0600")
        self.assertEqual(result["uid"], os.geteuid())
        self.assertEqual(result["references"], [inventory.ARTIFACTS[1]])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(self.path.read_bytes(), self.payload)
        # /tmp or the user-owned fixture is not a root-trusted install directory.
        self.assertEqual(result["status"], "untrusted_metadata")

    def test_symlinks_fifo_hardlinks_missing_and_bounds_are_incomplete(self):
        link = self.root / "link.service"
        link.symlink_to(self.path)
        self.assertEqual(inventory.inspect_file(str(link), 4096, inventory.Budget())["status"], "symlink_or_not_directory")
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(inventory.inspect_file(str(alias / self.path.name), 4096, inventory.Budget())["status"], "symlink_or_not_directory")
        fifo = self.root / "fifo.service"
        os.mkfifo(fifo)
        self.assertEqual(inventory.inspect_file(str(fifo), 4096, inventory.Budget())["status"], "not_regular")
        hard = self.root / "hard.service"
        os.link(self.path, hard)
        result = inventory.inspect_file(str(hard), 4096, inventory.Budget())
        self.assertEqual(result["links"], 2)
        self.assertNotEqual(result["status"], "observed")
        self.assertEqual(inventory.inspect_file(str(self.root / "missing"), 4096, inventory.Budget())["status"], "missing")
        self.assertEqual(inventory.inspect_file(str(self.path), 4, inventory.Budget())["status"], "file_bound_exceeded")
        with mock.patch.object(inventory, "open_directory", side_effect=PermissionError(SECRET)):
            result = inventory.inspect_file(str(self.path), 4096, inventory.Budget())
        self.assertEqual(result["status"], "inaccessible")
        self.assertNotIn(SECRET, json.dumps(result))

    def test_change_during_hash_and_global_budget(self):
        real_read = os.read
        changed = False

        def changing_read(fd, size):
            nonlocal changed
            data = real_read(fd, size)
            if not changed:
                changed = True
                with self.path.open("ab") as file:
                    file.write(b"changed")
            return data

        with mock.patch.object(inventory.os, "read", side_effect=changing_read):
            result = inventory.inspect_file(str(self.path), 4096, inventory.Budget())
        self.assertEqual(result["status"], "file_changed_during_read")
        budget = inventory.Budget()
        budget.remaining = 1
        self.assertEqual(inventory.inspect_file(str(self.path), 4096, budget)["status"], "inventory_bound_exceeded")

    def test_structured_properties_and_non_service_pids(self):
        timer = properties("heteronetwork-public-services-autopilot.timer", SubState="waiting")
        del timer["MainPID"]
        del timer["ControlPID"]
        result = inventory.parse_show(encode(timer))
        self.assertEqual(result[0]["MainPID"], 0)
        for raw in [encode(properties()) + b"Environment=" + SECRET.encode() + b"\n",
                    encode(properties()) + b"Id=heteronetwork-agent.service\n",
                    encode(properties(Id="unrelated.service")),
                    encode(properties(Requires="bad/name.service")),
                    encode(properties(MainPID="-1")),
                    encode(properties(ActiveState=SECRET)),
                    encode(properties(), properties())]:
            with self.assertRaises(inventory.Incomplete) as caught:
                inventory.parse_show(raw)
            self.assertNotIn(SECRET, str(caught.exception))
        service = properties()
        del service["MainPID"]
        with self.assertRaises(inventory.Incomplete):
            inventory.parse_show(encode(service))

    def test_dependency_closure_includes_explicit_restart_and_external_boundary(self):
        records = inventory.parse_show(encode(
            properties(Requires="heteronetwork-gateway.service", RequiredBy="kubelet.service"),
            properties("heteronetwork-gateway.service"),
            properties("heteronetwork-control-plane.service", Requires="heteronetwork-agent.service", BindsTo="heteronetwork-agent.service"),
            properties("heteronetwork-signal.service", Requires="heteronetwork-agent.service", BindsTo="heteronetwork-agent.service"),
            properties("heteronetwork-stun.service", Requires="heteronetwork-agent.service", BindsTo="heteronetwork-agent.service"),
            properties("heteronetwork-public-services-autopilot.timer", PartOf="heteronetwork-agent.service")))
        closure = inventory.dependency_closure(records)
        dependents = closure["requires_binds_to_partof_dependents"]
        self.assertEqual(len(dependents["heteronetwork-agent.service"]), 4)
        self.assertIn("heteronetwork-control-plane.service", dependents["heteronetwork-gateway.service"])
        self.assertEqual(closure["uninspected_stop_dependents"], ["kubelet.service"])
        outside = closure["uninspected_stop_dependents_by_origin"]
        self.assertEqual(outside["heteronetwork-agent.service"], ["kubelet.service"])
        self.assertEqual(outside["heteronetwork-gateway.service"], ["kubelet.service"])
        self.assertEqual(outside["heteronetwork-stun.service"], [])

    def test_external_stop_boundary_propagation_handles_cycles_and_deduplication(self):
        records = inventory.parse_show(encode(
            properties(PartOf="heteronetwork-gateway.service", RequiredBy="kubelet.service"),
            properties("heteronetwork-gateway.service", PartOf="heteronetwork-agent.service",
                       BoundBy="kubelet.service", ConsistsOf="external.service")))
        result = inventory.dependency_closure(records)
        for name in ("heteronetwork-agent.service", "heteronetwork-gateway.service"):
            self.assertEqual(result["uninspected_stop_dependents_by_origin"][name],
                             ["external.service", "kubelet.service"])
            self.assertNotIn(name, result["requires_binds_to_partof_dependents"][name])
        self.assertEqual(inventory.dependency_closure([])["uninspected_stop_dependents_by_origin"], {})

    def test_strict_escaped_dependency_names_remain_literal(self):
        mount = r"run-credentials-heteronetwork\x2dcontrol\x2dplane.service.mount"
        accepted = [mount, r"dev-disk-by\x2duuid-1234.device", r"mnt-space\x20name.mount",
                    r"mnt-\xc3\xa9.mount", "-.mount", "system.slice"]
        for name in accepted:
            self.assertTrue(inventory.valid_dependency(name), name)
        records = inventory.parse_show(encode(properties("heteronetwork-control-plane.service",
            Requires="heteronetwork-agent.service " + json.dumps(mount), After=json.dumps(mount))))
        self.assertIn(mount, records[0]["Requires"])
        self.assertIn(mount, inventory.dependency_closure(records)["uninspected_boundary_units"])
        self.assertNotIn(mount.replace(r"\x2d", "-"), records[0]["Requires"])
        rejected = [r"bad\name.mount", r"bad\x2.mount", r"bad\xgg.mount", r"bad\X2d.mount",
                    r"bad\x2D.mount", r"bad\x00.mount", r"bad\x0a.mount", r"bad\x1f.mount",
                    r"bad\x7f.mount", r"bad\x2f.mount", "bad/name.mount", "bad name.mount",
                    "bad;name.mount", "bad\nname.mount", "bad.service/extra", "bad.unknown",
                    r"bad\x2d", "a" * 250 + ".mount"]
        for name in rejected:
            self.assertFalse(inventory.valid_dependency(name), repr(name))
        for name in [value for value in rejected if not any(char.isspace() for char in value)]:
            with self.assertRaises(inventory.Incomplete):
                inventory.parse_show(encode(properties(Requires=name)))
        escaped_scoped = r"heteronetwork-test\x2drole.service"
        self.assertFalse(inventory.scoped(escaped_scoped))
        with self.assertRaises(inventory.Incomplete):
            inventory.parse_show(encode(properties(Id=escaped_scoped)))
        with self.assertRaises(inventory.Incomplete):
            inventory.unit_path("/etc/systemd/system/" + escaped_scoped)

    def test_actual_systemctl_quoted_after_list_preserves_escaped_mount(self):
        after = (r'heteronetwork-agent.service network-online.target "run-credentials-heteronetwork\\x2dcontrol\\x2dplane.service.mount" '
                 r'systemd-journald.socket sysinit.target -.mount system.slice systemd-tmpfiles-setup.service basic.target tmp.mount')
        mount = r"run-credentials-heteronetwork\x2dcontrol\x2dplane.service.mount"
        records = inventory.parse_show(encode(properties("heteronetwork-control-plane.service", After=after)))
        self.assertEqual(len(records[0]["After"]), 10)
        self.assertIn(mount, records[0]["After"])
        self.assertNotIn('"' + mount + '"', records[0]["After"])
        self.assertNotIn(mount.replace(r"\x2d", "-"), records[0]["After"])
        self.assertIn(mount, inventory.dependency_closure(records)["uninspected_boundary_units"])
        for value in ['"unterminated.service', "'unterminated.service", '"a.service"b.service',
                      'a.service"b.service"', '"a.service""b.service"', '""', '"bad name.service"',
                      r'"bad\x2d.service"', r'bad\x00.service', r'bad\x2d.service',
                      r'"bad\\x00.service"', r'"bad\\x2f.service"', r'"bad\\xgg.service"',
                      '"a.service";b.service', '"$(anything).service"', '"a.service" #comment']:
            with self.assertRaises(inventory.Incomplete, msg=repr(value)):
                inventory.parse_show(encode(properties(After=value)))
        self.assertEqual(inventory.parse_dependencies("   "), [])
        self.assertEqual(inventory.parse_dependencies('"a.service" b.service'), ["a.service", "b.service"])
        with mock.patch.object(inventory, "MAX_UNITS", 1):
            with self.assertRaises(inventory.Incomplete):
                inventory.parse_dependencies('"a.service" b.service')
            with self.assertRaises(inventory.Incomplete):
                inventory.parse_dependencies("a" * 514)

    def test_fixed_paths_reject_secret_locations_and_traversal(self):
        self.assertEqual(inventory.unit_path("/etc/systemd/system/heteronetwork-agent.service.d/10-local.conf", True),
                         "/etc/systemd/system/heteronetwork-agent.service.d/10-local.conf")
        for path in ["/etc/credstore/owner.key", "/etc/systemd/system/../owner.key",
                     "/etc/systemd/system/owner.env", "/etc/systemd/system/heteronetwork-agent.service\\x20"]:
            with self.assertRaises(inventory.Incomplete):
                inventory.unit_path(path)

    def test_full_discovery_includes_inactive_roles_and_timers(self):
        (self.root / "heteronetwork-agent.service.wants").mkdir()
        (self.root / "heteronetwork-agent.service.requires").mkdir()
        for name in ["heteronetwork-db.service", "heteronetwork-keycloak.service",
                     "heteronetwork-postgres-autopilot.service", "heteronetwork-public-services-bootstrap.timer",
                     "heteronetwork-public-services-autopilot.timer", "heteronetwork-relay-autopilot.timer",
                     "heteronetwork-relay.service", "unrelated.service"]:
            (self.root / name).write_bytes(b"inert")
        with mock.patch.object(inventory, "UNIT_ROOTS", (str(self.root),)):
            names, issues = inventory.discover_files(inventory.Budget())
        self.assertEqual(len(names), 7)
        self.assertTrue(issues)
        self.assertNotIn("unsupported_unit_name", [issue["reason"] for issue in issues])
        self.assertNotIn("unrelated.service", names)

    def test_proc_executable_hash_and_unknown_consumer_without_cmdline(self):
        exe = self.root / "exe"
        exe.write_bytes(b"not an executable, never executed")
        real_open = os.open

        def proc_open(path, flags, **kwargs):
            if path == "/proc/123":
                return real_open(self.root, flags)
            self.assertEqual(path, "exe")
            return real_open(path, flags, **kwargs)

        with mock.patch.object(inventory.os, "open", side_effect=proc_open):
            result = inventory.inspect_process(123, inventory.Budget())
        self.assertEqual(result["sha256"], hashlib.sha256(exe.read_bytes()).hexdigest())
        self.assertEqual(result["status"], "observed")
        entries = mock.MagicMock()
        entries.__enter__.return_value = iter([types.SimpleNamespace(name="123", path="/proc/123")])
        with mock.patch.object(inventory.os, "scandir", return_value=entries), \
             mock.patch.object(inventory.os, "open", side_effect=proc_open), \
             mock.patch.object(inventory.os, "readlink", return_value=inventory.ARTIFACTS[1] + " (deleted)"):
            result = inventory.scan_consumers([], set(), inventory.Budget())
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["unknown_consumers"][0]["artifact"], inventory.ARTIFACTS[1])
        with mock.patch.object(inventory.os, "open", side_effect=PermissionError(SECRET)):
            result = inventory.inspect_process(123, inventory.Budget())
        self.assertEqual(result["status"], "inaccessible")
        self.assertNotIn(SECRET, json.dumps(result))

    def run_fixture(self, overrides=None, bad_file=None, scan=None):
        values = properties(MainPID="123", DropInPaths="/etc/systemd/system/heteronetwork-agent.service.d/10-fixed.conf")
        if overrides:
            values.update(overrides)
        calls = []
        reads = []

        def systemctl(arguments, _budget):
            calls.append(arguments)
            return encode(values)

        def inspect(path, _maximum, _budget, references=False):
            reads.append(path)
            return {"path": path, "status": "missing" if path == bad_file else "observed",
                    "sha256": "a" * 64 if path == inventory.ARTIFACTS[1] else "b" * 64,
                    "references": [inventory.ARTIFACTS[1]] if references else [],
                    "mode": "0755", "uid": 0, "gid": 0, "device": 1, "inode": len(reads),
                    "links": 1, "root_owned_nonwritable": True, "trusted_ancestry": True}

        with mock.patch.object(inventory, "bounded_systemctl", side_effect=systemctl), \
             mock.patch.object(inventory, "discover_files", return_value=(set(), [])), \
             mock.patch.object(inventory, "inspect_file", side_effect=inspect), \
             mock.patch.object(inventory, "inspect_process", return_value={"pid": 123, "status": "observed", "sha256": "a" * 64}), \
             mock.patch.object(inventory, "scan_consumers", return_value=scan or {"status": "observed", "unknown_consumers": [], "unobservable_processes": 0}):
            result = inventory.inventory()
        return result, calls, reads

    def test_report_all_artifacts_caddy_preserve_and_no_activation(self):
        result, calls, reads = self.run_fixture()
        self.assertEqual(len(result["artifacts"]), 12)
        self.assertEqual([item["path"] for item in result["preserve"]], [inventory.CADDY])
        self.assertTrue(result["evidence_complete"])
        self.assertFalse(result["activation_performed"])
        self.assertFalse(result["deployment_ready"])
        self.assertTrue(all(call[0] == "show" for call in calls))
        self.assertTrue(all("ExecStart" not in str(call) and "Environment" not in str(call) for call in calls))
        self.assertEqual(calls[0][-1], "heteronetwork-*")
        self.assertTrue(set(inventory.ARTIFACTS + (inventory.CADDY,)).issubset(reads))

    def test_incomplete_missing_unknown_external_and_secret_fragment(self):
        cases = [dict(bad_file=inventory.ARTIFACTS[2]),
                 dict(overrides={"Id": "heteronetwork-unreviewed.service"}),
                 dict(overrides={"RequiredBy": "kubelet.service"}),
                 dict(overrides={"FragmentPath": "/etc/credstore/" + SECRET}),
                 dict(scan={"status": "incomplete", "unknown_consumers": [{"pid": 345}]}),
                 dict(overrides={"MainPID": "0"}),
                 dict(overrides={"UnitFileState": ""})]
        for case in cases:
            result, _, reads = self.run_fixture(**case)
            self.assertFalse(result["evidence_complete"])
            self.assertFalse(result["deployment_ready"])
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertFalse(any("credstore" in path for path in reads))

    def test_systemctl_bounds_sanitized_environment_and_no_payload_execution(self):
        for mode in ("ok", "oversize", "timeout", "failure"):
            read_fd, write_fd = os.pipe()
            stream = os.fdopen(read_fd, "rb")
            if mode != "timeout":
                os.write(write_fd, b"x" * (32 if mode == "oversize" else 2))
                os.close(write_fd)
            process = mock.Mock(stdout=stream, pid=999999)
            process.poll.return_value = None
            process.wait.return_value = 1 if mode == "failure" else 0
            try:
                with mock.patch.object(inventory.subprocess, "Popen", return_value=process) as popen, \
                     mock.patch.object(inventory.os, "killpg") as kill, \
                     mock.patch.object(inventory, "MAX_SYSTEMCTL_BYTES", 16), \
                     mock.patch.object(inventory, "COMMAND_SECONDS", 0.01):
                    if mode == "ok":
                        self.assertEqual(inventory.bounded_systemctl(["show", "--", "heteronetwork-*"], inventory.Budget()), b"xx")
                    else:
                        with self.assertRaises(inventory.Incomplete):
                            inventory.bounded_systemctl(["show", "--", "heteronetwork-*"], inventory.Budget())
                    command = popen.call_args.args[0]
                    self.assertEqual(command[0], "/usr/bin/systemctl")
                    self.assertNotIn("shell", popen.call_args.kwargs)
                    self.assertEqual(popen.call_args.kwargs["env"]["PATH"], "/usr/bin:/bin")
                    self.assertNotIn("HOME", popen.call_args.kwargs["env"])
                    kill.assert_called_once()
                    self.assertTrue(stream.closed)
            finally:
                if mode == "timeout":
                    os.close(write_fd)
        with self.assertRaises(inventory.Incomplete):
            inventory.bounded_systemctl(["restart", "heteronetwork-agent.service"], inventory.Budget())

    def test_cli_has_no_remote_command_or_path_overrides(self):
        for flag in ("--host", "--root", "--command", "--unit", "--output"):
            with mock.patch.object(sys, "argv", ["native-release-inventory.py", flag, "untrusted"]), \
                 mock.patch("sys.stderr", new_callable=io.StringIO), \
                 mock.patch.object(inventory, "inventory", side_effect=AssertionError("must not collect")):
                with self.assertRaises(SystemExit) as caught:
                    inventory.main()
                self.assertEqual(caught.exception.code, 2)
        with mock.patch.object(sys, "argv", ["native-release-inventory.py"]), \
             mock.patch.object(inventory.sys, "platform", "win32"), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(inventory.main(), 2)
            self.assertFalse(json.loads(output.getvalue())["deployment_ready"])

    def test_output_and_discovery_limits_fail_closed(self):
        with mock.patch.object(sys, "argv", ["native-release-inventory.py"]), \
             mock.patch.object(inventory, "inventory", return_value={"evidence_complete": True, "oversize": "x" * 100}), \
             mock.patch.object(inventory, "MAX_REPORT_BYTES", 32), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(inventory.main(), 2)
            result = json.loads(output.getvalue())
            self.assertFalse(result["evidence_complete"])
            self.assertEqual(result["issues"][0]["reason"], "report_bound_exceeded")
        with mock.patch.object(inventory, "UNIT_ROOTS", (str(self.root),)), \
             mock.patch.object(inventory, "MAX_ENTRIES", 0):
            _, issues = inventory.discover_files(inventory.Budget())
            self.assertIn("directory_bound_exceeded", [item["reason"] for item in issues])
        with mock.patch.object(inventory, "MAX_UNITS", 1):
            with self.assertRaises(inventory.Incomplete):
                inventory.parse_show(encode(properties(), properties("heteronetwork-db.service")))


if __name__ == "__main__":
    unittest.main()
