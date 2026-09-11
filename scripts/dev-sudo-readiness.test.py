"""Public fixtures only. No services, keys, ledgers, or guest access."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import subprocess


spec = importlib.util.spec_from_file_location("readiness", Path(__file__).with_name("dev-sudo-readiness.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    guests = {f"hetero-dev-{i}": {"node_id": f"node-{i}", "voter_identifier": i,
                                "endpoint": f"https://10.251.0.{i}:8443", "machine_id": str(i) * 32}
              for i in range(1, 4)}
    return {"guests": guests, "service_sha256": "a" * 64, "policy": {
        "schema_version": 2, "manifest": {"schema_version": 1, "cluster_id": "dev-cluster", "epoch": 1,
            "public_key_package": [1, 2, 3],
            "members": [{"node_id": g["node_id"], "identifier": g["voter_identifier"], "endpoint": g["endpoint"]}
                        for g in guests.values()]},
        "hosts": {g["node_id"]: {"attestation_key_epoch": 1, "attestation_public_key": [g["voter_identifier"]] * 32, "callers": {
            "1000": {"issuer": "https://owner.example/realm", "subject": "fixture-owner"}}}
                  for g in guests.values()}}}


class Tests(unittest.TestCase):
    def test_inactive_unit_rejects_overrides_and_activation(self):
        unit = "/etc/systemd/system/local-sudo-v2.service"
        properties = dict(LoadState="loaded", ActiveState="inactive", SubState="dead",
                          FragmentPath=unit, DropInPaths="", UnitFileState="disabled",
                          NeedDaemonReload="no")
        module.validate_inactive_unit(properties, unit)
        for key, value in (("LoadState", "not-found"), ("ActiveState", "active"),
                           ("SubState", "running"), ("UnitFileState", "enabled"),
                           ("UnitFileState", "enabled-runtime"), ("NeedDaemonReload", "yes"),
                           ("FragmentPath", "/run/systemd/system/local-sudo-v2.service"),
                           ("DropInPaths", "/etc/systemd/system/local-sudo-v2.service.d/override.conf")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                module.validate_inactive_unit({**properties, key: value}, unit)
        with self.assertRaises(ValueError):
            module.validate_inactive_unit({**properties, "Unknown": "x"}, unit)

    def test_inactive_plugins_fail_closed(self):
        module.validate_inactive_plugins(b"# Plugin example module.so\nDebug sudo /var/log/sudo debug\n")
        for value in (b"Plugin quorum_v2_gate /opt/gate.so", b" Plugin sudoers_policy sudoers.so",
                      b"plugin unknown /tmp/gate.so", b"Plugin\\\n gate /opt/gate.so"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_inactive_plugins(value)

    def test_runtime_inspection_is_read_only(self):
        output = (b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                  b"FragmentPath=/etc/systemd/system/local-sudo-v2.service\n"
                  b"DropInPaths=\nUnitFileState=disabled\nNeedDaemonReload=no\n")
        with patch.object(module.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=output)) as run, patch.object(module, "read", return_value=b""):
            module.inactive_runtime_check("/etc/systemd/system/local-sudo-v2.service")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/bin/systemctl", "show", "--no-pager"])
        self.assertEqual(command[-1], "local-sudo-v2.service")
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_runtime_inspection_refuses_failure_and_duplicate_properties(self):
        for result in (SimpleNamespace(returncode=1, stdout=b""),
                       SimpleNamespace(returncode=0, stdout=b"LoadState=loaded\nLoadState=loaded\n")):
            with patch.object(module.subprocess, "run", return_value=result), \
                    patch.object(module, "read") as read, self.assertRaises(ValueError):
                module.inactive_runtime_check("/etc/systemd/system/local-sudo-v2.service")
            read.assert_not_called()

    def test_native_check_uses_only_fixed_flag_and_clean_environment(self):
        with patch.object(module, "read", return_value=b"verified") as read, \
                patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            module.native_check("/opt/pinned", module.NATIVE_CONFIG, b"verified")
        read.assert_called_once_with(Path("/opt/pinned/bin/local-sudo-v2"), 8, 0o755)
        run.assert_called_once_with(
            ["/opt/pinned/bin/local-sudo-v2", "--check-config"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
            cwd="/", timeout=15, check=False,
        )

    def test_native_check_rejects_different_config_before_execution(self):
        with patch.object(module.subprocess, "run") as run, \
                self.assertRaisesRegex(ValueError, "fixed_config_path"):
            module.native_check("/opt/pinned", "/tmp/config.json", b"verified")
        run.assert_not_called()

    def test_native_check_rejects_changed_binary_before_execution(self):
        with patch.object(module, "read", return_value=b"changed"), \
                patch.object(module.subprocess, "run") as run, \
                self.assertRaisesRegex(ValueError, "native_checker_changed"):
            module.native_check("/opt/pinned", module.NATIVE_CONFIG, b"verified")
        run.assert_not_called()

    def test_native_check_fails_closed_on_error_or_timeout(self):
        with patch.object(module, "read", return_value=b"verified"):
            for code in (1, 2, -9):
                with self.subTest(code=code), patch.object(module.subprocess, "run",
                        return_value=SimpleNamespace(returncode=code)), \
                        self.assertRaisesRegex(ValueError, "native_configuration_rejected"):
                    module.native_check("/opt/pinned", module.NATIVE_CONFIG, b"verified")
            with patch.object(module.subprocess, "run",
                    side_effect=subprocess.TimeoutExpired("checker", 15)), \
                    self.assertRaises(subprocess.TimeoutExpired):
                module.native_check("/opt/pinned", module.NATIVE_CONFIG, b"verified")

    def test_exact_public_inventory(self):
        module.validate_expected(fixture(), "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_cluster_and_host_guard(self):
        for cluster, host, machine in (("production", "hetero-dev-1", "1" * 32),
                                       ("dev-cluster", "prod-host", "1" * 32),
                                       ("dev-cluster", "hetero-dev-1", "2" * 32)):
            with self.assertRaises(ValueError):
                module.validate_expected(fixture(), cluster, host, machine)

    def test_voter_host_and_owner_pins(self):
        original = fixture()
        for mutate in (
            lambda x: x["policy"]["manifest"]["members"][0].update(identifier=9),
            lambda x: x["policy"]["hosts"].pop("node-3"),
            lambda x: x["policy"]["hosts"]["node-1"]["callers"]["1000"].update(issuer="http://owner.example"),
            lambda x: x["guests"].pop("hetero-dev-3"),
        ):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            module.unique_object([("policy", {}), ("policy", {})])

    def test_duplicate_host_keys_rejected(self):
        value = fixture()
        value["policy"]["hosts"]["node-2"]["attestation_public_key"] = [1] * 32
        with self.assertRaisesRegex(ValueError, "duplicate_host_public_pin"):
            module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_caller_uids_rejected(self):
        for uid in ("0", "-1", "01", "4294967296", "1000 ", "root"):
            value = fixture()
            callers = value["policy"]["hosts"]["node-1"]["callers"]
            callers[uid] = callers.pop("1000")
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_invalid_identity_and_epoch_rejected(self):
        for field, invalid in (("issuer", "https://owner.example/\nrealm"),
                               ("issuer", "https://" + "a" * 2048),
                               ("subject", "owner\x00"), ("subject", "a" * 257),
                               ("subject", "\u00e9" * 129)):
            value = fixture()
            value["policy"]["hosts"]["node-1"]["callers"]["1000"][field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)
        for epoch in (True, 1.5, 0, 2**64):
            value = fixture()
            value["policy"]["hosts"]["node-1"]["attestation_key_epoch"] = epoch
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_relative_paths_rejected(self):
        with self.assertRaises(ValueError):
            module.read("config.json", 1024)

    def test_public_pin_shape_required(self):
        for field in ("public_key_package", "attestation_public_key"):
            value = fixture()
            if field == "public_key_package":
                value["policy"]["manifest"][field] = []
            else:
                value["policy"]["hosts"]["node-1"][field] = [256] * 32
            with self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)


if __name__ == "__main__":
    unittest.main()
