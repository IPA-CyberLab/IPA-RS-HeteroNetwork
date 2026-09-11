"""Offline deployment coordinator tests; no SSH or systemd operations."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deployment", Path(__file__).with_name("deploy-dev-sudo-runtime.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
LOCAL_POPEN = subprocess.Popen


class Tests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(module.subprocess, "Popen", side_effect=AssertionError("unmocked process prohibited"))
        guard.start()
        self.addCleanup(guard.stop)

    def test_fixed_public_payloads_match_repository(self):
        sources = {
            "provision-dev-sudo-runtime.py": ROOT / "scripts/provision-dev-sudo-runtime.py",
            "sudo-hosts.json": ROOT / "deploy/dev/native/sudo-hosts.json",
            "heteronetwork-sudo-local.service": ROOT / "deploy/systemd/heteronetwork-sudo-local.service",
            "heteronetwork-sudo-quorum-signer.service": ROOT / "deploy/systemd/heteronetwork-sudo-quorum-signer.service",
        }
        for name, path in sources.items():
            digest, size = module.FILES[name]
            raw = path.read_bytes()
            self.assertEqual((module.hashlib.sha256(raw).hexdigest(), len(raw)), (digest, size))

    def test_ssh_is_strict_and_input_is_bounded(self):
        arguments = ["sudo", "-n", "/usr/bin/python3", "-B", "fixed"]
        def child(command, **kwargs):
            return LOCAL_POPEN([sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                               **kwargs)
        with patch.object(module.subprocess, "Popen", side_effect=child) as spawn:
            self.assertEqual(module.invoke(1, arguments, b"fixture"), b"fixture")
        self.assertEqual(spawn.call_args.args[0], [*module.SSH, "devadmin@172.28.240.11",
                                                   shlex.join(arguments)])
        for option in ("BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes"):
            self.assertIn(option, module.SSH)
        with patch.object(module.subprocess, "Popen") as blocked:
            with self.assertRaises(ValueError):
                module.invoke(4, arguments)
            with self.assertRaises(ValueError):
                module.invoke(1, arguments, b"x" * (module.INPUT_LIMIT + 1))
            blocked.assert_not_called()

    def test_deliver_skips_verified_and_installs_only_after_failed_check(self):
        verified = json.dumps({"name": "sudo-hosts.json", "state": "verified"}).encode()
        with patch.object(module, "invoke", return_value=verified) as invoke:
            self.assertFalse(module.deliver(2, "sudo-hosts.json", b"fixture"))
        self.assertEqual(invoke.call_count, 1)
        installed = json.dumps({"name": "sudo-hosts.json", "state": "installed"}).encode()
        with patch.object(module, "invoke", side_effect=[ValueError("missing"), installed]) as invoke:
            self.assertTrue(module.deliver(2, "sudo-hosts.json", b"fixture"))
        self.assertEqual(invoke.call_count, 2)
        self.assertEqual(invoke.call_args.args[2], b"fixture")

    def test_deploy_requires_inactive_result(self):
        payloads = {"sudo-hosts.json": b"fixture"}
        valid = {"member": 3, "services_started": False, "services_enabled": False,
                 "activation_performed": False, "sudo_configuration_unchanged": True}
        with patch.object(module, "deliver", return_value=False), patch.object(
                module, "invoke", return_value=json.dumps(valid).encode()):
            self.assertEqual(module.deploy(3, payloads)["bundle_files_installed"], [])
        for field in ("services_started", "services_enabled", "activation_performed"):
            invalid = {**valid, field: True}
            with self.subTest(field=field), patch.object(module, "deliver", return_value=False), \
                    patch.object(module, "invoke", return_value=json.dumps(invalid).encode()), \
                    self.assertRaises(ValueError):
                module.deploy(3, payloads)


if __name__ == "__main__":
    unittest.main()
