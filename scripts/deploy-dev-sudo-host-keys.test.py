"""Offline coordinator contract tests; no SSH or guest operations."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("deployment", Path(__file__).with_name("deploy-dev-sudo-host-keys.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
LOCAL_POPEN = subprocess.Popen


class Tests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(module.subprocess, "Popen", side_effect=AssertionError("unmocked process prohibited"))
        guard.start()
        self.addCleanup(guard.stop)

    def test_fixed_ssh_and_destination(self):
        self.assertEqual(module.SSH[:5], ["/usr/bin/ssh", "-F", "/dev/null", "-i",
                                        "/var/lib/hetero-dev-provisioner/admin_ed25519"])
        for value in ("BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes",
                      "ConnectTimeout=10",
                      "UserKnownHostsFile=/var/lib/hetero-dev-provisioner/known_hosts"):
            self.assertIn(value, module.SSH)
        self.assertEqual(module.DEST,
                         "/opt/heteronetwork-dev-sudo-host-key-f0e8c943/provision-dev-sudo-host-key.py")

    def test_invoke_is_bounded_and_quotes_fixed_arguments(self):
        arguments = ["sudo", "-n", "/usr/bin/python3", "-B", module.DEST]
        def child(command, **kwargs):
            return LOCAL_POPEN([sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                               **kwargs)
        with patch.object(module.subprocess, "Popen", side_effect=child) as spawn:
            self.assertEqual(module.invoke(2, arguments, b"fixture"), b"fixture")
        self.assertEqual(spawn.call_args.args[0], [*module.SSH, "devadmin@172.28.240.12",
                                                   shlex.join(arguments)])
        self.assertEqual(spawn.call_args.kwargs["env"], module.ENV)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])

    def test_invalid_target_or_oversized_input_does_not_spawn(self):
        with patch.object(module.subprocess, "Popen") as spawn:
            for member in (0, 4):
                with self.assertRaises(ValueError):
                    module.invoke(member, ["fixed"])
            with self.assertRaises(ValueError):
                module.invoke(1, ["fixed"], b"x" * (module.LIMIT + 1))
            spawn.assert_not_called()

    def result(self, member):
        guest, machine, node = module.GUESTS[member - 1]
        receipt = {"guest": guest, "script_created": True, "source_sha256": module.SOURCE_SHA}
        result = {"created": True, "sudo_configuration_unchanged": True,
                  "private_key_exported": False, "activation_performed": False,
                  "public_record": {"schema_version": 1, "guest": guest, "machine_id": machine,
                      "cluster_id": "02282a57-784b-4269-90a0-8fda47ee62ec", "host_node_id": node,
                      "manifest_file_sha256": "ec4d9c6cccac45a8afa56544279b28382af6dd9e885c25a3f478da9e61e99235",
                      "attestation_key_epoch": 1, "attestation_public_key": [member] * 32}}
        return json.dumps(receipt).encode(), json.dumps(result).encode()

    def test_deploy_uses_stdin_install_then_fixed_provisioner(self):
        raw = b"public-source-fixture"
        with patch.object(module, "invoke", side_effect=self.result(3)) as invoke:
            result = module.deploy(3, raw)
        install, run = invoke.call_args_list
        self.assertEqual(install.args[0], 3)
        self.assertEqual(install.args[1][:5], ["sudo", "-n", "/usr/bin/python3", "-B", "-c"])
        self.assertEqual(install.args[2], raw)
        self.assertEqual(run.args, (3, ["sudo", "-n", "/usr/bin/python3", "-B", module.DEST]))
        self.assertFalse(result["activation_performed"])
        self.assertFalse(result["private_key_exported"])

    def test_deploy_rejects_identity_flags_or_public_key_shape(self):
        receipt, result = self.result(1)
        value = json.loads(result)
        mutations = (
            lambda x: x["public_record"].update(guest="other"),
            lambda x: x.update(activation_performed=True),
            lambda x: x.update(private_key_exported=True),
            lambda x: x["public_record"].update(attestation_public_key=[1]),
        )
        for mutate in mutations:
            changed = json.loads(result)
            mutate(changed)
            with self.subTest(value=changed), patch.object(
                    module, "invoke", side_effect=[receipt, json.dumps(changed).encode()]), self.assertRaises(ValueError):
                module.deploy(1, b"fixture")


if __name__ == "__main__":
    unittest.main()
