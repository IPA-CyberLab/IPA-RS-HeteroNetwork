import importlib.util
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/provision-dev-sudo-active.py"
spec = importlib.util.spec_from_file_location("provision_dev_sudo_active", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProvisionDevSudoActiveTests(unittest.TestCase):
    def test_caller_policy_is_public_without_exposing_private_parent(self):
        helper = (ROOT / "scripts/heteronetwork-sudo-approve.py").read_text()
        self.assertEqual(module.CALLER_POLICY,
                         Path("/etc/heteronetwork-sudo-quorum/policy.json"))
        self.assertNotEqual(module.CALLER_POLICY.parent, module.POLICY.parent)
        self.assertIn(f'POLICY = "{module.CALLER_POLICY}"', helper)

    def test_inventory_is_exact_and_distinct(self):
        self.assertEqual(set(module.GUESTS), {"hetero-dev-1", "hetero-dev-2", "hetero-dev-3"})
        self.assertEqual({value[2] for value in module.GUESTS.values()}, {1, 2, 3})
        self.assertEqual({value[3] for value in module.GUESTS.values()},
                         {"10.251.0.1", "10.251.0.2", "10.251.0.3"})
        self.assertEqual(len({value[0] for value in module.GUESTS.values()}), 3)
        self.assertEqual(len({value[1] for value in module.GUESTS.values()}), 3)

    def test_signer_unit_uses_systemd_credentials_for_private_parent(self):
        raw = (ROOT / "deploy/systemd/heteronetwork-sudo-quorum-signer.service").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), module.SIGNER_UNIT_SHA256)
        text = raw.decode()
        for value in (
            "LoadCredential=quorum-manifest.json:/etc/heteronetwork/sudo-quorum/manifest.json",
            "LoadCredential=sudo-policy.json:/etc/heteronetwork/sudo-quorum/policy.json",
            "LoadCredential=quorum-share.json:/etc/credstore/heteronetwork-sudo-quorum-share.json",
            "HETERONETWORK_ADMIN_QUORUM_MANIFEST_PATH=%d/quorum-manifest.json",
            "HETERONETWORK_SUDO_QUORUM_POLICY_PATH=%d/sudo-policy.json",
        ):
            self.assertIn(value, text)

    def test_sudo_plugin_parser_fails_closed(self):
        self.assertEqual(module.plugin_directives(b"# Plugin fake /tmp/fake\nDebug sudo /tmp/log all@debug\n"), [])
        self.assertEqual(module.plugin_directives((module.PLUGIN_LINE + "\n").encode()),
                         [module.PLUGIN_LINE])
        self.assertEqual(module.plugin_directives(b"Plugin unknown /tmp/module.so # note\n"),
                         ["Plugin unknown /tmp/module.so"])
        with self.assertRaisesRegex(ValueError, "continuation"):
            module.plugin_directives(b"Plugin unknown \\\n/tmp/module.so\n")

    def test_committed_public_policy_is_exact(self):
        values = {
            "sudo-manifest.json": (ROOT / "deploy/dev/native/sudo-manifest.json").read_bytes(),
            "sudo-policy.json": (ROOT / "deploy/dev/native/sudo-policy.json").read_bytes(),
        }
        with patch.object(module, "bundle", side_effect=lambda name, maximum: values[name]):
            manifest, policy, decoded = module.public_inputs()
        self.assertEqual(module.sha(manifest), module.MANIFEST_SHA256)
        self.assertEqual(module.sha(policy), module.POLICY_SHA256)
        self.assertEqual(decoded["manifest"]["cluster_id"], module.CLUSTER)

    def test_release_rejects_old_incompatible_plugin(self):
        elf = b"\x7fELF\x02\x01\x01" + bytes(128)
        notice = b"not enabled\n"
        payloads = {
            "native/ipars": elf,
            "native/iparsd": elf,
            "sudo/local-sudo-v2": elf,
            "sudo/quorum_v2_gate.so": elf,
            "sudo/NOT_ENABLED.txt": notice,
        }
        hashes = {name: module.sha(raw) for name, raw in payloads.items()}
        hashes["sudo/quorum_v2_gate.so"] = module.OLD_INCOMPATIBLE_PLUGIN_SHA256
        release = {
            "schema_version": 1, "component": "heteronetwork",
            "version": module.VERSION, "commit": module.SOURCE_COMMIT,
            "native": {"linux-amd64": {"files": {
                "bin/ipars": hashes["native/ipars"], "bin/iparsd": hashes["native/iparsd"]}}},
            "sudo_native": {"linux-amd64": {
                "source_commit": module.SOURCE_COMMIT, "profile": "release",
                "plugin_header_sha256": module.PLUGIN_HEADER_SHA256,
                "files": {
                    "bin/local-sudo-v2": {"sha256": hashes["sudo/local-sudo-v2"]},
                    "lib/quorum_v2_gate.so": {"sha256": hashes["sudo/quorum_v2_gate.so"]},
                    "NOT_ENABLED.txt": {"sha256": hashes["sudo/NOT_ENABLED.txt"]},
                },
            }},
        }
        raw = (json.dumps(release) + "\n").encode()

        def fake_bundle(name, maximum=0):
            return raw if name == "release.json" else payloads[name]

        with patch.object(module, "RELEASE_DOCUMENT_SHA256", module.sha(raw)), \
                patch.object(module, "bundle", side_effect=fake_bundle), \
                self.assertRaisesRegex(ValueError, "incompatible"):
            module.release_payloads()

    def test_active_check_waits_for_local_sockets(self):
        state = {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled"}
        adapter = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0)
        submit = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o666, st_uid=0)
        with patch.object(module, "identity",
                          return_value=("hetero-dev-1", "machine", "node", 1, "10.251.0.1")), \
                patch.object(module, "unit_state", return_value=state), \
                patch.object(module, "wait_http"), \
                patch.object(module.Path, "lstat",
                             side_effect=[FileNotFoundError(), adapter, submit]), \
                patch.object(module.time, "monotonic", side_effect=[0, 1]), \
                patch.object(module.time, "sleep") as sleep:
            result = module.require_active()
        self.assertTrue(result["services_active"])
        sleep.assert_called_once_with(0.05)

    def test_known_replacement_requires_pinned_previous_hash(self):
        old, new = b"old helper", b"new helper"
        with patch.object(module.os.path, "lexists", return_value=True), \
                patch.object(module, "read", side_effect=[old, new]), \
                patch.object(module, "atomic_replace") as replace:
            module.install_known_replacement(Path("/trusted/helper"), new, 0o555,
                                             module.sha(old))
        replace.assert_called_once_with(Path("/trusted/helper"), new, 0o555)

        with patch.object(module.os.path, "lexists", return_value=True), \
                patch.object(module, "read", return_value=old), \
                patch.object(module, "atomic_replace"), \
                self.assertRaisesRegex(ValueError, "unknown_existing_file"):
            module.install_known_replacement(Path("/trusted/helper"), new, 0o555,
                                             "0" * 64)


if __name__ == "__main__":
    unittest.main()
