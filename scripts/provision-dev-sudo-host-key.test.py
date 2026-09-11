"""Disposable local key fixtures only; never access guest state or enable sudo."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("host_key", Path(__file__).with_name("provision-dev-sudo-host-key.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
DKG = SimpleNamespace(GUESTS=[("dev-fixture", "fixture-machine", "fixture-node")],
                      CLUSTER="fixture-cluster", decode=json.loads)


@contextlib.contextmanager
def sandbox():
    with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
        root = Path(directory) / "config"
        stack.enter_context(patch.object(module, "ROOT", root))
        stack.enter_context(patch.object(module, "trusted"))
        stack.enter_context(patch.object(module, "sudo_snapshot", return_value={}))
        stack.enter_context(patch.object(module, "read", side_effect=lambda path, *a, **kw: path.read_bytes()))
        yield root


class Tests(unittest.TestCase):
    def test_raw_seed_matches_ed25519_public_key_vector(self):
        # RFC 8032 section 7.1, test 1: public test material, not a deployed key.
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        key = module.Ed25519PrivateKey.from_private_bytes(seed)
        self.assertEqual(module.public_bytes(key).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    def test_create_and_repeat_preserve_key_and_metadata(self):
        with sandbox() as root:
            first = module.provision(DKG, 1)
            key = (root / "host.key").read_bytes()
            inode = (root / "host.key").stat().st_ino
            second = module.provision(DKG, 1)
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertEqual(first["public_record"], second["public_record"])
            self.assertEqual(key, (root / "host.key").read_bytes())
            self.assertEqual(inode, (root / "host.key").stat().st_ino)
            self.assertEqual((root / "host.key").stat().st_mode & 0o777, 0o600)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertFalse(first["private_key_exported"])
            self.assertFalse(first["activation_performed"])
            self.assertNotIn(key.hex(), json.dumps(first))

    def test_partial_state_is_not_regenerated(self):
        with sandbox() as root:
            root.mkdir(mode=0o700)
            with patch.object(module.Ed25519PrivateKey, "generate") as generate, self.assertRaises(ValueError):
                module.provision(DKG, 1)
            generate.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_conflicting_public_pin_and_policy_refused_without_overwrite(self):
        for conflict in ("public", "config"):
            with sandbox() as root:
                module.provision(DKG, 1)
                key = (root / "host.key").read_bytes()
                if conflict == "public":
                    value = json.loads((root / "host-public.json").read_bytes())
                    value["attestation_public_key"] = [0] * 32
                    (root / "host-public.json").write_text(json.dumps(value))
                else:
                    (root / "config.json").write_text("{}")
                with self.assertRaises(ValueError):
                    module.provision(DKG, 1)
                self.assertEqual(key, (root / "host.key").read_bytes())

    def test_other_guest_identity_refused(self):
        with sandbox():
            module.provision(DKG, 1)
            other = SimpleNamespace(GUESTS=[("other", "other", "other")], CLUSTER="other", decode=json.loads)
            with self.assertRaises(ValueError):
                module.provision(other, 1)

    def test_sudo_changes_are_not_reported_as_success(self):
        with sandbox(), patch.object(module, "sudo_snapshot", side_effect=[{}, {"changed": True}]):
            with self.assertRaises(ValueError):
                module.provision(DKG, 1)

    def test_exclusive_write_preserves_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            module.write_new(path, b"original")
            with self.assertRaises(FileExistsError):
                module.write_new(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
