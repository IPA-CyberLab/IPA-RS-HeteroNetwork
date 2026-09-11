import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).with_name("heteronetwork-sudo-device-login.py")
spec = importlib.util.spec_from_file_location("heteronetwork_sudo_device_login", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DeviceLoginTests(unittest.TestCase):
    def test_endpoint_is_pinned_to_issuer(self):
        expected = module.ISSUER + "/protocol/openid-connect/token"
        self.assertEqual(module.endpoint(expected, module.ISSUER, "test"), expected)
        for value in ("http://heterocloud.mizuame.app/token",
                      "https://attacker.invalid/token",
                      module.ISSUER + ".attacker.invalid/token"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.endpoint(value, module.ISSUER, "test")

    def test_token_publish_is_atomic_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            token = root / "owner.token"
            module.publish(token, b"first")
            self.assertEqual(token.read_bytes(), b"first")
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)
            module.publish(token, b"second")
            self.assertEqual(token.read_bytes(), b"second")
            token.unlink()
            os.symlink(root / "missing", token)
            with self.assertRaisesRegex(ValueError, "unsafe_existing_token"):
                module.publish(token, b"rejected")


if __name__ == "__main__":
    unittest.main()
