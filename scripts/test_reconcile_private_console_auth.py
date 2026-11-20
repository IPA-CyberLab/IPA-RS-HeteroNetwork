import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).with_name("reconcile-private-console-auth.py")
spec = importlib.util.spec_from_file_location("private_console_auth", PATH)
private = importlib.util.module_from_spec(spec)
spec.loader.exec_module(private)


def entry(name, value):
    encoded = base64.b64encode(value.encode()).decode()
    return private.PREFIX + name + "_B64=" + encoded + "\n"


class PrivateConsoleAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "bootstrap.env"
        self.original = (
            "# Preserve unrelated settings and credentials\n"
            + entry("VPN_POOL", "10.250.0.0/24")
            + entry("OIDC_CLIENT_ID", "ipars-web")
            + entry("OIDC_REQUIRED_EMAIL", "owner@example.test")
            + entry("OIDC_ISSUER_URL", "https://cloud.example/id/realms/heterocloud")
            + entry("OIDC_AUTH_BASE_URL", "http://old.internal/realms/heterocloud")
            + entry("OIDC_BACKCHANNEL_BASE_URL", "http://127.0.0.1:18079/realms/heterocloud")
            + entry("OIDC_BACKCHANNEL_FALLBACK_BASE_URLS", "http://10.250.0.4:18080/realms/heterocloud")
            + entry("OIDC_DEVICE_VERIFICATION_ORIGIN", "https://cloud.example")
            + "UNRELATED_SECRET=untouched\n"
        ).encode()
        self.path.write_bytes(self.original)
        self.path.chmod(0o600)
        self.origin = "http://console.heteronetwork.internal:18079"
        self.fallbacks = ["10.250.0.2", "10.250.0.10"]

    def test_migrates_only_owner_authentication_and_is_idempotent(self):
        self.assertTrue(private.reconcile(self.path, self.origin, self.fallbacks, check=True, expected_uid=os.geteuid()))
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertTrue(private.reconcile(self.path, self.origin, self.fallbacks, expected_uid=os.geteuid()))
        text, fields = private.parse(self.path.read_bytes())
        self.assertEqual(fields["OIDC_ISSUER_URL"], self.origin + "/realms/heteronetwork")
        self.assertEqual(fields["OIDC_AUTH_BASE_URL"], self.origin + "/realms/heteronetwork")
        self.assertEqual(fields["OIDC_DEVICE_VERIFICATION_ORIGIN"], self.origin)
        self.assertEqual(fields["OIDC_REQUIRED_EMAIL"], "owner@example.test")
        self.assertEqual(fields["OIDC_BACKCHANNEL_FALLBACK_BASE_URLS"],
                         "http://10.250.0.2:18079/realms/heteronetwork,"
                         "http://10.250.0.10:18079/realms/heteronetwork")
        self.assertIn("UNRELATED_SECRET=untouched", text)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(private.reconcile(self.path, self.origin, self.fallbacks, expected_uid=os.geteuid()))

    def test_refuses_public_identity_or_non_vpn_fallback(self):
        for origin in ("https://example.com", "http://console.heteronetwork.internal.evil:18079",
                       "http://user@console.heteronetwork.internal:18079",
                       "http://console.heteronetwork.internal:18079/path"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                private.desired_content(self.original, origin, self.fallbacks)
        for addresses in (["8.8.8.8"], ["10.250.0.2", "10.250.0.2"], []):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                private.desired_content(self.original, self.origin, addresses)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_refuses_unknown_issuer_and_duplicate_managed_fields(self):
        unknown = self.original.replace(
            entry("OIDC_ISSUER_URL", "https://cloud.example/id/realms/heterocloud").encode(),
            entry("OIDC_ISSUER_URL", "https://unrelated.example/realms/elsewhere").encode())
        with self.assertRaisesRegex(ValueError, "unrecognized owner issuer"):
            private.desired_content(unknown, self.origin, self.fallbacks)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            private.desired_content(self.original + entry("OIDC_CLIENT_ID", "ipars-web").encode(),
                                    self.origin, self.fallbacks)

    def test_rejects_unsafe_file_and_symlink(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            private.reconcile(self.path, self.origin, self.fallbacks, expected_uid=os.geteuid())
        target = self.path.with_name("target")
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            private.reconcile(self.path, self.origin, self.fallbacks, expected_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
