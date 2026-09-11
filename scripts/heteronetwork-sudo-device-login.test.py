import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch


SOURCE = Path(__file__).with_name("heteronetwork-sudo-device-login.py")
spec = importlib.util.spec_from_file_location("heteronetwork_sudo_device_login", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DeviceLoginTests(unittest.TestCase):
    def test_requests_use_product_user_agent(self):
        class Response:
            status = 200
            headers = {}

            @staticmethod
            def read(_maximum):
                return b"{}"

        class Opener:
            request = None

            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()

        opener = Opener()
        self.assertEqual(module.request(opener, module.ISSUER + "/test"), {})
        self.assertEqual(opener.request.get_header("User-agent"), module.USER_AGENT)
        self.assertEqual(opener.timeout, 15)

    def test_transient_requests_retry_but_permanent_http_errors_do_not(self):
        class Response:
            status = 200
            headers = {}

            @staticmethod
            def read(_maximum):
                return b"{}"

        class Opener:
            calls = 0

            def open(self, _request, timeout):
                self.calls += 1
                if self.calls < 3:
                    raise TimeoutError()
                self.timeout = timeout
                return Response()

        opener = Opener()
        with patch.object(module.time, "sleep") as sleep:
            self.assertEqual(module.request_with_retries(opener, module.ISSUER + "/test"), {})
        self.assertEqual(opener.calls, 3)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1,), (2,)])

        denied = urllib.error.HTTPError(
            module.ISSUER + "/test", 403, "denied", {}, io.BytesIO(b"{}")
        )
        with patch.object(opener, "open", side_effect=denied), \
                self.assertRaises(urllib.error.HTTPError):
            module.request_with_retries(opener, module.ISSUER + "/test")

        certificate_error = urllib.error.URLError(
            module.ssl.SSLCertVerificationError(1, "certificate rejected")
        )
        with patch.object(opener, "open", side_effect=certificate_error), \
                self.assertRaises(urllib.error.URLError):
            module.request_with_retries(opener, module.ISSUER + "/test")

    def test_endpoint_is_pinned_to_issuer(self):
        expected = module.ISSUER + "/protocol/openid-connect/token"
        self.assertEqual(module.endpoint(expected, module.ISSUER, "test"), expected)
        for value in ("http://heterocloud.mizuame.app/token",
                      "https://attacker.invalid/token",
                      module.ISSUER + ".attacker.invalid/token"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.endpoint(value, module.ISSUER, "test")

    def test_pkce_uses_rfc_7636_s256(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertEqual(
            module.pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        generated, challenge = module.new_pkce_pair()
        self.assertRegex(generated, module.PKCE_VERIFIER)
        self.assertEqual(challenge, module.pkce_challenge(generated))

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
