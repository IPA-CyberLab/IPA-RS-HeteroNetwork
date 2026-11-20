import base64
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import time
import unittest


PATH = Path(__file__).with_name("verify-private-owner-proof.py")
spec = importlib.util.spec_from_file_location("private_owner_proof", PATH)
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)

ISSUER = "http://console.heteronetwork.internal:18079/realms/heteronetwork"


def jwt(**overrides):
    payload = {"iss": ISSUER, "azp": "ipars-web", "sub": "owner-subject", "exp": time.time() + 300}
    payload.update(overrides)
    data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "header." + data + ".signature"


class Response:
    def __init__(self, value): self.value = value
    def __enter__(self): return self
    def __exit__(self, *_args): pass
    def read(self, _limit): return json.dumps(self.value).encode()


class Opener:
    def __init__(self, email="owner@example.test"):
        self.email = email
        self.urls = []
    def open(self, request, timeout):
        self.urls.append(request.full_url)
        if request.full_url.endswith("/userinfo"):
            return Response({"sub": "owner-subject", "email": self.email})
        return Response({"cluster_policy": {"overlay_strict_hierarchy": True}})


class PrivateOwnerProofTests(unittest.TestCase):
    def setUp(self):
        self.pool = ipaddress.ip_network("10.250.0.0/24")

    def test_verifies_owner_and_only_vpn_control_planes(self):
        opener = Opener()
        self.assertEqual(proof.verify(jwt(), ISSUER, "owner@example.test", self.pool,
                                      ["10.250.0.2", "10.250.0.10"], opener=opener), 2)
        self.assertEqual(len(opener.urls), 3)
        with self.assertRaises(ValueError):
            proof.verify(jwt(), ISSUER, "owner@example.test", self.pool, ["203.0.113.4"], opener=opener)
        self.assertFalse(any("203.0.113.4" in url for url in opener.urls))

    def test_rejects_wrong_realm_client_owner_and_expiry(self):
        for token in (jwt(iss="https://public.example/realms/heterocloud"),
                      jwt(azp="heterocloud-web"), jwt(exp=time.time() + 5)):
            with self.subTest(token=token[:10]), self.assertRaises(ValueError):
                proof.verify(token, ISSUER, "owner@example.test", self.pool, opener=Opener())
        with self.assertRaisesRegex(ValueError, "configured owner"):
            proof.verify(jwt(), ISSUER, "owner@example.test", self.pool, opener=Opener("other@example.test"))

    def test_proof_file_must_be_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text(jwt())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                proof.read_proof(path, os.geteuid(), check_location=False)
            path.chmod(0o600)
            self.assertEqual(proof.read_proof(path, os.geteuid(), check_location=False), path.read_text())
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                proof.read_proof(alias, os.geteuid(), check_location=False)


if __name__ == "__main__":
    unittest.main()
