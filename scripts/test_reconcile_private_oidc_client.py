import base64
import importlib.util
import json
from pathlib import Path
import unittest


PATH = Path(__file__).with_name("reconcile-private-oidc-client.py")
spec = importlib.util.spec_from_file_location("private_oidc_client", PATH)
private = importlib.util.module_from_spec(spec)
spec.loader.exec_module(private)


class FakeKeycloak:
    def __init__(self):
        self.client = {
            "id": "11111111-1111-1111-1111-111111111111", "clientId": "ipars-web",
            "enabled": True, "publicClient": True, "standardFlowEnabled": True,
            "attributes": {"oauth2.device.authorization.grant.enabled": "true",
                           "pkce.code.challenge.method": "S256"},
            "redirectUris": ["http://10.250.0.4:19088/ui/*"],
            "webOrigins": ["http://10.250.0.4:19088"],
        }
        self.realm = {"enabled": True, "registrationAllowed": False}
        self.owner = {"id": "22222222-2222-2222-2222-222222222222",
                      "enabled": True, "email": "owner@example.test"}
        self.links = [{"identityProvider": "github"}]
        self.providers = [{"alias": "github", "enabled": True, "trustEmail": False,
                           "firstBrokerLoginFlowAlias": "github-deny-unlinked"}]
        self.credentials = []
        self.updates = []
        self.accessed_realms = []

    def get(self, path, *, realm=None, query=None):
        self.accessed_realms.append(realm)
        if path == "realms/heteronetwork": return self.realm
        if path == "clients": return [self.client]
        if path == "users": return [self.owner] if self.owner else []
        if path == "identity-provider/instances": return self.providers
        if path.endswith("/federated-identity"): return self.links
        if path.endswith("/credentials"): return self.credentials
        raise AssertionError(path)

    def update_client(self, identifier, values):
        self.updates.append((identifier, json.loads(json.dumps(values))))
        self.client.update(values)


class PrivateOidcClientTests(unittest.TestCase):
    def setUp(self):
        self.kc = FakeKeycloak()
        self.origins = ["http://console.heteronetwork.internal",
                        "http://console.heteronetwork.internal:9781"]

    def test_prepares_private_client_without_removing_existing_redirects(self):
        self.assertTrue(private.prepare(self.kc, "owner@example.test", self.origins, check=True))
        self.assertFalse(self.kc.updates)
        self.assertTrue(private.prepare(self.kc, "owner@example.test", self.origins))
        self.assertEqual(len(self.kc.updates), 1)
        self.assertIn("http://10.250.0.4:19088/ui/*", self.kc.client["redirectUris"])
        for origin in self.origins:
            self.assertIn(origin + "/ui/callback", self.kc.client["redirectUris"])
            self.assertIn(origin, self.kc.client["webOrigins"])
        self.assertFalse(private.prepare(self.kc, "owner@example.test", self.origins))
        self.assertNotIn("heterocloud", self.kc.accessed_realms)

    def test_refuses_missing_owner_or_unlinked_provider(self):
        self.kc.owner = None
        with self.assertRaisesRegex(ValueError, "existing owner"):
            private.prepare(self.kc, "owner@example.test", self.origins)
        self.kc = FakeKeycloak()
        self.kc.providers[0]["trustEmail"] = True
        with self.assertRaisesRegex(ValueError, "sign-in method"):
            private.prepare(self.kc, "owner@example.test", self.origins)
        self.assertFalse(self.kc.updates)

    def test_refuses_open_registration_and_missing_pkce(self):
        self.kc.realm["registrationAllowed"] = True
        with self.assertRaisesRegex(ValueError, "self-registration"):
            private.prepare(self.kc, "owner@example.test", self.origins)
        self.kc.realm["registrationAllowed"] = False
        self.kc.client["attributes"]["pkce.code.challenge.method"] = "plain"
        with self.assertRaisesRegex(ValueError, "PKCE"):
            private.prepare(self.kc, "owner@example.test", self.origins)

    def test_rejects_public_or_ambiguous_console_origins(self):
        for value in ("https://example.com", "http://console.heteronetwork.internal.evil",
                      "http://user@console.heteronetwork.internal", "http://console.heteronetwork.internal/path",
                      "http://console.heteronetwork.internal?x=1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                private.console_origin(value)

    def test_owner_field_is_unique_and_encoded(self):
        email = base64.b64encode(b"Owner@example.test").decode()
        data = private.OWNER_KEY + "=" + email + "\n"
        self.assertEqual(private.owner_email(data), "owner@example.test")
        with self.assertRaises(ValueError): private.owner_email(data + data)


if __name__ == "__main__":
    unittest.main()
