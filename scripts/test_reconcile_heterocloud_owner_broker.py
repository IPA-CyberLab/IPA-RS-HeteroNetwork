import copy
import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).with_name("reconcile-heterocloud-owner-broker.py")
spec = importlib.util.spec_from_file_location("cloud_owner_broker", path)
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

OWNER = "owner@example.test"
CLOUD_ID = "11111111-1111-4111-8111-111111111111"
PRIVATE_ID = "22222222-2222-4222-8222-222222222222"
CLIENT_UUID = "33333333-3333-4333-8333-333333333333"
ISSUER = "https://cloud.example.test/id/realms/heterocloud"
ORIGIN = "http://console.heteronetwork.internal:18079"
SECRET = "unit-test-secret-that-is-not-a-real-credential"


class FakeKeycloak:
    def __init__(self):
        self.users = {
            broker.PRIVATE_REALM: [{"id": PRIVATE_ID, "email": OWNER, "username": "private-owner", "enabled": True}],
            broker.CLOUD_REALM: [{"id": CLOUD_ID, "email": OWNER, "username": OWNER,
                                  "enabled": True, "emailVerified": True}],
        }
        self.links = {PRIVATE_ID: []}
        self.client = None
        self.provider = None
        self.events = []
        self.flow = [{"providerId": "deny-access-authenticator", "requirement": "REQUIRED"}]
        self.fail_link = False

    def get(self, path, *, realm=None, query=None):
        if path == "realms/heteronetwork":
            return {"enabled": True, "registrationAllowed": False}
        if path == "authentication/flows":
            return [{"alias": broker.DENY_FLOW, "topLevel": True}]
        if path == "authentication/flows/" + broker.DENY_FLOW + "/executions":
            return copy.deepcopy(self.flow)
        if path == "users":
            users = self.users[realm]
            if query and "email" in query:
                users = [user for user in users if user["email"] == query["email"]]
            return copy.deepcopy(users)
        if path.startswith("users/") and path.endswith("/federated-identity"):
            return copy.deepcopy(self.links.get(path.split("/")[1], []))
        if path == "clients":
            return [copy.deepcopy(self.client)] if self.client else []
        if path == "clients/" + CLIENT_UUID + "/client-secret":
            return {"value": SECRET}
        if path == "identity-provider/instances":
            if not self.provider:
                return []
            provider = copy.deepcopy(self.provider)
            provider["config"]["clientSecret"] = "**********"
            return [provider]
        raise AssertionError((realm, path, query))

    def mutate(self, method, path, *, realm, body):
        self.events.append((method, realm, path))
        if path == "clients" and method == "create":
            self.client = dict(copy.deepcopy(body), id=CLIENT_UUID)
        elif path == "clients/" + CLIENT_UUID and method == "update":
            self.client = copy.deepcopy(body)
        elif path == "identity-provider/instances" and method == "create":
            self.provider = copy.deepcopy(body)
        elif path == "identity-provider/instances/heterocloud" and method == "update":
            self.provider = copy.deepcopy(body)
        elif path == "users/" + PRIVATE_ID + "/federated-identity/heterocloud" and method == "create":
            if self.fail_link:
                raise RuntimeError("simulated link failure")
            self.links[PRIVATE_ID].append(copy.deepcopy(body))
        else:
            raise AssertionError((method, realm, path))


class CloudOwnerBrokerTests(unittest.TestCase):
    def setUp(self):
        self.kc = FakeKeycloak()

    def reconcile(self):
        return broker.reconcile(self.kc, OWNER, ISSUER, ORIGIN)

    def test_creates_confidential_broker_and_links_only_exact_owner(self):
        self.assertTrue(self.reconcile())
        client, provider = self.kc.client, self.kc.provider
        self.assertFalse(client["publicClient"])
        self.assertFalse(client["directAccessGrantsEnabled"])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertEqual(client["redirectUris"], [ORIGIN + "/realms/heteronetwork/broker/heterocloud/endpoint"])
        self.assertEqual(provider["firstBrokerLoginFlowAlias"], broker.DENY_FLOW)
        self.assertFalse(provider["trustEmail"])
        self.assertFalse(provider["storeToken"])
        self.assertTrue(provider["enabled"])
        self.assertEqual(provider["config"]["issuer"], ISSUER)
        self.assertEqual(provider["config"]["tokenUrl"], broker.LOOPBACK + "/token")
        self.assertEqual(provider["config"]["validateSignature"], "true")
        self.assertEqual(provider["config"]["pkceMethod"], "S256")
        self.assertEqual(self.kc.links[PRIVATE_ID][0]["userId"], CLOUD_ID)
        before = list(self.kc.events)
        self.assertFalse(self.reconcile())
        self.assertEqual(self.kc.events, before)

    def test_unlinked_owner_is_denied_until_identity_link_is_created(self):
        self.kc.fail_link = True
        with self.assertRaises(RuntimeError):
            self.reconcile()
        self.assertFalse(self.kc.client["enabled"])
        self.assertFalse(self.kc.provider["enabled"])
        self.kc.fail_link = False
        self.assertTrue(self.reconcile())
        self.assertTrue(self.kc.client["enabled"])
        self.assertTrue(self.kc.provider["enabled"])

    def test_rejects_unmanaged_resources_and_unverified_or_wrong_owner(self):
        cases = []
        cases.append(lambda: setattr(self.kc, "client", {"clientId": broker.CLIENT_ID, "attributes": {}}))
        cases.append(lambda: setattr(self.kc, "provider", {"alias": "heterocloud", "providerId": "oidc", "config": {}}))
        cases.append(lambda: self.kc.users[broker.CLOUD_REALM][0].update(emailVerified=False))
        cases.append(lambda: self.kc.links[PRIVATE_ID].append({"identityProvider": "heterocloud", "userId": PRIVATE_ID}))
        cases.append(lambda: self.kc.flow.clear())
        for mutate in cases:
            with self.subTest(case=mutate):
                self.setUp()
                mutate()
                with self.assertRaises(ValueError):
                    self.reconcile()
                self.assertFalse(self.kc.events)

    def test_rejects_public_callback_or_non_https_cloud_issuer(self):
        for value in ("https://public.example:443", "http://console.heteronetwork.internal:18079/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                broker.reconcile(self.kc, OWNER, ISSUER, value)
        with self.assertRaises(ValueError):
            broker.reconcile(self.kc, OWNER, "http://cloud.example/id/realms/heterocloud", ORIGIN)
        self.assertFalse(self.kc.events)


if __name__ == "__main__":
    unittest.main()
