import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).with_name("retire-public-owner-client.py")
spec = importlib.util.spec_from_file_location("retire_public_owner_client", PATH)
retirement = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retirement)


class FakeKeycloak:
    def __init__(self):
        self.client = {"id": "11111111-1111-1111-1111-111111111111", "clientId": "ipars-web",
                       "publicClient": True, "enabled": True,
                       "redirectUris": ["http://console.heteronetwork.internal/ui/callback"]}
        self.updates = []

    def get(self, path, *, realm=None, query=None):
        if path != "clients" or realm != "heterocloud" or query != {"clientId": "ipars-web"}:
            raise AssertionError("attempted to change another identity client")
        return [self.client] if self.client else []

    def update_client(self, identifier, changes, *, realm):
        self.updates.append((identifier, changes, realm))
        self.client.update(changes)


class RetirePublicOwnerClientTests(unittest.TestCase):
    def test_disables_only_the_known_legacy_client_and_is_idempotent(self):
        kc = FakeKeycloak()
        self.assertTrue(retirement.retire(kc))
        self.assertEqual(kc.updates[0][1:], ({"enabled": False}, "heterocloud"))
        self.assertFalse(retirement.retire(kc))
        self.assertEqual(len(kc.updates), 1)

    def test_refuses_an_unexpected_client(self):
        kc = FakeKeycloak()
        kc.client["redirectUris"] = ["https://public.example/callback"]
        with self.assertRaisesRegex(ValueError, "known owner console"):
            retirement.retire(kc)
        self.assertEqual(kc.updates, [])

    def test_missing_client_needs_no_change(self):
        kc = FakeKeycloak()
        kc.client = None
        self.assertFalse(retirement.retire(kc))


if __name__ == "__main__":
    unittest.main()
