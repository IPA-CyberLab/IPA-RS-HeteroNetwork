import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('configure_realm', Path(__file__).with_name('configure-realm.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
DESIRED = json.loads(Path(__file__).with_name('realm.json').read_bytes())
UID = DESIRED['attributes'][m.MARKER]


class RealmContract(unittest.TestCase):
    def test_cloud_requires_secret_but_device_client_remains_public(self):
        cloud, device = DESIRED['clients']
        self.assertFalse(cloud['publicClient'])
        self.assertEqual(cloud['clientAuthenticatorType'], 'client-secret')
        self.assertTrue(device['publicClient'])

    def test_explicit_known_legacy_upgrade_and_readback(self):
        expected = DESIRED['clients'][0]
        legacy = dict(expected, publicClient=True, id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                      secret='masked-secret-must-not-be-written')
        legacy.pop('clientAuthenticatorType')
        api = SimpleNamespace(request=Mock(side_effect=[(200, DESIRED), (200, [legacy]),
              (204, None), (200, expected), (200, [DESIRED['clients'][1]])]))
        result = m.configure(api, DESIRED, UID, upgrade_cloud_client=True)
        self.assertTrue(result['cloud_client_upgraded'])
        writes = [call for call in api.request.call_args_list if call.args[0] != 'GET']
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].args[0], 'PUT')
        self.assertFalse(writes[0].args[2]['publicClient'])
        self.assertNotIn('secret', writes[0].args[2])

    def test_legacy_requires_explicit_upgrade(self):
        legacy = dict(DESIRED['clients'][0], publicClient=True)
        api = SimpleNamespace(request=Mock(side_effect=[(200, DESIRED), (200, [legacy])]))
        with self.assertRaises(ValueError):
            m.configure(api, DESIRED, UID)
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_upgrade_does_not_repair_unrelated_drift(self):
        legacy = dict(DESIRED['clients'][0], publicClient=True, directAccessGrantsEnabled=True)
        api = SimpleNamespace(request=Mock(side_effect=[(200, DESIRED), (200, [legacy])]))
        with self.assertRaises(ValueError):
            m.configure(api, DESIRED, UID, upgrade_cloud_client=True)
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_existing_managed_realm_is_read_only(self):
        api = SimpleNamespace(request=Mock(side_effect=[(200, DESIRED),
             *((200, [client]) for client in DESIRED['clients'])]))
        result = m.configure(api, DESIRED, UID)
        self.assertFalse(result['created'])
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_foreign_realm_rejected_without_mutation(self):
        current = dict(DESIRED, attributes={m.MARKER: 'foreign'})
        api = SimpleNamespace(request=Mock(return_value=(200, current)))
        with self.assertRaises(ValueError):
            m.configure(api, DESIRED, UID)
        self.assertEqual(api.request.call_count, 1)

    def test_client_has_no_password_or_wildcard_grants(self):
        for client in DESIRED['clients']:
            self.assertFalse(client['directAccessGrantsEnabled'])
            self.assertFalse(client['implicitFlowEnabled'])
            self.assertFalse(client['serviceAccountsEnabled'])
            self.assertNotIn('secret', client)
            self.assertTrue(all('*' not in uri for uri in client['redirectUris']))
        self.assertNotIn('users', DESIRED)
        self.assertFalse(DESIRED['registrationAllowed'])

    def test_drift_rejected_not_overwritten(self):
        drift = dict(DESIRED['clients'][0], directAccessGrantsEnabled=True)
        api = SimpleNamespace(request=Mock(side_effect=[(200, DESIRED), (200, [drift])]))
        with self.assertRaises(ValueError):
            m.configure(api, DESIRED, UID)
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))


if __name__ == '__main__':
    unittest.main()
