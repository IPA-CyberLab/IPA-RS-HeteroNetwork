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
