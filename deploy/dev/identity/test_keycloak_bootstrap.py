import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('bootstrap_keycloak', Path(__file__).with_name('bootstrap-keycloak.py'))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class SecretReconciliation(unittest.TestCase):
    def test_matching_secret_is_not_rewritten(self):
        existing = {'type': 'Opaque', 'data': {'password': base64.b64encode(b'fixture').decode()},
                    'metadata': {'annotations': {'heteronetwork.dev/cluster-uid': 'dev-uid'}}}
        helper = SimpleNamespace(UID='dev-uid', run=Mock(return_value=json.dumps(existing).encode()))
        bootstrap.ensure_secret(helper, 'dev-keycloak-bootstrap', 'Opaque', {'password': b'fixture'})
        self.assertEqual(helper.run.call_count, 1)

    def test_foreign_or_changed_secret_is_preserved_and_rejected(self):
        for uid, value in [('prod-uid', b'fixture'), ('dev-uid', b'changed')]:
            existing = {'type': 'Opaque', 'data': {'password': base64.b64encode(value).decode()},
                        'metadata': {'annotations': {'heteronetwork.dev/cluster-uid': uid}}}
            helper = SimpleNamespace(UID='dev-uid', run=Mock(return_value=json.dumps(existing).encode()))
            with self.assertRaises(ValueError):
                bootstrap.ensure_secret(helper, 'dev-keycloak-bootstrap', 'Opaque', {'password': b'fixture'})
            self.assertEqual(helper.run.call_count, 1)

    def test_creation_uses_stdin_and_does_not_upsert(self):
        helper = SimpleNamespace(UID='dev-uid', run=Mock(side_effect=[b'', b'secret created']))
        bootstrap.ensure_secret(helper, 'dev-keycloak-bootstrap', 'Opaque', {'password': b'fixture'})
        arguments, payload = helper.run.call_args.args
        self.assertEqual(arguments, ['create', '-f', '-'])
        self.assertEqual(json.loads(payload)['metadata']['namespace'], 'hetero-dev-identity')
        self.assertNotIn('fixture', ' '.join(arguments))


if __name__ == '__main__':
    unittest.main()
