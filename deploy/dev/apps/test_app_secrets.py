import base64
import copy
import json
import unittest

from cryptography.hazmat.primitives import serialization

import app_secrets as m


class AppSecretsTests(unittest.TestCase):
    def fixture(self):
        seeds = m.generate_seeds()
        databases = {name: {'database-url': 'postgresql://fixture.invalid/' + name}
                     for name in ('heterocloud-dev', 'heterocloud-flow-dev', 'heterocloud-syouyu-dev')}
        return seeds, databases

    def test_shared_values_and_private_key_boundary(self):
        seeds, databases = self.fixture()
        docs = m.build(seeds, databases)
        self.assertEqual(len(docs), 7)
        self.assertEqual(docs, m.build(seeds, databases))
        decoded = {d['metadata']['name']: {k: base64.b64decode(v).decode() for k, v in d['data'].items()} for d in docs}
        private = decoded['heterocloud-dev-provider-signing']['ed25519-private.pem']
        key = serialization.load_pem_private_key(private.encode(), password=None)
        for name, field in (('heterocloud-flow-dev-secrets', 'heterocloud-provider-public-keys.json'),
                            ('heterocloud-flash-dev-provider-auth', 'provider-public-keys.json'),
                            ('heterocloud-syouyu-dev-secrets', 'provider-public-keys.json')):
            data = decoded[name]
            self.assertNotIn('PRIVATE KEY', json.dumps(data))
            public = serialization.load_pem_public_key(json.loads(data[field])[m.KEY_ID].encode())
            public.verify(key.sign(b'fixture'), b'fixture')
        flow = decoded['heterocloud-flow-dev-secrets']
        self.assertEqual(flow['flow-principal-context-hmac-secret'], decoded['heterocloud-dev-flow-access']['hmac-secret'])
        self.assertEqual(decoded['heterocloud-syouyu-dev-secrets']['principal-context-hmac-secret'],
                         decoded['heterocloud-dev-syouyu-access']['hmac-secret'])
        self.assertEqual(json.loads(flow['livekit-keys.yaml']), {flow['livekit-api-key']: flow['livekit-api-secret']})

    def test_existing_ownership_and_data(self):
        seeds, databases = self.fixture()
        for desired in m.build(seeds, databases):
            m.verify(copy.deepcopy(desired), desired)
            actual = copy.deepcopy(desired)
            actual['metadata']['annotations'] = {}
            with self.assertRaises(ValueError):
                m.verify(actual, desired)
            actual = copy.deepcopy(desired)
            actual['data']['unexpected'] = 'extra'
            with self.assertRaises(ValueError):
                m.verify(actual, desired)

    def test_foreign_or_reused_seed_state_rejected(self):
        seeds, _ = self.fixture()
        for change in ({'cluster_uid': 'production'}, {'redis': seeds['turn']}, {'schema_version': True}):
            with self.assertRaises(ValueError):
                m.validate_seeds({**seeds, **change})

    def test_missing_database_rejected(self):
        seeds, databases = self.fixture()
        databases.pop('heterocloud-dev')
        with self.assertRaises(ValueError):
            m.build(seeds, databases)


if __name__ == '__main__':
    unittest.main()
