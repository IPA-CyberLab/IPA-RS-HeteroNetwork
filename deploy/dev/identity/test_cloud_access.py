import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('access', Path(__file__).with_name('configure-cloud-access.py'))
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)


class CloudAccessTests(unittest.TestCase):
    def test_only_cloud_api_and_owner_are_admitted(self):
        document = access.policy()
        access.verify(document)
        rule = document['spec']['ingress'][0]
        self.assertEqual(rule['ports'], [{'protocol': 'TCP', 'port': 8443}])
        self.assertEqual(len(rule['from']), 1)
        peer = rule['from'][0]
        self.assertEqual(peer['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], 'heterocloud-dev')
        self.assertEqual(peer['podSelector']['matchExpressions'][0]['values'], ['api', 'owner-console'])
        self.assertNotIn('Egress', document['spec']['policyTypes'])

    def test_foreign_or_broadened_policy_refused(self):
        for field in ('namespaceSelector', 'podSelector'):
            document = copy.deepcopy(access.policy())
            del document['spec']['ingress'][0]['from'][0][field]
            with self.assertRaises(ValueError):
                access.verify(document)
        document = access.policy()
        document['metadata']['annotations']['heteronetwork.dev.cluster-uid'] = 'foreign'
        with self.assertRaises(ValueError):
            access.verify(document)
