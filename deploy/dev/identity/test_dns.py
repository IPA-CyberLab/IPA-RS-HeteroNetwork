import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('dev_dns', Path(__file__).with_name('configure-dns.py'))
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)


class DnsTests(unittest.TestCase):
    def fixture(self):
        return {'kind': 'ConfigMap', 'metadata': {'name': 'coredns', 'namespace': 'kube-system',
                'uid': 'e3077db4-e987-4159-83e2-423ff31299c9', 'resourceVersion': '282'},
                'data': {'Corefile': dns.BASELINE}}

    def test_compare_and_swap_and_repeat(self):
        document = self.fixture()
        patch = dns.patch_for(document)
        self.assertEqual([op['op'] for op in patch], ['test', 'test', 'test', 'replace'])
        self.assertEqual(patch[1]['value'], '282')
        document['data']['Corefile'] = patch[-1]['value']
        self.assertEqual(dns.patch_for(document), [])
        self.assertEqual(dns.DESIRED.count('rewrite name exact'), 1)
        self.assertIn(dns.SERVICE, dns.DESIRED)

    def test_foreign_or_modified_configuration_is_rejected(self):
        for field, value in [('uid', 'foreign'), ('namespace', 'other'), ('resourceVersion', '')]:
            document = self.fixture()
            document['metadata'][field] = value
            with self.assertRaises(ValueError):
                dns.patch_for(document)
        for data in [{'Corefile': dns.BASELINE + '# user change'}, {'Corefile': dns.BASELINE, 'extra': 'x'}]:
            document = copy.deepcopy(self.fixture())
            document['data'] = data
            with self.assertRaises(ValueError):
                dns.patch_for(document)
