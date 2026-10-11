import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verifier', Path(__file__).with_name('verify-apiserver-etcd.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ApiServerEtcdTests(unittest.TestCase):
    def setUp(self):
        self.argument = verifier.expected_argument('10.250.0.2,10.250.0.6,10.250.0.10')
        self.pod = {'spec': {'nodeName': 'api-node', 'containers': [{'name': 'kube-apiserver', 'command': ['kube-apiserver', self.argument]}]},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}],
                               'containerStatuses': [{'name': 'kube-apiserver', 'ready': True, 'state': {'running': {}}}]}}

    def test_ready_old_manifest_cannot_complete_a_rolling_update(self):
        self.pod['spec']['containers'][0]['command'][1] = '--etcd-servers=https://127.0.0.1:2379'
        with self.assertRaises(ValueError):
            verifier.verify_pod(self.pod, 'api-node', self.argument)

    def test_new_manifest_without_a_running_container_is_rejected(self):
        self.pod['status']['containerStatuses'][0]['state'] = {'waiting': {}}
        with self.assertRaises(ValueError):
            verifier.verify_pod(self.pod, 'api-node', self.argument)

    def test_readiness_and_node_identity_are_required(self):
        with self.assertRaises(ValueError):
            verifier.verify_pod(self.pod, 'wrong-node', self.argument)
        self.pod['status']['conditions'][0]['status'] = 'False'
        with self.assertRaises(ValueError):
            verifier.verify_pod(self.pod, 'api-node', self.argument)

    def test_applied_ready_manifest_passes(self):
        verifier.verify_pod(self.pod, 'api-node', self.argument)

    def test_invalid_or_duplicate_backends_are_rejected(self):
        for addresses in ['10.250.0.2,10.250.0.6', '10.250.0.2,10.250.0.6,10.250.0.2', '10.250.0.2,10.250.0.6,not-an-ip']:
            with self.assertRaises(ValueError):
                verifier.expected_argument(addresses)


if __name__ == '__main__':
    unittest.main()
