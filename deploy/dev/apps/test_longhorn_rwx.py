import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('rwx', Path(__file__).with_name('verify-longhorn-rwx.py'))
rwx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rwx)


class RwxTests(unittest.TestCase):
    def test_real_isolated_runtime_on_each_node(self):
        pods = [rwx.pod(i) for i in range(1, 4)]
        self.assertEqual({p['spec']['nodeName'] for p in pods},
                         {'hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3'})
        for p in pods:
            self.assertEqual(p['metadata']['namespace'], 'hetero-dev-rwx-check')
            self.assertEqual(p['spec']['runtimeClassName'], 'gvisor')
            self.assertFalse(p['spec']['automountServiceAccountToken'])
            self.assertTrue(p['spec']['securityContext']['runAsNonRoot'])
            self.assertEqual(p['spec']['activeDeadlineSeconds'], 900)
            c = p['spec']['containers'][0]
            self.assertIn('@sha256:', c['image'])
            self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
            self.assertEqual(c['volumeMounts'], [{'name': 'shared', 'mountPath': '/shared'}])
            self.assertEqual(p['spec']['volumes'], [{'name': 'shared',
                              'persistentVolumeClaim': {'claimName': 'shared'}}])


if __name__ == '__main__':
    unittest.main()
