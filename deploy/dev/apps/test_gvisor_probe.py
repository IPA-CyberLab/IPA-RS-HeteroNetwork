import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verify_gvisor', Path(__file__).with_name('verify-gvisor.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RuntimeProbe(unittest.TestCase):
    def test_scoped_tokenless_nonroot_probe(self):
        for number in range(1, 4):
            node = f'hetero-dev-{number}'
            obj = probe.probe(node)
            self.assertEqual(obj['metadata']['namespace'], 'heterocloud-flash-dev')
            self.assertEqual(obj['spec']['nodeName'], node)
            self.assertEqual(obj['spec']['runtimeClassName'], 'hetero-dev-gvisor-probe')
            self.assertIs(obj['spec']['automountServiceAccountToken'], False)
            self.assertEqual(obj['spec']['restartPolicy'], 'Never')
            self.assertEqual(obj['spec']['activeDeadlineSeconds'], 120)
            self.assertEqual(obj['spec']['securityContext']['runAsUser'], 65532)
            container = obj['spec']['containers'][0]
            self.assertIn('@sha256:', container['image'])
            self.assertIn('Starting gVisor', container['command'][2])
            self.assertEqual(container['securityContext']['capabilities'], {'drop': ['ALL']})
            self.assertFalse(obj['spec'].get('hostNetwork', False))
            self.assertNotIn('volumes', obj['spec'])


if __name__ == '__main__':
    unittest.main()
