import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('verify-flash-provider.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProviderFixture(unittest.TestCase):
    def test_bounded_private_service(self):
        value = probe.workload()
        self.assertEqual(value['exposure'], {'type': 'internal', 'traffic_mode': 'forwarded'})
        self.assertEqual(value['egress'], {'mode': 'disabled'})
        self.assertEqual(value['ports'], [])
        self.assertEqual(value['replicas'], 1)
        self.assertEqual(value['cpu_millis'], 100)
        self.assertEqual(value['memory_mib'], 128)
        self.assertEqual(value['ephemeral_storage_gib'], 2)
        self.assertIn('@sha256:', value['image'])
        self.assertIn('Starting gVisor', value['args'][0])

    def test_urlsafe_encoding_has_no_padding(self):
        self.assertEqual(probe.encoded(b'\xfb\xff'), b'-_8')


if __name__ == '__main__':
    unittest.main()
