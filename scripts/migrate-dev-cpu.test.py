import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('cpu_migration', Path(__file__).with_name('migrate-dev-cpu.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CpuMigration(unittest.TestCase):
    def setUp(self):
        self.p = m.dev.profile()
        self.name = 'hetero-dev-2'
        self.uuid = m.dev.identity(self.p, 'domain', self.name)
        root = ET.fromstring(m.dev.domain_xml(self.p, self.name))
        root.remove(root.find('cpu'))
        root.append(ET.fromstring('<cpu mode="custom" match="exact" check="none"><model fallback="forbid">qemu64</model></cpu>'))
        self.original = ET.tostring(root, encoding='unicode')

    def test_changes_only_cpu_and_is_idempotent(self):
        result = m.change_cpu(self.original, self.name, self.uuid)
        self.assertEqual(m.without_cpu(result), m.without_cpu(self.original))
        self.assertEqual(ET.fromstring(result).find('cpu').attrib, {'mode': 'host-model', 'check': 'full'})
        self.assertEqual(m.change_cpu(result, self.name, self.uuid), result)

    def test_rejects_wrong_identity_or_unreviewed_cpu(self):
        for original, name, uuid in [(self.original, 'production', self.uuid),
                                     (self.original, self.name, 'different'),
                                     (self.original.replace('qemu64', 'Skylake-Client'), self.name, self.uuid),
                                     (self.original.replace('check="none"', 'check="full"'), self.name, self.uuid)]:
            with self.assertRaises(ValueError):
                m.change_cpu(original, name, uuid)


if __name__ == '__main__':
    unittest.main()
