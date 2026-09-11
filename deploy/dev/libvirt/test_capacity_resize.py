import unittest
import uuid
import xml.etree.ElementTree as ET

import capacity_resize as capacity


class ResizeTests(unittest.TestCase):
    def original(self):
        name = 'hetero-dev-1'
        ident = uuid.uuid5(uuid.NAMESPACE_URL, f'urn:heteronetwork:dev:ichikawap1:domain:{name}')
        return (f'<domain type="kvm"><name>{name}</name><uuid>{ident}</uuid>'
                '<memory unit="KiB">8388608</memory><currentMemory unit="KiB">8388608</currentMemory>'
                '<vcpu placement="static">4</vcpu><cpu mode="host-model" check="full"/>'
                '<devices><disk type="file"><source file="/preserved.qcow2"/></disk></devices></domain>')

    def test_only_capacity_changes_and_repeat_is_stable(self):
        before = self.original()
        after = capacity.requested_xml(before, 'hetero-dev-1')
        self.assertEqual(capacity.without_capacity(before), capacity.without_capacity(after))
        self.assertEqual(ET.fromstring(after).findtext('vcpu'), '8')
        self.assertEqual(ET.fromstring(after).findtext('memory'), '10485760')
        self.assertEqual(capacity.requested_xml(after, 'hetero-dev-1'), after)

    def test_mixed_and_foreign_state_refused(self):
        for text, name in ((self.original().replace('>4<', '>8<'), 'hetero-dev-1'),
                           (self.original(), 'vercel-research'),
                           (self.original().replace('<devices>', '<maxMemory/><devices>'), 'hetero-dev-1')):
            with self.assertRaises(ValueError):
                capacity.requested_xml(text, name)

    def test_other_vm_and_host_reserve_are_counted(self):
        result = capacity.static_budget(82061076, 104, 16777216, 16)
        self.assertEqual(result['with_host_reserve_kib'], 73400320)
        self.assertEqual(result['total_vm_vcpus'], 40)
        self.assertTrue(result['static_totals_fit'])
        self.assertFalse(result['runtime_changed'])
        self.assertFalse(capacity.static_budget(73400319, 104, 16777216, 16)['static_totals_fit'])


if __name__ == '__main__':
    unittest.main()
