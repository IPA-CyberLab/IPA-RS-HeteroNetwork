import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('disk', Path(__file__).with_name('prepare-longhorn-disk.py'))
disk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(disk)


class DiskTests(unittest.TestCase):
    def test_exact_mount_and_capacity(self):
        m = {'target': str(disk.MOUNT), 'source': '/dev/vdb', 'uuid': disk.DISKS['hetero-dev-1'],
             'fstype': 'ext4', 'options': 'rw,nodev,nosuid,relatime'}
        disk.validate_mount('hetero-dev-1', [m], 62 * 1024**3, 60 * 1024**3)
        for key, value in [('target', '/'), ('source', '/dev/vda'), ('uuid', 'foreign'),
                           ('fstype', 'xfs'), ('options', 'rw')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                disk.validate_mount('hetero-dev-1', [{**m, key: value}], 62 * 1024**3, 60 * 1024**3)
        with self.assertRaises(ValueError):
            disk.validate_mount('hetero-dev-1', [m], 62 * 1024**3, disk.RESERVED)

    def test_existing_mapping_rejected_recursively(self):
        disk.no_multipath([{'type': 'disk', 'children': [{'type': 'part'}]}], ['LVM-123'])
        with self.assertRaises(ValueError):
            disk.no_multipath([{'type': 'disk', 'children': [{'type': 'mpath'}]}], [])
        with self.assertRaises(ValueError):
            disk.no_multipath([], ['mpath-123'])


if __name__ == '__main__':
    unittest.main()
