#!/usr/bin/env python3
"""Offline tests only: no hypervisor, SSH or storage mutation."""
import copy
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('expansion', Path(__file__).with_name('expand-dev-storage.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class CapacityTests(unittest.TestCase):
    def test_observed_budget_and_boundary(self):
        roots = [7176564736, 7158185984, 7196143616, 5994098688]
        r = app.capacity(514584236032, roots, [])
        self.assertEqual(r['required_bytes'], 493239791616)
        self.assertEqual(r['remaining_growth_bytes'], 144273698816)
        self.assertTrue(r['admitted'])
        self.assertTrue(app.capacity(r['required_bytes'], roots, [])['admitted'])
        self.assertFalse(app.capacity(r['required_bytes'] - 1, roots, [])['admitted'])

    def test_completed_not_double_counted(self):
        roots = [7 * app.GIB] * 4
        before = app.capacity(500 * app.GIB, roots, [])
        after = app.capacity(436 * app.GIB, roots, [64 * app.GIB])
        self.assertEqual(before['available_bytes'] - before['required_bytes'],
                         after['available_bytes'] - after['required_bytes'])
        self.assertEqual(app.capacity(500 * app.GIB, roots, [60 * app.GIB])['required_bytes'],
                         after['required_bytes'] + 4 * app.GIB)

    def test_overallocated_metadata_never_negative_growth(self):
        r = app.capacity(133 * app.GIB, [41 * app.GIB] * 4, [65 * app.GIB] * 3)
        self.assertEqual(r['remaining_growth_bytes'], 0)
        self.assertEqual(r['required_bytes'], 133 * app.GIB)

    def test_missing_vercel_or_invalid_counts(self):
        for roots, apps in [([0] * 3, []), ([0] * 4, [0] * 4), ([-1] * 4, [])]:
            with self.assertRaises(app.dev.Refusal):
                app.capacity(500 * app.GIB, roots, apps)


class XMLTests(unittest.TestCase):
    def setUp(self):
        self.p = app.dev.profile()
        self.name = self.p['vms'][0]
        root = ET.fromstring(app.dev.domain_xml(self.p, self.name))
        ET.SubElement(root.find('devices'), 'controller', type='pci', index='0', model='pci-root')
        self.before = ET.tostring(root, encoding='unicode')

    def addition(self):
        root = ET.fromstring(self.before)
        root.find('devices').append(ET.fromstring(app.disk_xml(self.before, self.p, self.name)))
        return root

    def test_exact_addition_and_normalization(self):
        root = self.addition()
        d = root.findall('devices/disk')[-1]
        ET.SubElement(d, 'alias', name='virtio-disk1')
        ET.SubElement(d, 'backingStore')
        d.find('source').set('index', '3')
        ET.indent(root)
        app.verify_addition(self.before, ET.tostring(root, encoding='unicode'), self.p, self.name)
        self.assertEqual(d.findtext('serial'), 'hnapp-' + app.dev.identity(
            self.p, 'domain', self.name).replace('-', '')[:12])
        self.assertEqual(d.find('source').get('file'), str(app.disk_path(self.p, self.name)))

    def test_foreign_mapping_and_other_changes_refused(self):
        for xpath, attribute, value in [('devices/disk[last()]/source', 'file', '/foreign.qcow2'),
                                         ('devices/disk[last()]/source', 'index', 'invalid'),
                                         ('devices/disk[last()]/source', 'unknown', '3'),
                                         ('devices/disk[last()]/driver', 'type', 'raw'),
                                         ('devices/disk[last()]/target', 'bus', 'sata'),
                                         ('devices/controller', 'model', 'pcie-root')]:
            root = self.addition()
            root.find(xpath).set(attribute, value)
            with self.assertRaises(app.dev.Refusal):
                app.verify_addition(self.before, ET.tostring(root, encoding='unicode'), self.p, self.name)

    def test_duplicate_or_occupied_target_refused(self):
        root = self.addition()
        after = ET.tostring(root, encoding='unicode')
        with self.assertRaises(app.dev.Refusal):
            app.disk_xml(after, self.p, self.name)
        root.find('devices').append(copy.deepcopy(root.findall('devices/disk')[-1]))
        with self.assertRaises(app.dev.Refusal):
            app.verify_addition(self.before, ET.tostring(root, encoding='unicode'), self.p, self.name)

    def test_wrong_uuid_missing_or_ambiguous_controller(self):
        for mode in ('uuid', 'missing', 'duplicate'):
            root = ET.fromstring(self.before)
            controller = root.find('devices/controller')
            if mode == 'uuid':
                root.find('uuid').text = 'foreign'
            elif mode == 'missing':
                root.find('devices').remove(controller)
            else:
                root.find('devices').append(copy.deepcopy(controller))
            with self.assertRaises(app.dev.Refusal):
                app.disk_xml(ET.tostring(root, encoding='unicode'), self.p, self.name)

    def test_existing_pcie_port_only(self):
        root = ET.fromstring(self.before)
        root.find('devices/controller').set('model', 'pcie-root')
        ET.SubElement(root.find('devices'), 'controller', type='pci', index='1', model='pcie-root-port')
        d = ET.fromstring(app.disk_xml(ET.tostring(root, encoding='unicode'), self.p, self.name))
        self.assertEqual(d.find('address').get('bus'), '0x1')
        ET.SubElement(root.find('devices/disk'), 'address', type='pci', bus='0x1', slot='0x0')
        with self.assertRaises(app.dev.Refusal):
            app.disk_xml(ET.tostring(root, encoding='unicode'), self.p, self.name)


class RefusalTests(unittest.TestCase):
    def setUp(self):
        self.p = app.dev.profile()

    def test_partial_foreign_or_missing_file_record(self):
        for records in ({'foreign': {}}, {'hetero-dev-1': {'completed': False}},
                        {'hetero-dev-1': {'completed': True, 'path': str(app.disk_path(self.p, 'hetero-dev-1')),
                                          'serial': app.serial(self.p, 'hetero-dev-1'), 'size_bytes': 64 * app.GIB}}):
            with self.assertRaises(app.dev.Refusal):
                app.completed_records(self.p, {'app_storage': records, 'files': {}})

    def test_unknown_domain_refused_before_disk_inspection(self):
        with patch.object(app, 'virsh', return_value=' '.join(app.GUESTS + [app.OTHER, 'foreign'])):
            with self.assertRaises(app.dev.Refusal):
                app.inventory(self.p, {'files': {}})

    def test_incomplete_resources_refused_before_commands(self):
        with patch.object(app.dev, 'run', side_effect=AssertionError('Must not execute')):
            with self.assertRaises(app.dev.Refusal):
                app.prerequisites(self.p, {'ready': True, 'resources': {}})

    def test_backing_snapshots_wrong_size_refused(self):
        for extra in ({'backing-filename': '/foreign'}, {'snapshots': [{}]},
                      {'virtual-size': 40 * app.GIB}, {'data-file': '/foreign'}):
            value = {'format': 'qcow2', 'virtual-size': 64 * app.GIB, **extra}
            with patch.object(app.dev, 'validate_base_header'), patch.object(app.dev, 'decode', return_value=value), \
                    patch.object(app.dev, 'run', return_value='{}'):
                with self.assertRaises(app.dev.Refusal):
                    app.image_info(Path('/not-read'), 64 * app.GIB)


class PoolFileTests(unittest.TestCase):
    def setUp(self):
        self.p = app.dev.profile()
        self.record = {'mutable': False, 'sha256': 'a' * 64, 'inode': [42, 99]}

    def check_file(self, pool, filename, record):
        path = Path('/not-read') / filename
        value = {'files': {} if record is None else {str(path): record}}
        with patch.object(app, 'file_info') as info, \
                patch.object(app.dev, 'inode', return_value=[42, 99]), \
                patch.object(app.dev, 'digest_file', return_value='a' * 64) as digest, \
                patch.object(app.dev, 'validate_base_header'), \
                patch.object(app.dev, 'run', return_value='{"virtual-size": 123}'), \
                patch.object(app, 'image_info') as image:
            app.pool_file(self.p, value, pool, path, 42, set())
            info.assert_called_once_with(path, 42, set())
            return digest.call_count, image.call_count

    def test_exact_three_owned_backup_seeds(self):
        for name in app.GUESTS:
            self.assertEqual(self.check_file(self.p['name'], name + '-seed.iso.before-schema-repair',
                                             self.record), (1, 0))

    def test_exact_pool_specific_bases(self):
        self.assertEqual(self.check_file(self.p['name'], 'ubuntu-base.img', self.record), (1, 1))
        self.assertEqual(self.check_file(app.OTHER, 'ubuntu-24.04-server-cloudimg-amd64.img', None), (0, 1))
        self.assertEqual(self.check_file(app.OTHER, 'ubuntu-24.04-server-cloudimg-amd64.img', self.record), (1, 1))

    def test_missing_mutable_replaced_or_changed_backup_refused(self):
        for record in (None, {**self.record, 'mutable': True}, {**self.record, 'inode': [42, 100]},
                       {**self.record, 'sha256': 'b' * 64}):
            with self.assertRaises(app.dev.Refusal):
                self.check_file(self.p['name'], app.GUESTS[0] + '-seed.iso.before-schema-repair', record)

    def test_similar_names_wrong_pool_and_unowned_dev_base_refused(self):
        for pool, name in ((app.OTHER, 'ubuntu-base.img'), (self.p['name'], 'ubuntu-24.04-server-cloudimg-amd64.img'),
                           (app.OTHER, app.GUESTS[0] + '-seed.iso.before-schema-repair'),
                           (self.p['name'], 'hetero-dev-4-seed.iso.before-schema-repair'),
                           (self.p['name'], app.GUESTS[0] + '-seed.iso.before-schema-repair.extra'),
                           (self.p['name'], 'ubuntu-base.img')):
            with self.assertRaises(app.dev.Refusal):
                self.check_file(pool, name, None)

    def test_file_type_same_filesystem_and_distinctness(self):
        path = Path('/not-read')
        valid = dict(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=42, st_ino=99, st_blocks=8)
        for changes in ({'st_mode': stat.S_IFDIR | 0o700}, {'st_dev': 43}, {'st_nlink': 2}):
            with patch.object(app.dev, 'checked_path', return_value=path), \
                    patch.object(Path, 'stat', return_value=SimpleNamespace(**{**valid, **changes})):
                with self.assertRaises(app.dev.Refusal):
                    app.file_info(path, 42, set())
        with patch.object(app.dev, 'checked_path', return_value=path), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(**valid)):
            seen = set()
            self.assertEqual(app.file_info(path, 42, seen), 4096)
            with self.assertRaises(app.dev.Refusal):
                app.file_info(path, 42, seen)


class InventoryDirectoryTests(unittest.TestCase):
    def test_unrelated_owner_is_only_root_or_libvirt(self):
        path = Path('/var/lib/libvirt/images/vercel-research/cloud-init')
        for owner, mode, accepted in ((0, 0o700, True), (64055, 0o750, True),
                                      (1000, 0o700, False), (64055, 0o770, False)):
            with patch.object(app.dev, 'root_directory', return_value=99), \
                    patch.object(app.os, 'close'), \
                    patch.object(app.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=64055)), \
                    patch.object(Path, 'lstat', return_value=SimpleNamespace(
                        st_uid=owner, st_mode=stat.S_IFDIR | mode)):
                if accepted:
                    app.inventory_directory(path, other=True)
                else:
                    with self.assertRaises(app.dev.Refusal):
                        app.inventory_directory(path, other=True)

    def test_other_directory_name_is_not_allowed(self):
        with patch.object(app.dev, 'root_directory', side_effect=AssertionError('No access')):
            with self.assertRaises(app.dev.Refusal):
                app.inventory_directory(Path('/var/lib/libvirt/images/foreign'), other=True)


class PreallocationTests(unittest.TestCase):
    def test_falloc_on_ext4_and_block_boundary(self):
        path = Path('/not-read/apps.qcow2')
        for blocks in (64 * app.GIB // 512, 64 * app.GIB // 512 - 1):
            with patch.object(app.dev, 'run', return_value='{"filesystems": [{"fstype": "ext4"}]}') as run, \
                    patch.object(app, 'image_info') as image, \
                    patch.object(Path, 'stat', return_value=SimpleNamespace(st_blocks=blocks)):
                if blocks * 512 < 64 * app.GIB:
                    with self.assertRaises(app.dev.Refusal):
                        app.preallocate(path)
                else:
                    app.preallocate(path)
                self.assertEqual(run.call_args_list[0].args[0],
                                 ['findmnt', '--json', '--target', str(path.parent), '--output', 'FSTYPE'])
                run.assert_called_with(['qemu-img', 'create', '-f', 'qcow2', '-o', 'preallocation=falloc',
                                        str(path), '64G'], timeout=900)
                image.assert_called_once_with(path, 64 * app.GIB)

    def test_non_ext4_never_allocates(self):
        with patch.object(app.dev, 'run', return_value='{"filesystems": [{"fstype": "xfs"}]}') as run:
            with self.assertRaises(app.dev.Refusal):
                app.preallocate(Path('/not-read/apps.qcow2'))
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
