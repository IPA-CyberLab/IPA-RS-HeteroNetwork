import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('etcd_source', ROOT / 'control_plane_dr_etcd_source.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EtcdSourceTests(unittest.TestCase):
    def test_mount_selection_uses_most_specific_mount(self):
        entries = 'root / tmpfs rw 0 0\nnone /secure tmpfs rw,noswap 0 0\n'
        self.assertEqual(module.mounts_for('/secure/recovery', entries), ('tmpfs', {'rw', 'noswap'}))

    def test_refuses_plaintext_disk_and_swappable_tmpfs(self):
        with tempfile.TemporaryDirectory() as path:
            fake_mount = f'device {path} ext4 rw 0 0\n'
            with self.assertRaisesRegex(ValueError, 'tmpfs'):
                module.check_tmpfs(path, 1, mounts=fake_mount)
            fake_mount = f'tmpfs {path} tmpfs rw 0 0\n'
            with self.assertRaisesRegex(ValueError, 'noswap'):
                module.check_tmpfs(path, 1, mounts=fake_mount)

    def test_obscured_noswap_mount_does_not_override_visible_mount(self):
        with tempfile.TemporaryDirectory() as path:
            mounts = f'tmpfs {path} tmpfs rw,noswap 0 0\ntmpfs {path} tmpfs rw 0 0\n'
            with self.assertRaisesRegex(ValueError, 'noswap'):
                module.check_tmpfs(path, 1, mounts=mounts)

    def test_noswap_mount_is_accepted(self):
        with tempfile.TemporaryDirectory() as path:
            fake_mount = f'tmpfs {path} tmpfs rw,noswap 0 0\n'
            module.check_tmpfs(path, 1, mounts=fake_mount)

    def test_changed_cluster_is_rejected_before_streaming(self):
        config = {'etcdctl': '/bin/true', 'etcdutl': '/bin/true', 'endpoint': 'https://127.0.0.1:2379',
                  'ca': '/ca', 'cert': '/cert', 'key': '/key', 'tmp_dir': '/dev/shm',
                  'max_snapshot_bytes': 1024 * 1024}
        source = module.Source(config)
        with tempfile.TemporaryDirectory() as temporary:
            fake_snapshot = Path(temporary) / 'snapshot.db'
            fake_snapshot.write_bytes(b'fixture')
            class Directory:
                def __enter__(self): return temporary
                def __exit__(self, *_): return False
            status = mock.Mock(side_effect=[(1, 10), (2, 11)])
            with mock.patch.object(module, 'check_tmpfs'), mock.patch.object(source, 'status', status), \
                 mock.patch.object(module.tempfile, 'TemporaryDirectory', return_value=Directory()), \
                 mock.patch.object(module.subprocess, 'run', side_effect=[
                     mock.Mock(returncode=0), mock.Mock(returncode=0, stdout=b'{"revision":10}')]):
                with self.assertRaisesRegex(RuntimeError, 'cluster identity'):
                    source.backup()


if __name__ == '__main__':
    unittest.main()
