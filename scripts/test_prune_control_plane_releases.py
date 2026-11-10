import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("release_cleanup", Path(__file__).with_name("prune-control-plane-releases.py"))
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class ReleaseCleanupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = time.time()
        self.active = hashlib.sha256(b"active").hexdigest()
        self.make_release(self.active, b"active")
        self.untrusted = set()
        original_lstat = Path.lstat

        def fixture_lstat(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if path.is_relative_to(self.root):
                fields = list(info)
                fields[4] = 1234 if path in self.untrusted else 0
                return os.stat_result(fields)
            return info

        self.stat_patch = mock.patch.object(Path, "lstat", fixture_lstat)
        self.stat_patch.start()
        self.addCleanup(self.stat_patch.stop)

    def tearDown(self):
        self.temp.cleanup()

    def make_release(self, name, content=b"old", age=90000):
        path = self.root / name
        path.mkdir()
        (path / "iparsd").write_bytes(content)
        os.utime(path, (self.now - age, self.now - age))
        return path

    def test_only_old_unreferenced_releases_are_selected(self):
        old, referenced, recent = "a" * 64, "b" * 64, "c" * 64
        self.make_release(old)
        self.make_release(referenced)
        self.make_release(recent, age=30)
        self.assertEqual(cleanup.candidates(self.root, self.active, {referenced}, self.now), [old])

    def test_unknown_contents_and_symlinks_are_preserved(self):
        extra = self.make_release("a" * 64)
        (extra / "metadata").write_text("keep")
        (self.root / ("b" * 64)).symlink_to(extra, target_is_directory=True)
        self.assertEqual(cleanup.candidates(self.root, self.active, set(), self.now), [])

    def test_wrong_pinned_digest_fails_closed(self):
        (self.root / self.active / "iparsd").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            cleanup.candidates(self.root, self.active, set(), self.now)

    def test_unprotected_root_fails_closed(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            cleanup.candidates(self.root, self.active, set(), self.now)

    def test_non_root_owned_release_is_preserved(self):
        old = self.make_release("a" * 64)
        self.untrusted.add(old)
        self.assertEqual(cleanup.candidates(self.root, self.active, set(), self.now), [])

    def test_only_old_regular_unreferenced_backup_is_selected(self):
        old = "iparsd.1.2026-10-27@12:00:00~"
        protected = "iparsd.2.2026-10-27@12:00:00~"
        recent = "iparsd.3.2026-10-27@12:00:00~"
        for name in (old, protected, recent):
            path = self.root / name
            path.write_bytes(b"old binary")
            if name != recent:
                os.utime(path, (self.now - 90000, self.now - 90000))
        (self.root / "iparsd.4.2026-10-27@12:00:00~").symlink_to(self.root / old)
        (self.root / "iparsd.5.invalid~").write_bytes(b"unknown format")
        self.assertEqual(cleanup.backup_candidates(self.root, {protected}, self.now), [old])

    def test_backup_referenced_by_local_symlink_is_protected(self):
        name = "iparsd.1.2026-10-27@12:00:00~"
        (self.root / name).write_bytes(b"old binary")
        (self.root / "iparsd-current").symlink_to(self.root / name)
        self.assertIn(name, cleanup.backup_references(self.root, unit_roots=(), process_root=self.root))

    def test_backup_referenced_by_process_or_service_is_protected(self):
        unit_name = "iparsd.1.2026-10-27@12:00:00~"
        process_name = "iparsd.2.2026-10-27@12:00:00~"
        for name in (unit_name, process_name):
            (self.root / name).write_bytes(b"old binary")
        units = self.root / "units"
        units.mkdir()
        (units / "example.service").write_text(f"ExecStart={self.root / unit_name}\n")
        processes = self.root / "processes"
        process = processes / "123"
        (process / "fd").mkdir(parents=True)
        (process / "exe").symlink_to(self.root / process_name)
        (process / "cmdline").write_bytes(b"running\0")
        protected = cleanup.backup_references(self.root, unit_roots=(units,), process_root=processes)
        self.assertEqual(protected, {unit_name, process_name})


if __name__ == "__main__":
    unittest.main()
