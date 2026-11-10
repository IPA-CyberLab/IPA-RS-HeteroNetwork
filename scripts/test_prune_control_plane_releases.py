import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest


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


if __name__ == "__main__":
    unittest.main()
