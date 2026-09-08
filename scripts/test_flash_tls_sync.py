#!/usr/bin/env python3
"""Local root-only filesystem tests. No Kubernetes or host gateway changes."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "deploy/gitops/flash-web/tls-sync.py"
spec = importlib.util.spec_from_file_location("tls_sync", SOURCE)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


@unittest.skipUnless(os.geteuid() == 0, "run with sudo for root-ownership checks")
class SyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = Path(tempfile.mkdtemp(prefix="flash-tls-test-", dir="/run"))
        cls.pairs = []
        for index, hostname in enumerate((sync.HOST, sync.HOST, "wrong.example")):
            key, cert = cls.workspace / f"key{index}", cls.workspace / f"cert{index}"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec",
                            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                            "-subj", "/CN=test", "-addext", f"subjectAltName=DNS:{hostname}",
                            "-keyout", str(key), "-out", str(cert)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cls.pairs.append((cert.read_bytes(), key.read_bytes()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workspace)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.workspace))
        self.host = self.work / "host"
        self.host.mkdir(mode=0o755)
        self.secret = self.work / "secret"
        self.secret.mkdir()
        self.group = self.work / "group"
        self.group.write_text("root:x:0:\nheteronetwork-gateway:x:12345:\n")
        self.extra = self.host / sync.EXTRA
        self.original = b"# preserve exact bytes\r\n(heterocloud_envoy) {\n respond ok\n}\n# EOF"
        self.extra.write_bytes(self.original)
        self.extra.chmod(0o644)
        self.project(self.pairs[0])

    def tearDown(self):
        shutil.rmtree(self.work)

    def project(self, pair):
        generation = Path(tempfile.mkdtemp(prefix="..gen-", dir=self.secret))
        (generation / "tls.crt").write_bytes(pair[0])
        (generation / "tls.key").write_bytes(pair[1])
        temporary = self.secret / "..next"
        temporary.symlink_to(generation.name)
        temporary.replace(self.secret / "..data")

    def run_sync(self):
        return sync.sync(str(self.host), str(self.secret), str(self.group))

    def assert_rejected(self):
        before = self.extra.read_bytes() if self.extra.exists() else None
        with self.assertRaises((ValueError, OSError)):
            self.run_sync()
        if before is not None:
            self.assertEqual(self.extra.read_bytes(), before)

    def test_publish_idempotence_rotation_and_permissions(self):
        self.assertTrue(self.run_sync())
        first = self.extra.read_bytes()
        self.assertTrue(first.startswith(self.original + b"\n"))
        self.assertIn(b"http://*.flash.heterocloud.mizuame.app:80", first)
        self.assertIn(b"https://*.flash.heterocloud.mizuame.app:443", first)
        self.assertIn(b"import heterocloud_envoy /api/v1/health/live heterocloud.mizuame.app", first)
        inode = self.extra.stat().st_ino
        self.assertFalse(self.run_sync())
        self.assertEqual(self.extra.stat().st_ino, inode)
        # Preserve additions after the managed block as well as the initial bytes.
        self.extra.write_bytes(first + b"# another operator's tail\n")
        self.project(self.pairs[1])
        self.assertTrue(self.run_sync())
        second = self.extra.read_bytes()
        self.assertNotEqual(first, second)
        self.assertTrue(second.startswith(self.original + b"\n"))
        self.assertTrue(second.endswith(b"# another operator's tail\n"))
        self.assertEqual(second.count(sync.BEGIN), 1)
        certdir = self.host / sync.CERTDIR
        self.assertEqual(len(list(certdir.iterdir())), 2)
        for path in (certdir, *certdir.glob("*"), *certdir.glob("*/*")):
            self.assertEqual(path.stat().st_uid, 0)
            self.assertEqual(path.stat().st_gid, 12345)
            self.assertEqual(path.stat().st_mode & 0o777, 0o750 if path.is_dir() else 0o640)

    def test_bad_key_and_hostname_and_pem(self):
        self.run_sync()
        for pair in ((self.pairs[0][0], self.pairs[1][1]), self.pairs[2],
                     (b"invalid cert", self.pairs[0][1]), (self.pairs[0][0], b"invalid key")):
            self.project(pair)
            self.assert_rejected()

    def test_expired_and_not_yet_valid(self):
        now = sync.time.time()
        for when in (now + 3 * 86400, now - 86400, now + 2 * 86400 - 1800):
            with mock.patch.object(sync.time, "time", return_value=when):
                self.assert_rejected()

    def test_missing_symlink_hardlink_and_nonroot_extra(self):
        self.extra.unlink()
        self.assert_rejected()
        self.assertFalse(self.extra.exists())
        target = self.host / "target"
        target.write_bytes(self.original)
        self.extra.symlink_to(target)
        self.assert_rejected()
        self.extra.unlink()
        os.link(target, self.extra)
        self.assert_rejected()
        self.extra.unlink()
        self.extra.write_bytes(self.original)
        os.chown(self.extra, 1000, 1000)
        self.assert_rejected()

    def test_writable_extra_and_parent(self):
        self.extra.chmod(0o664)
        self.assert_rejected()
        self.extra.chmod(0o644)
        self.host.chmod(0o777)
        self.assert_rejected()

    def test_missing_snippet_conflict_and_broken_markers(self):
        for content in (b"# empty", self.original + sync.BEGIN,
                        self.original + sync.END + sync.BEGIN,
                        self.original + b"\nhttp://" + sync.HOST.encode() + b" {}\n"):
            self.extra.write_bytes(content)
            self.assert_rejected()

    def test_existing_generation_tampering_and_symlink(self):
        self.run_sync()
        key = next((self.host / sync.CERTDIR).glob("*/tls.key"))
        key.chmod(0o644)
        self.assert_rejected()
        key.chmod(0o640)
        key.unlink()
        key.symlink_to(self.group)
        self.assert_rejected()

    def test_missing_group(self):
        self.group.write_text("root:x:0:\n")
        self.assert_rejected()

    def test_nontraversable_parent(self):
        self.host.chmod(0o700)
        self.assert_rejected()

    def test_symlinked_certificate_directory(self):
        (self.host / sync.CERTDIR).symlink_to(self.work)
        self.assert_rejected()

    def test_failed_extra_rename_retains_original_and_pair(self):
        with mock.patch.object(sync.os, "replace", side_effect=OSError("simulated I/O error")):
            self.assert_rejected()
        self.assertEqual(list(self.host.glob(".flash-extra-*")), [])
        self.assertEqual(len(list((self.host / sync.CERTDIR).glob("*/tls.key"))), 1)
        self.assertTrue(self.run_sync())

    def test_failed_pair_write_never_publishes_extra(self):
        original_write = sync.write_new
        def failed_write(parent, name, data, gid, mode):
            if name == "tls.key":
                raise OSError("simulated disk full")
            original_write(parent, name, data, gid, mode)
        with mock.patch.object(sync, "write_new", side_effect=failed_write):
            self.assert_rejected()
        self.assertEqual(list((self.host / sync.CERTDIR).iterdir()), [])
        self.assertTrue(self.run_sync())

    def test_projected_secret_generation_is_paired(self):
        original_read = sync.read_file
        def rotating_read(parent, name, trusted=True):
            result = original_read(parent, name, trusted)
            if name == "tls.crt" and not trusted:
                self.project(self.pairs[1])
            return result
        with mock.patch.object(sync, "read_file", side_effect=rotating_read):
            self.assertEqual(sync.secret_pair(self.secret), self.pairs[0])

    def test_concurrent_edit_is_not_overwritten(self):
        original_write = sync.write_new
        changed = self.original + b"\n# concurrent edit\n"
        def concurrent_write(parent, name, data, gid, mode):
            original_write(parent, name, data, gid, mode)
            if name.startswith(".flash-extra-"):
                self.extra.write_bytes(changed)
        with mock.patch.object(sync, "write_new", side_effect=concurrent_write):
            with self.assertRaises(ValueError):
                self.run_sync()
        self.assertEqual(self.extra.read_bytes(), changed)
        self.assertEqual(list(self.host.glob(".flash-extra-*")), [])


if __name__ == "__main__":
    unittest.main()
