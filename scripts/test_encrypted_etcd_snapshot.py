import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidTag


spec = importlib.util.spec_from_file_location("encrypted_snapshot", Path(__file__).with_name("encrypted-etcd-snapshot.py"))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class EncryptedSnapshotTests(unittest.TestCase):
    def test_round_trip_and_new_file_restore(self):
        key = bytes(range(32))
        plaintext = (b"secret-database-records\x00" * 100000) + b"last byte"
        expected = hashlib.sha256(plaintext).hexdigest()
        encrypted = io.BytesIO()
        result = snapshot.encrypt(io.BytesIO(plaintext), encrypted, key)
        self.assertEqual(result["plaintext_sha256"], expected)
        self.assertNotIn(b"secret-database-records", encrypted.getvalue())
        self.assertEqual(snapshot.decrypt(io.BytesIO(encrypted.getvalue()), None, key, expected)["plaintext_bytes"], len(plaintext))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "snapshot.db"
            snapshot.restore(io.BytesIO(encrypted.getvalue()), target, key, expected)
            self.assertEqual(target.read_bytes(), plaintext)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                snapshot.restore(io.BytesIO(encrypted.getvalue()), target, key, expected)
            self.assertEqual(target.read_bytes(), plaintext)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_wrong_key_tampering_and_truncation_are_rejected(self):
        key, plaintext = b"a" * 32, b"database payload"
        expected = hashlib.sha256(plaintext).hexdigest()
        encrypted = io.BytesIO()
        snapshot.encrypt(io.BytesIO(plaintext), encrypted, key)
        blob = bytearray(encrypted.getvalue())
        with self.assertRaises(InvalidTag):
            snapshot.decrypt(io.BytesIO(blob), None, b"b" * 32, expected)
        blob[-17] ^= 1
        with self.assertRaises(InvalidTag):
            snapshot.decrypt(io.BytesIO(blob), None, key, expected)
        with self.assertRaises((ValueError, InvalidTag)):
            snapshot.decrypt(io.BytesIO(encrypted.getvalue()[:-12]), None, key, expected)
        with self.assertRaisesRegex(ValueError, "checksum"):
            snapshot.decrypt(io.BytesIO(encrypted.getvalue()), None, key, "0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "snapshot.db"
            with self.assertRaises(InvalidTag):
                snapshot.restore(io.BytesIO(blob), target, key, expected)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_key_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            snapshot.generate_key(key)
            self.assertEqual(len(snapshot.read_key(key)), 32)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                snapshot.generate_key(key)
            alias = Path(directory) / "alias"
            os.symlink(key, alias)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                snapshot.read_key(alias)
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                snapshot.read_key(key)

    def test_cli_encrypts_from_a_pipe_and_verifies_its_output(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            snapshot.generate_key(key)
            payload = b"compressed-stream-fixture" * 300
            encrypted = subprocess.run([sys.executable, str(Path(__file__).with_name("encrypted-etcd-snapshot.py")),
                                        "encrypt", "--key", str(key), "--input", "-"],
                                       input=payload, capture_output=True, check=True)
            verified = subprocess.run([sys.executable, str(Path(__file__).with_name("encrypted-etcd-snapshot.py")),
                                       "verify", "--key", str(key), "--sha256", hashlib.sha256(payload).hexdigest()],
                                      input=encrypted.stdout, capture_output=True, check=True)
            self.assertIn(b'"result": "verified"', verified.stderr)
            self.assertNotIn(payload, encrypted.stdout)


if __name__ == "__main__":
    unittest.main()
