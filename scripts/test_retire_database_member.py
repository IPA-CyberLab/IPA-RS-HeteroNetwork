import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import yaml


SCRIPT = Path(__file__).with_name("retire_database_member.py")
SPEC = importlib.util.spec_from_file_location("retire_database_member", SCRIPT)
retire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retire)


class DatabaseRetirementTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"a": "192.0.2.1", "b": "192.0.2.2"}
        self.voters = [
            {"ID": 1, "name": "a", "peerURLs": ["https://192.0.2.1:12380"]},
            {"ID": 2, "name": "b", "peerURLs": ["https://192.0.2.2:12380"]},
        ]

    def test_exact_membership_and_ids_are_required(self):
        self.assertEqual(retire.snapshot_members(self.voters, self.expected)["a"][1], "1")
        for mutation in (
            self.voters[:1],
            [self.voters[0], {**self.voters[1], "peerURLs": ["https://192.0.2.3:12380"]}],
            [self.voters[0], {**self.voters[1], "isLearner": True}],
            self.voters + [self.voters[0]],
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                retire.snapshot_members(mutation, self.expected)

    def test_configuration_removes_only_the_retired_member_and_is_idempotent(self):
        state = {"target": "db-e", "address": "192.0.2.2",
                 "old_dcs": {"db-b": "192.0.2.1", "db-e": "192.0.2.2", "db-h": "192.0.2.3"},
                 "survivors": {"db-b": "192.0.2.1", "db-h": "192.0.2.3"}}
        patroni = ("etcd3:\n  hosts:\n    - 192.0.2.1:12379\n    - 192.0.2.2:12379\n"
                   "    - 192.0.2.3:12379\npostgresql:\n  listen: 127.0.0.1:5432\n")
        etcd = "name: db-b\ninitial-cluster: db-b=https://192.0.2.1:12380,db-e=https://192.0.2.2:12380,db-h=https://192.0.2.3:12380\n"
        proxy = ("backend database\n  server db-b 192.0.2.1:55432 check\n"
                 "  server db-e 192.0.2.2:55432 check\n  server db-h 192.0.2.3:55432 check\n"
                 "backend health\n  server health-db-e 192.0.2.2:18008 check\n")
        result = retire.render_local_configs(patroni, etcd, proxy, state)
        self.assertEqual(yaml.safe_load(result[0])["etcd3"]["hosts"], ["192.0.2.1:12379", "192.0.2.3:12379"])
        self.assertEqual(yaml.safe_load(result[0])["postgresql"]["listen"], "127.0.0.1:5432")
        self.assertNotIn("192.0.2.2", result[1] + result[2])
        self.assertEqual(retire.render_local_configs(*result, state), result)
        with self.assertRaises(ValueError):
            retire.render_local_configs(patroni, etcd, proxy.replace("db-e 192.0.2.2", "db-e 192.0.2.9"), state)

    def test_archive_extraction_preserves_private_directory_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bundle.tar.gz"
            with tarfile.open(archive, "w:gz") as target:
                folder = tarfile.TarInfo("ca")
                folder.type, folder.mode = tarfile.DIRTYPE, 0o700
                target.addfile(folder)
                key = tarfile.TarInfo("ca/key")
                key.mode, key.size = 0o600, 3
                target.addfile(key, io.BytesIO(b"key"))
            out = root / "out"
            out.mkdir(mode=0o700)
            with patch.object(retire.recovery, "archive_digest"):
                retire.extract_protected_archive(archive, out)
            self.assertEqual((out / "ca").stat().st_mode & 0o777, 0o700)
            self.assertEqual((out / "ca/key").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
