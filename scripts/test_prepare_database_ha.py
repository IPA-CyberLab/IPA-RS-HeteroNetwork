#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "prepare_database_ha", HERE / "prepare-database-ha.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class DatabaseHaPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="database-ha-test-"))
        self.key = self.temp / "id_ed25519"
        self.key.write_text("inert test key\n")
        self.key.chmod(0o600)
        self.work = self.temp / "work"

    def tearDown(self):
        shutil.rmtree(self.temp)

    def test_renders_recovered_members_and_dcs_voter_privately(self):
        result = PREPARE.prepare(self.work, self.key)
        self.assertEqual(result, {
            "result": "prepared",
            "postgres_members": ["uc-k8sp4", "uc-k8sp5"],
            "postgres_dcs_only": ["uc-k8sp2"],
        })
        inventory = json.loads((self.work / "inventory.json").read_text())
        groups = inventory["all"]["children"]
        self.assertEqual(groups["postgres_members"]["hosts"]["uc-k8sp5"]["postgres_name"], "db-b")
        self.assertEqual(groups["postgres_members"]["hosts"]["uc-k8sp4"]["postgres_name"], "db-e")
        self.assertEqual(groups["postgres_dcs_only"]["hosts"]["uc-k8sp2"]["postgres_name"], "db-g")
        for name in ("inventory.json", "known_hosts"):
            self.assertEqual((self.work / name).stat().st_mode & 0o777, 0o600)

    def test_rejects_broad_ssh_key_permissions_before_staging(self):
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            PREPARE.prepare(self.work, self.key)
        self.assertFalse(self.work.exists())


if __name__ == "__main__":
    unittest.main()
