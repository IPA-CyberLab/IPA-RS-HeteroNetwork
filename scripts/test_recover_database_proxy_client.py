import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("recover-database-proxy-client.py")
SPEC = importlib.util.spec_from_file_location("recover_database_proxy_client", SCRIPT)
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class RecoverDatabaseProxyClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "agent.json"
        self.node_id = "node-" + "a" * 64
        self.cluster_id = "cluster-recovery-test"
        self.state.write_text(json.dumps({
            "registered_node": {
                "node_id": self.node_id,
                "cluster_id": self.cluster_id,
            },
        }))
        self.state.chmod(0o600)
        self.bundle_parent = self.root / "postgres-autopilot"
        self.bundle_parent.mkdir(mode=0o700)
        self.bundle = self.bundle_parent / "bundle"
        self.archive = self.root / "proxy-bundle.tar.gz"
        self.retired_archive = self.bundle_parent / "bundle.tar.gz"
        self.retired_archive.write_bytes(b"retired-authority")
        self.retired_archive.chmod(0o600)
        self.backup = self.root / "backup"
        self._write_proxy_archive()

    def tearDown(self):
        self.temporary.cleanup()

    def _manifest(self, identities):
        return (
            "HETERONETWORK_DB_TOPOLOGY_REVISION=7\n"
            "HETERONETWORK_DB_MEMBERS=db-b=100.96.127.54,db-e=100.111.33.52\n"
            f"HETERONETWORK_DB_MEMBER_IDENTITIES={identities}\n"
        ).encode()

    def _write_proxy_archive(self, identities=None):
        identities = identities or (
            "db-b=node-" + "b" * 64 + ",db-e=node-" + "e" * 64
        )
        files = {
            ".proxy-only": (b"1\n", 0o600),
            "manifest.env": (self._manifest(identities), 0o600),
            "cluster-id": ((self.cluster_id + "\n").encode(), 0o600),
            "ca/ca.crt": (
                b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
                0o644,
            ),
            "secrets/application.password": (b"application-password-for-tests\n", 0o600),
        }
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for directory in ("ca", "secrets"):
                entry = tarfile.TarInfo("./" + directory)
                entry.type = tarfile.DIRTYPE
                entry.mode = 0o700
                archive.addfile(entry)
            for name, (data, mode) in files.items():
                entry = tarfile.TarInfo("./" + name)
                entry.size = len(data)
                entry.mode = mode
                archive.addfile(entry, io.BytesIO(data))
        self.archive.chmod(0o600)

    def _write_retired_bundle(self, owner=True):
        self.bundle.mkdir(mode=0o700)
        (self.bundle / "cluster-id").write_text(self.cluster_id + "\n")
        owner_id = self.node_id if owner else "node-" + "c" * 64
        (self.bundle / "manifest.env").write_bytes(self._manifest(
            f"db-a={owner_id},db-b=node-" + "b" * 64
        ))
        authority = self.bundle / "ca"
        authority.mkdir()
        (authority / "ca.key").write_text("retired-private-authority\n")

    def test_demotes_retired_member_transactionally_and_is_idempotent(self):
        self._write_retired_bundle()

        audit = RECOVERY.recover(
            self.bundle, self.archive, self.state, self.backup,
            self.retired_archive, apply=False)
        self.assertEqual("migration-required", audit["result"])
        self.assertEqual("retired-member", audit["mode"])
        self.assertEqual(["db-b", "db-e"], audit["members"])
        self.assertTrue((self.bundle / "ca/ca.key").exists())

        applied = RECOVERY.recover(
            self.bundle, self.archive, self.state, self.backup,
            self.retired_archive, apply=True)
        self.assertEqual("changed", applied["result"])
        self.assertEqual("1", (self.bundle / ".proxy-only").read_text().strip())
        self.assertFalse((self.bundle / "ca/ca.key").exists())
        self.assertTrue((self.backup / "retired-member-bundle/ca/ca.key").exists())
        self.assertTrue((self.backup / "retired-member-bundle.tar.gz").exists())
        self.assertFalse(self.retired_archive.exists())

        repeated = RECOVERY.recover(
            self.bundle, self.archive, self.state, self.backup,
            self.retired_archive, apply=True)
        self.assertEqual("unchanged", repeated["result"])

    def test_refuses_to_replace_a_full_bundle_not_owned_by_this_node(self):
        self._write_retired_bundle(owner=False)

        with self.assertRaises(ValueError):
            RECOVERY.recover(
                self.bundle, self.archive, self.state, self.backup,
                self.retired_archive, apply=True)
        self.assertTrue((self.bundle / "ca/ca.key").exists())
        self.assertFalse(self.backup.exists())

    def test_rejects_proxy_bundle_for_an_active_database_member(self):
        self._write_proxy_archive(
            f"db-b={self.node_id},db-e=node-" + "e" * 64)

        with self.assertRaises(ValueError):
            RECOVERY.recover(
                self.bundle, self.archive, self.state, self.backup,
                self.retired_archive, apply=True)
        self.assertFalse(self.bundle.exists())

    def test_rejects_proxy_bundle_with_an_unreviewed_member_address(self):
        self._write_proxy_archive()
        with tarfile.open(self.archive, "r:gz") as source:
            extracted = self.root / "edited"
            source.extractall(extracted, filter="data")
        manifest = extracted / "manifest.env"
        manifest.write_bytes(self._manifest(
            "db-b=node-" + "b" * 64 + ",db-e=node-" + "e" * 64
        ).replace(b"100.111.33.52", b"100.111.33.99"))
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            archive.add(extracted, arcname=".")
        self.archive.chmod(0o600)

        with self.assertRaises(ValueError):
            RECOVERY.recover(
                self.bundle, self.archive, self.state, self.backup,
                self.retired_archive, apply=True)
        self.assertFalse(self.bundle.exists())

    def test_rejects_non_regular_archive_entries(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            entry = tarfile.TarInfo("./manifest.env")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            archive.addfile(entry)
        self.archive.chmod(0o600)

        with self.assertRaises(ValueError):
            RECOVERY.recover(
                self.bundle, self.archive, self.state, self.backup,
                self.retired_archive, apply=True)

    def test_cli_reports_only_a_bounded_validation_reason(self):
        private_input = "not-a-node-id-private-input"
        self.state.write_text(json.dumps({
            "registered_node": {
                "node_id": private_input,
                "cluster_id": self.cluster_id,
            },
        }))
        result = subprocess.run([
            sys.executable,
            SCRIPT,
            "--bundle", self.bundle,
            "--archive", self.archive,
            "--agent-state", self.state,
            "--backup-dir", self.backup,
            "--retired-archive", self.retired_archive,
        ], check=False, capture_output=True, text=True)

        self.assertNotEqual(0, result.returncode)
        self.assertEqual(
            {"result": "rejected", "reason": "Agent node identity is invalid"},
            json.loads(result.stderr),
        )
        self.assertNotIn(private_input, result.stderr)

    def test_cli_redacts_unexpected_input_details(self):
        private_input = "private-malformed-state-value"
        self.state.write_text("{" + private_input)
        result = subprocess.run([
            sys.executable,
            SCRIPT,
            "--bundle", self.bundle,
            "--archive", self.archive,
            "--agent-state", self.state,
            "--backup-dir", self.backup,
        ], check=False, capture_output=True, text=True)

        self.assertNotEqual(0, result.returncode)
        self.assertEqual(
            {"result": "rejected", "reason": "unexpected-input"},
            json.loads(result.stderr),
        )
        self.assertNotIn(private_input, result.stderr)


if __name__ == "__main__":
    unittest.main()
