import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/postgres-ha-node.sh"
RECOVERY = ROOT / "scripts/recover-database-authority.py"
MEMBERS = (
    "db-b=100.96.127.54,db-e=100.111.33.52,"
    "db-a=100.64.0.1,db-c=100.64.0.2,db-d=100.64.0.3,db-f=100.64.0.4"
)
IDENTITIES = "db-b=node-b,db-e=node-e,db-a=node-a,db-c=node-c,db-d=node-d,db-f=node-f"
DCS = "db-b=100.96.127.54,db-e=100.111.33.52,db-g=100.94.130.38"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(path):
    return dict(
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
    )


class DatabaseAuthorityRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.archive = self.root / "bundle.tar.gz"
        self.proxy_archive = self.root / "proxy-bundle.tar.gz"
        self.backups = self.root / "backups"
        environment = {
            **os.environ,
            "HETERONETWORK_DB_MEMBERS": MEMBERS,
            "HETERONETWORK_DB_MEMBER_IDENTITIES": IDENTITIES,
            "HETERONETWORK_DB_DCS_MEMBERS": DCS,
            "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS": DCS,
        }
        subprocess.run(
            [HELPER, "init-bundle", self.bundle],
            env=environment,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        (self.bundle / "cluster-id").write_text("fixture-cluster-id\n", encoding="utf-8")
        (self.bundle / "cluster-id").chmod(0o600)
        self.pack()

    def tearDown(self):
        self.temporary.cleanup()

    def pack(self):
        subprocess.run(
            ["tar", "--format=ustar", "--create", "--gzip", "--file", self.archive,
             "--directory", self.bundle, "."],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.archive.chmod(0o600)

    def recover(self, apply=True):
        command = [
            "python3", RECOVERY,
            "--bundle", self.bundle,
            "--archive", self.archive,
            "--backup-dir", self.backups,
        ]
        if apply:
            command.append("--apply")
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def publish_proxy(self):
        return subprocess.run([
            "python3", RECOVERY,
            "--bundle", self.bundle,
            "--archive", self.archive,
            "--backup-dir", self.backups,
            "--proxy-archive", self.proxy_archive,
            "--apply",
        ], check=False, capture_output=True, text=True)

    def protected_hashes(self):
        paths = [
            self.bundle / "ca/ca.crt",
            self.bundle / "ca/ca.key",
            self.bundle / "cluster-id",
            *(self.bundle / "secrets").glob("*.password"),
            *(self.bundle / "nodes/db-b").glob("*"),
            *(self.bundle / "nodes/db-e").glob("*"),
            *(self.bundle / "nodes/db-g").glob("*"),
        ]
        return {path.relative_to(self.bundle).as_posix(): digest(path) for path in paths}

    def test_retires_only_obsolete_members_and_is_idempotent(self):
        old_archive_hash = digest(self.archive)
        protected = self.protected_hashes()

        preview = self.recover(apply=False)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(json.loads(preview.stdout)["result"], "migration-required")

        first = self.recover()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout), {
            "result": "changed",
            "retired_members": 4,
            "revision": 2,
        })
        updated = manifest(self.bundle / "manifest.env")
        self.assertEqual(
            updated["HETERONETWORK_DB_MEMBERS"],
            "db-b=100.96.127.54,db-e=100.111.33.52",
        )
        self.assertEqual(
            updated["HETERONETWORK_DB_MEMBER_IDENTITIES"],
            "db-b=node-b,db-e=node-e",
        )
        self.assertEqual(updated["HETERONETWORK_DB_DCS_MEMBERS"], DCS)
        self.assertEqual(updated["HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS"], DCS)
        self.assertEqual(updated["HETERONETWORK_DB_TOPOLOGY_REVISION"], "2")
        self.assertEqual(self.protected_hashes(), protected)

        backup_directories = list(self.backups.iterdir())
        self.assertEqual(len(backup_directories), 1)
        self.assertEqual(digest(backup_directories[0] / "bundle.tar.gz"), old_archive_hash)
        with tarfile.open(self.archive, "r:gz") as archive:
            archived = archive.extractfile("./manifest.env")
            self.assertIsNotNone(archived)
            self.assertEqual(archived.read(), (self.bundle / "manifest.env").read_bytes())

        second = self.recover()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout), {
            "result": "unchanged",
            "retired_members": 0,
            "revision": 2,
        })
        self.assertEqual(len(list(self.backups.iterdir())), 1)

        self.proxy_archive.write_bytes(b"stale proxy topology")
        self.proxy_archive.chmod(0o600)
        published = self.publish_proxy()
        self.assertEqual(published.returncode, 0, published.stderr)
        self.assertEqual(json.loads(published.stdout)["proxy_bundle"], "changed")
        published_hash = digest(self.proxy_archive)
        with tarfile.open(self.proxy_archive, "r:gz") as proxy:
            files = {
                member.name.removeprefix("./")
                for member in proxy.getmembers()
                if member.isfile()
            }
            self.assertEqual(files, {
                ".proxy-only",
                "manifest.env",
                "cluster-id",
                "ca/ca.crt",
                "secrets/application.password",
            })
            self.assertEqual(proxy.extractfile("./.proxy-only").read(), b"1\n")
            self.assertEqual(
                proxy.extractfile("./manifest.env").read(),
                (self.bundle / "manifest.env").read_bytes(),
            )
            self.assertNotIn("./ca/ca.key", proxy.getnames())
            self.assertNotIn("./secrets/superuser.password", proxy.getnames())

        repeated_publish = self.publish_proxy()
        self.assertEqual(repeated_publish.returncode, 0, repeated_publish.stderr)
        self.assertEqual(json.loads(repeated_publish.stdout)["proxy_bundle"], "unchanged")
        self.assertEqual(digest(self.proxy_archive), published_hash)

    def test_refuses_to_change_invalid_protected_credentials(self):
        original_manifest = (self.bundle / "manifest.env").read_bytes()
        (self.bundle / "nodes/db-e/node.crt").write_bytes(b"invalid-certificate\n")
        self.pack()
        original_archive_hash = digest(self.archive)

        result = self.recover()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.bundle / "manifest.env").read_bytes(), original_manifest)
        self.assertEqual(digest(self.archive), original_archive_hash)
        self.assertFalse(self.backups.exists())
        self.assertNotIn("invalid-certificate", result.stderr)


if __name__ == "__main__":
    unittest.main()
