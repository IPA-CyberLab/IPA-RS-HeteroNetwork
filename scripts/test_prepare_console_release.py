#!/usr/bin/env python3
"""Preparation tests use inert ELF-shaped bytes and never contact a host."""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "prepare_console_release", HERE / "prepare-console-release.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def elf(marker):
    value = bytearray(512)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", value, 16, 3, 62)
    struct.pack_into("<I", value, 20, 1)
    struct.pack_into("<H", value, 52, 64)
    value[-1] = marker
    return bytes(value)


class ConsoleReleasePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="console-release-test-"))
        self.key = self.temp / "id_ed25519"
        self.key.write_text("inert test key\n")
        self.key.chmod(0o600)
        self.work = self.temp / "work"
        self.commit = "1" * 40
        self.files = {
            "bin/ipars": elf(1),
            "bin/iparsd": elf(2),
            "bin/ipars-k8s-controller": elf(3),
        }
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, value in sorted(self.files.items()):
                item = tarfile.TarInfo(name)
                item.size = len(value)
                item.mode = 0o755
                archive.addfile(item, io.BytesIO(value))
        archive = gzip.compress(stream.getvalue(), mtime=0)
        self.archive = self.temp / "heteronetwork-1.2.3-linux-amd64.tar.gz"
        self.archive.write_bytes(archive)
        self.manifest = self.temp / "heteronetwork-release-artifact.json"
        self.manifest.write_text(json.dumps({
            "schema_version": 1,
            "component": "heteronetwork",
            "version": "1.2.3",
            "commit": self.commit,
            "image": "ghcr.io/ipa-cyberlab/heteronetwork@sha256:" + "2" * 64,
            "native": {"linux-amd64": {
                "asset": self.archive.name,
                "sha256": digest(archive),
                "files": {name: digest(value) for name, value in self.files.items()},
            }},
        }))

    def tearDown(self):
        for root, directories, files in os.walk(self.temp):
            for name in directories:
                Path(root, name).chmod(0o700)
            for name in files:
                Path(root, name).chmod(0o600)
        shutil.rmtree(self.temp)

    def test_verified_release_renders_private_six_host_inputs(self):
        result = PREPARE.prepare(
            self.manifest, self.archive, self.work, self.key, "v1.2.3", self.commit)
        self.assertEqual(result["result"], "prepared")
        self.assertEqual(result["targets"], [
            "ichikawap1", "uc-k8s3p", "uc-k8sp1", "uc-k8sp2", "uc-k8sp4", "uc-k8sp5"])
        with tarfile.open(self.work / "native-bin.tar.gz", "r:gz") as archive:
            self.assertEqual(archive.getnames(), ["ipars", "iparsd"])
            for name in PREPARE.TARGET_BINARIES:
                member = archive.getmember(name)
                self.assertEqual(member.mode, 0o755)
                self.assertEqual(archive.extractfile(member).read(), self.files[f"bin/{name}"])
        rendered = json.loads((self.work / "inventory.json").read_text())
        groups = rendered["all"]["children"]
        self.assertEqual({
            name for group in groups.values() for name in group["hosts"]
        }, {"ichikawap1", "uc-k8s3p", "uc-k8sp1", "uc-k8sp2", "uc-k8sp4", "uc-k8sp5"})
        self.assertEqual(set(groups["postgres_members"]["hosts"]), {"uc-k8sp4", "uc-k8sp5"})
        self.assertEqual(set(groups["postgres_dcs_only"]["hosts"]), {"uc-k8sp2"})
        self.assertEqual(groups["postgres_members"]["hosts"]["uc-k8sp5"]["postgres_name"], "db-b")
        self.assertIn("ProxyCommand=ssh", groups["enrollment_issuer"]["hosts"]
                      ["ichikawap1"]["ansible_ssh_common_args"])
        for name in ("known_hosts", "inventory.json", "native-bin.tar.gz"):
            self.assertEqual((self.work / name).stat().st_mode & 0o777, 0o600)

    def test_release_identity_mismatch_precedes_any_staging(self):
        with self.assertRaises(ValueError):
            PREPARE.prepare(
                self.manifest, self.archive, self.work, self.key, "v1.2.3", "3" * 40)
        self.assertFalse(self.work.exists())

    def test_archive_tampering_never_produces_ansible_inputs(self):
        self.archive.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            PREPARE.prepare(
                self.manifest, self.archive, self.work, self.key, "v1.2.3", self.commit)
        self.assertFalse((self.work / "inventory.json").exists())
        self.assertFalse((self.work / "native-bin.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
