"""Offline packaging tests; synthetic ELF bytes are never executed."""
import copy
import gzip
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("sudo_artifact", Path(__file__).with_name("sudo-quorum-v2-artifact.py"))
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.platform, machine = artifact.host_platform()
        elf = bytearray(64)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", elf, 16, 3, machine, 1)
        struct.pack_into("<H", elf, 52, 64)
        self.payloads = {"bin/local-sudo-v2": bytes(elf), "lib/quorum_v2_gate.so": bytes(elf),
                         "NOT_ENABLED.txt": artifact.NOTE}
        self.manifest = artifact.manifest_for(self.payloads, {"source_dirty": True}, self.platform)

    def decode(self, payloads=None, manifest=None):
        data = artifact.encode_archive(payloads or self.payloads, manifest or self.manifest)
        return artifact.decode_archive(data, artifact.digest(data))

    def test_exact_disabled_roundtrip_and_deterministic_archive(self):
        members, manifest = self.decode()
        self.assertEqual(set(members), set(artifact.FILES))
        self.assertIs(manifest["enabled"], False)
        self.assertEqual(artifact.encode_archive(self.payloads, self.manifest),
                         artifact.encode_archive(self.payloads, self.manifest))

    def test_checksum_is_mandatory(self):
        data = artifact.encode_archive(self.payloads, self.manifest)
        for wrong in ("", "0" * 64, artifact.digest(data).upper()):
            with self.assertRaises(ValueError):
                artifact.decode_archive(data, wrong)

    def release_archive(self, **overrides):
        provenance = {"source_commit": "a" * 40, "source_dirty": False,
                      "profile": "release", "ack_regression": "passed", **overrides}
        return artifact.encode_archive(self.payloads, artifact.manifest_for(self.payloads, provenance, self.platform))

    def test_release_contract_exact_schema(self):
        if self.platform != "linux-amd64":
            self.skipTest("initial release platform is amd64")
        data = self.release_archive()
        contract = artifact.release_contract(data, "a" * 40, "v1.2.3-dev.1")
        self.assertEqual(contract, {
            "asset": "heteronetwork-1.2.3-dev.1-sudo-v2-linux-amd64.tar.gz",
            "sha256": artifact.digest(data), "source_commit": "a" * 40,
            "profile": "release", "plugin_header_sha256": artifact.HEADER_SHA256,
            "files": self.manifest["files"]})

    def test_release_rejects_invalid_identity_and_profile(self):
        for commit, version, profile in (("a" * 39, "1.2.3", "release"),
                ("A" * 40, "1.2.3", "release"), (None, "1.2.3", "release"),
                ("a" * 40, None, "release"), ("a" * 40, "1.02.3", "release"),
                ("a" * 40, "1.2.3-01", "release"), ("a" * 40, "1.2.3+build.1", "release"),
                ("a" * 40, "1.2.3", "dev")):
            with self.subTest(commit=commit, version=version, profile=profile), self.assertRaises(ValueError):
                artifact.release_identity(commit, version, profile)

    def test_release_rejects_dirty_dev_or_mismatched_artifact(self):
        for changes in ({"source_dirty": True}, {"source_dirty": 0},
                        {"source_commit": "b" * 40}, {"profile": "dev"},
                        {"ack_regression": "failed"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                artifact.release_contract(self.release_archive(**changes), "a" * 40, "1.2.3")

    def test_release_source_requires_exact_clean_head(self):
        for head, status, accepted in (("a" * 40, "", True), ("b" * 40, "", False),
                                      ("a" * 40, "?? new-file\n", False),
                                      ("a" * 40, " M tracked\n", False)):
            with patch.object(artifact, "run", side_effect=[SimpleNamespace(stdout=head), SimpleNamespace(stdout=status)]):
                if accepted:
                    artifact.check_release_source("a" * 40)
                else:
                    with self.assertRaises(ValueError):
                        artifact.check_release_source("a" * 40)

    def test_manifest_payload_mismatch(self):
        bad = copy.deepcopy(self.manifest)
        bad["files"]["bin/local-sudo-v2"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.decode(manifest=bad)

    def test_enabled_wrong_platform_header_and_symbol_rejected(self):
        for field, value in (("enabled", True), ("platform", "windows-amd64"),
                             ("sudo_plugin_header_sha256", "0" * 64),
                             ("sudo_plugin_symbol", "quorum_privilege_gate")):
            bad = {**self.manifest, field: value}
            with self.assertRaises(ValueError):
                self.decode(manifest=bad)

    def test_elf_architecture_and_shared_object_required(self):
        for offset, value in ((18, 0), (4, 1), (16, 2)):
            bad = dict(self.payloads)
            elf = bytearray(bad["lib/quorum_v2_gate.so"])
            elf[offset] = value
            bad["lib/quorum_v2_gate.so"] = bytes(elf)
            with self.assertRaises(ValueError):
                self.decode(bad, artifact.manifest_for(bad, {}, self.platform))

    def hostile_archive(self, name, kind=tarfile.REGTYPE, duplicate=False, mode=0o644):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for _ in range(2 if duplicate else 1):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = mode
                member.linkname = "outside" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                member.size = 1 if kind == tarfile.REGTYPE else 0
                archive.addfile(member, io.BytesIO(b"x") if member.size else None)
        data = gzip.compress(raw.getvalue(), mtime=0)
        with self.assertRaises(ValueError):
            artifact.decode_archive(data, artifact.digest(data))

    def test_traversal_config_and_extra_members_rejected(self):
        for name in ("../sudo.conf", "/etc/sudoers", "config.json", "host.key", "daemon.service"):
            self.hostile_archive(name)

    def test_links_directories_duplicates_and_setuid_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
            self.hostile_archive("NOT_ENABLED.txt", kind)
        self.hostile_archive("NOT_ENABLED.txt", duplicate=True)
        self.hostile_archive("bin/local-sudo-v2", mode=0o4755)

    def test_missing_notice_or_changed_notice_rejected(self):
        bad = dict(self.payloads)
        bad["NOT_ENABLED.txt"] = b"enabled"
        with self.assertRaises(ValueError):
            self.decode(bad, artifact.manifest_for(bad, {}, self.platform))
        del bad["NOT_ENABLED.txt"]
        with self.assertRaises(ValueError):
            self.decode(bad, artifact.manifest_for(bad, {}, self.platform))

    def scratch(self):
        return tempfile.TemporaryDirectory(prefix="sudo-artifact-test-", dir="/root" if os.geteuid() == 0 else None)

    def test_publish_is_copy_only_modes_and_noclobber(self):
        with self.scratch() as directory:
            target = Path(directory) / "inactive"
            artifact.publish_directory(target, {name: (data, artifact.FILES[name]) for name, data in self.payloads.items()})
            self.assertEqual({str(p.relative_to(target)) for p in target.rglob("*") if p.is_file()}, set(artifact.FILES))
            for name, mode in artifact.FILES.items():
                self.assertEqual(stat.S_IMODE((target / name).stat().st_mode), mode)
            with self.assertRaises(FileExistsError):
                artifact.publish_directory(target, {})

    def test_symlink_destination_and_ancestor_rejected(self):
        with self.scratch() as directory:
            root = Path(directory)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(FileExistsError):
                artifact.publish_directory(root / "link", {})
            with self.assertRaises(OSError):
                artifact.publish_directory(root / "link" / "new", {})

    def test_input_links_and_empty_files_rejected(self):
        with self.scratch() as directory:
            root = Path(directory)
            (root / "empty").touch()
            with self.assertRaises(ValueError):
                artifact.regular(root / "empty", 32)
            (root / "regular").write_bytes(b"public")
            (root / "symbolic").symlink_to(root / "regular")
            with self.assertRaises(OSError):
                artifact.regular(root / "symbolic", 32)
            os.link(root / "regular", root / "hard")
            with self.assertRaises(ValueError):
                artifact.regular(root / "regular", 32)


if __name__ == "__main__":
    unittest.main()
