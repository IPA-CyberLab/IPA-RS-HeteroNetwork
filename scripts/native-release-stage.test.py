#!/usr/bin/env python3
"""Local temporary-directory tests. No payload is ever executed."""
import copy
import concurrent.futures
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_stage", HERE / "native-release-stage.py")
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def elf(marker=1):
    data = bytearray(512)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 3, 62)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<H", data, 52, 64)
    data[-1] = marker
    return bytes(data)


class NativeStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="native-stage-test-"))
        self.root = self.temp / "staging"
        self.root.mkdir(mode=0o700)
        self.archive = self.temp / "bundle.tar.gz"
        self.channels = self.temp / "channels.json"
        self.files = {name: elf(index) for index, name in enumerate(sorted(stage.REQUIRED_BINARIES), 1)}
        self.files["libexec/public-services-autopilot.sh"] = b"#!/bin/sh\nexit 97\n"

    def tearDown(self):
        # Tests create deliberately read-only slots; only the isolated test tree is removed.
        for directory, _, _ in os.walk(self.temp):
            if not Path(directory).is_symlink():
                os.chmod(directory, 0o700)
        shutil.rmtree(self.temp)

    def bundle(self, members=None, files=None):
        files = self.files if files is None else files
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            if members is None:
                members = [(name, tarfile.REGTYPE, data) for name, data in files.items()]
            for name, kind, data in members:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.mode = 0o7777  # Archive modes are never applied.
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    item.linkname = "/outside"
                if kind == tarfile.REGTYPE:
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
                else:
                    archive.addfile(item)
        self.archive.write_bytes(gzip.compress(stream.getvalue(), mtime=0))
        return self.catalog(files)

    def catalog(self, files=None):
        files = self.files if files is None else files
        artifact = {"schema_version": 1, "component": "heteronetwork", "version": "v1.2.3",
                    "commit": "1" * 40, "image": "ghcr.io/ipa-cyberlab/heteronetwork@sha256:" + "2" * 64,
                    "native": {"linux-amd64": {"asset": "heteronetwork-1.2.3-linux-amd64.tar.gz",
                              "sha256": digest(self.archive.read_bytes()),
                              "files": {name: digest(data) for name, data in files.items()}}}}
        self.state(artifact)
        return artifact

    def state(self, artifact, promote=False):
        state = {"schema_version": 1, "revision": 1, "dev": {"heteronetwork": artifact}, "prod": {},
                 "history": [{"revision": 1, "command": "stage", "channel": "dev", "component": "heteronetwork",
                              "before": None, "after": artifact, "at": "2026-09-10T00:00:00.000Z"}]}
        if promote:
            state["revision"] = 2
            state["prod"]["heteronetwork"] = artifact
            state["history"].append({"revision": 2, "command": "promote", "channel": "prod", "component": "heteronetwork",
                                     "before": None, "after": artifact, "at": "2026-09-10T00:01:00.000Z"})
        self.channels.write_text(json.dumps(state))

    def prepare(self):
        return stage.prepare(self.root, self.channels, "dev", self.archive)

    def assert_no_prepared(self):
        slots = self.root / "slots"
        self.assertFalse(slots.exists() and list(slots.iterdir()))
        self.assertFalse((self.root / ".lock").exists())

    def test_prepare_inspect_shared_dev_prod_same_complete_bytes(self):
        artifact = self.bundle()
        before = self.channels.read_bytes()
        result = self.prepare()
        self.assertEqual(result["selected_revision"], 1)
        self.assertFalse(result["activation_performed"])
        slot = Path(result["slot"])
        for name, data in self.files.items():
            self.assertEqual((slot / name).read_bytes(), data)
            self.assertEqual((slot / name).stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.channels.read_bytes(), before)
        self.assertFalse((self.root / "selection.json").exists())
        self.assertEqual(stage.inspect(self.root, result["artifact_id"])["manifest"]["native"], artifact["native"])
        self.assertEqual(self.prepare()["slot"], result["slot"])
        self.state(artifact, promote=True)
        selected = stage.select(self.root, self.channels, "prod", 2)
        self.assertEqual(selected["artifact_id"], result["artifact_id"])
        self.assertEqual(selected["selected_revision"], 2)
        with self.assertRaises(ValueError):
            stage.select(self.root, self.channels, "prod", 1)

    def test_corrupt_shared_history_and_unprepared_selection_rejected(self):
        self.bundle()
        with self.assertRaises(FileNotFoundError):
            stage.select(self.root, self.channels, "dev", 1)
        state = json.loads(self.channels.read_text())
        state["dev"]["heteronetwork"]["commit"] = "3" * 40
        self.channels.write_text(json.dumps(state))
        with self.assertRaises(ValueError):
            self.prepare()
        self.assert_no_prepared()

    def test_archive_checksum_before_tar_processing(self):
        self.bundle()
        self.archive.write_bytes(b"not a tar archive")
        with mock.patch.object(stage, "unpack_verified_archive") as unpack:
            with self.assertRaises(ValueError):
                self.prepare()
            unpack.assert_not_called()
        self.assert_no_prepared()

    def test_binary_checksum_and_native_architecture(self):
        self.bundle()
        artifact = json.loads(self.channels.read_text())["dev"]["heteronetwork"]
        artifact["native"]["linux-amd64"]["files"]["bin/ipars"] = "0" * 64
        self.state(artifact)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assert_no_prepared()
        files = copy.deepcopy(self.files)
        files["bin/ipars"] = b"#!/bin/sh\n" + bytes(502)
        self.bundle(files=files)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assert_no_prepared()

    def test_all_unsafe_tar_entry_types_and_paths(self):
        valid = [(name, tarfile.REGTYPE, data) for name, data in self.files.items()]
        cases = [("../escape", tarfile.REGTYPE), ("/escape", tarfile.REGTYPE),
                 ("bin/ipars", tarfile.SYMTYPE), ("bin/ipars", tarfile.LNKTYPE),
                 ("bin/ipars", tarfile.CHRTYPE), ("bin/ipars", tarfile.FIFOTYPE),
                 ("bin/ipars", tarfile.GNUTYPE_SPARSE), ("bin/ipars", tarfile.XHDTYPE),
                 ("bin", tarfile.DIRTYPE), ("./bin/ipars", tarfile.REGTYPE)]
        for name, kind in cases:
            with self.subTest(name=name, kind=kind):
                self.bundle([(name, kind, elf())] + valid)
                with self.assertRaises((ValueError, tarfile.TarError)):
                    self.prepare()
                self.assert_no_prepared()
        self.bundle(valid + [valid[0]])
        with self.assertRaises(ValueError):
            self.prepare()
        self.assert_no_prepared()

    def test_total_and_helper_and_archive_bounds(self):
        self.bundle()
        for limit, size in [("MAX_TOTAL", 1024), ("MAX_HELPER", 4), ("MAX_ARCHIVE", 8), ("MAX_BINARY", 64)]:
            with self.subTest(limit=limit), mock.patch.object(stage, limit, size):
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assert_no_prepared()

    def test_missing_required_binary_and_unlisted_helper(self):
        files = copy.deepcopy(self.files)
        del files["bin/ipars-k8s-controller"]
        self.bundle(files=files)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assert_no_prepared()
        valid = [(name, tarfile.REGTYPE, data) for name, data in self.files.items()]
        self.bundle(valid + [("libexec/unlisted.sh", tarfile.REGTYPE, b"exit 1\n")])
        with self.assertRaises(ValueError):
            self.prepare()
        self.assert_no_prepared()

    def test_symlink_sources_slots_and_private_root(self):
        self.bundle()
        original = self.temp / "original.tar.gz"
        self.archive.rename(original)
        self.archive.symlink_to(original)
        with self.assertRaises(OSError):
            self.prepare()
        self.assert_no_prepared()
        self.archive.unlink()
        original.rename(self.archive)
        root_link = self.temp / "root-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            stage.prepare(root_link, self.channels, "dev", self.archive)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.prepare()
        self.root.chmod(0o700)

    def test_tampered_slot_and_hardlink_fail_inspection(self):
        self.bundle()
        result = self.prepare()
        payload = Path(result["slot"]) / "bin/iparsd"
        os.link(payload, self.temp / "hardlink")
        with self.assertRaises(ValueError):
            stage.inspect(self.root, result["artifact_id"])
        (self.temp / "hardlink").unlink()
        payload.chmod(0o600)
        payload.write_bytes(elf(99))
        payload.chmod(0o400)
        with self.assertRaises(ValueError):
            stage.select(self.root, self.channels, "dev", 1)

    def test_failure_is_atomic_and_stale_lock_not_removed(self):
        self.bundle()
        with mock.patch.object(stage.os, "rename", side_effect=OSError("injected publication failure")):
            with self.assertRaises(OSError):
                self.prepare()
        self.assert_no_prepared()
        lock = self.root / ".lock"
        lock.write_text("existing owner")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(lock.read_text(), "existing owner")

    def test_node_environment_and_catalog_control_injection(self):
        artifact = self.bundle()
        with mock.patch.dict(os.environ, {"NODE_OPTIONS": "--require /nonexistent/injected.js"}):
            self.prepare()
        artifact["image"] += "\n"
        self.state(artifact)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_cli_uses_shared_catalog_and_never_prints_untrusted_failure_text(self):
        self.bundle()
        result = subprocess.run(["python3", str(HERE / "native-release-stage.py"), "prepare",
                                 "--root", str(self.root), "--channels", str(self.channels),
                                 "--environment", "dev", "--archive", str(self.archive)],
                                capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["activation_performed"])
        self.channels.write_text('{"secret":"DO_NOT_PRINT", "bad":"\\u001b[31m"}')
        result = subprocess.run(["python3", str(HERE / "native-release-stage.py"), "select",
                                 "--root", str(self.root), "--channels", str(self.channels), "--environment", "dev"],
                                capture_output=True, text=True, timeout=15, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DO_NOT_PRINT", result.stderr)
        self.assertNotIn("\x1b", result.stderr)

    def test_committed_builder_to_shared_channels_to_prepare_integration(self):
        binary_dir = self.temp / "builder-binaries"
        binary_dir.mkdir()
        for index, name in enumerate(sorted(stage.REQUIRED_BINARIES), 1):
            (binary_dir / name.split("/")[1]).write_bytes(elf(index))
        base = {"schema_version": 1, "component": "heteronetwork", "version": "v1.2.3",
                "commit": "1" * 40, "image": "ghcr.io/ipa-cyberlab/heteronetwork@sha256:" + "2" * 64}
        base_path = self.temp / "base-artifact.json"
        base_path.write_text(json.dumps(base))
        packaged = self.temp / "packaged"
        def node(*args):
            return subprocess.run(["node", *map(str, args)], check=True, capture_output=True,
                                  text=True, timeout=30, env={"PATH": os.defpath})
        node(HERE / "package-native-release.mjs", base_path, binary_dir, packaged)
        artifact_path = packaged / "heteronetwork-release-artifact.json"
        artifact = json.loads(artifact_path.read_text())
        bundle = artifact["native"]["linux-amd64"]
        self.assertEqual(len(bundle["files"]), 12)
        node(HERE / "release-channels.mjs", "stage", self.channels, artifact_path, "0")
        result = stage.prepare(self.root, self.channels, "dev", packaged / bundle["asset"])
        slot = Path(result["slot"])
        for name, expected in bundle["files"].items():
            self.assertEqual(digest((slot / name).read_bytes()), expected)
            if name.startswith("libexec/"):
                self.assertEqual((slot / name).read_bytes(), (HERE / name.split("/")[1]).read_bytes())
        node(HERE / "release-channels.mjs", "promote", self.channels, artifact_path, "1")
        prod = stage.select(self.root, self.channels, "prod", 2)
        self.assertEqual(prod["artifact_id"], result["artifact_id"])
        self.assertEqual(prod["archive_sha256"], bundle["sha256"])
        self.assertFalse(prod["activation_performed"])

    def test_competing_preparations_publish_only_one_complete_slot(self):
        self.bundle()
        def attempt():
            try:
                return self.prepare()
            except FileExistsError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        prepared = [result for result in results if result is not None]
        self.assertTrue(prepared)
        self.assertEqual(len({result["artifact_id"] for result in prepared}), 1)
        self.assertEqual([item.name for item in (self.root / "slots").iterdir()], [prepared[0]["artifact_id"]])
        self.assertFalse((self.root / ".lock").exists())
        stage.inspect(self.root, prepared[0]["artifact_id"])


if __name__ == "__main__":
    unittest.main()
