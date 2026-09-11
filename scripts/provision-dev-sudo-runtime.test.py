"""Offline runtime preparation tests; no systemd or guest mutations."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runtime", Path(__file__).with_name("provision-dev-sudo-runtime.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def test_historical_public_inputs_and_local_unit_match_pins(self):
        values = (
            (ROOT / "deploy/dev/native/sudo-hosts.json", module.HOSTS_SHA),
            (ROOT / "deploy/systemd/heteronetwork-sudo-local.service", module.LOCAL_UNIT_SHA),
        )
        for path, digest in values:
            with self.subTest(path=path):
                self.assertEqual(module.hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_local_unit_is_root_local_and_networkless(self):
        unit = (ROOT / "deploy/systemd/heteronetwork-sudo-local.service").read_text()
        for value in ("PrivateNetwork=true", "RestrictAddressFamilies=AF_UNIX",
                      "RuntimeDirectory=ipars-sudo-v2", "StateDirectory=ipars-sudo-v2",
                      "CapabilityBoundingSet=", "NoNewPrivileges=true",
                      "/opt/heteronetwork/sudo-v2/artifacts/current/bin/local-sudo-v2 --check-config"):
            self.assertIn(value, unit)
        self.assertNotIn("WantedBy=default.target", unit)

    def test_signer_uses_dynamic_user_dedicated_runtime_and_credential(self):
        unit = (ROOT / "deploy/systemd/heteronetwork-sudo-quorum-signer.service").read_text()
        for value in ("DynamicUser=yes", "NoNewPrivileges=true", "CapabilityBoundingSet=",
                      "LoadCredential=quorum-share.json:",
                      "/opt/heteronetwork/sudo-v2/runtime/current/bin/iparsd quorum-signer"):
            self.assertIn(value, unit)
        self.assertNotIn("ExecStart=/opt/heteronetwork/bin/iparsd", unit)

    def test_install_file_is_exclusive_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(module, "trusted"), \
                patch.object(module, "read", side_effect=lambda path, limit, mode=None: Path(path).read_bytes()):
            path = Path(directory) / "file"
            self.assertTrue(module.install_file(path, b"fixed", 0o600))
            inode = path.stat().st_ino
            self.assertFalse(module.install_file(path, b"fixed", 0o600))
            self.assertEqual(path.stat().st_ino, inode)
            with self.assertRaises(ValueError):
                module.install_file(path, b"changed", 0o600)
            self.assertEqual(path.read_bytes(), b"fixed")

    def test_mkdir_sets_explicit_mode_and_repairs_only_empty_private_directory(self):
        def verify(path, directory=False, mode=None):
            module.require(directory and (Path(path).stat().st_mode & 0o777) == mode)
        with tempfile.TemporaryDirectory() as directory, patch.object(module, "trusted", side_effect=verify):
            path = Path(directory) / "runtime"
            previous = module.os.umask(0o077)
            try:
                module.mkdir(path, 0o755)
            finally:
                module.os.umask(previous)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            path.chmod(0o700)
            module.mkdir(path, 0o755, repair_empty_private=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            (path / "unknown").write_text("preserve")
            path.chmod(0o700)
            with self.assertRaises(ValueError):
                module.mkdir(path, 0o755, repair_empty_private=True)
            self.assertEqual((path / "unknown").read_text(), "preserve")

    def test_selection_never_retargets_existing_link(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current"
            self.assertTrue(module.select(path, "version-a"))
            self.assertFalse(module.select(path, "version-a"))
            with self.assertRaises(ValueError):
                module.select(path, "version-b")
            self.assertEqual(path.readlink(), Path("version-a"))

    def test_unit_state_requires_disabled_inactive_exact_fragment(self):
        path = Path("/etc/systemd/system/fixture.service")
        valid = (b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                 b"FragmentPath=/etc/systemd/system/fixture.service\nDropInPaths=\n"
                 b"UnitFileState=disabled\nNeedDaemonReload=no\n")
        with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=valid)):
            self.assertEqual(module.unit_state(path), {"ActiveState": "inactive", "SubState": "dead",
                                                       "UnitFileState": "disabled"})
        for replacement in (b"ActiveState=active", b"DropInPaths=/tmp/override", b"UnitFileState=enabled",
                            b"NeedDaemonReload=yes", b"FragmentPath=/tmp/fixture.service"):
            key = replacement.split(b"=", 1)[0]
            bad = b"\n".join(replacement if line.startswith(key + b"=") else line
                              for line in valid.splitlines()) + b"\n"
            with self.subTest(replacement=replacement), patch.object(
                    module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=bad)), \
                    self.assertRaises(ValueError):
                module.unit_state(path)


if __name__ == "__main__":
    unittest.main()
