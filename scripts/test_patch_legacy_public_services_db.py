import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('legacy_db_patch', ROOT / 'scripts/patch-legacy-public-services-db.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
LEGACY_COMMIT = '392145ec99f169d459341eb5a3eab6c19044b978'


class LegacyPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subprocess.check_output(
            ['git', 'show', f'{LEGACY_COMMIT}:scripts/public-services-autopilot.sh'], cwd=ROOT)
        assert module.digest(cls.original) == module.ORIGINAL

    def test_patch_is_atomic_backed_up_and_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            script = directory / 'autopilot.sh'
            script.write_bytes(self.original)
            script.chmod(0o755)
            backup = directory / 'backup'
            backup.mkdir(mode=0o700)
            result = module.apply(script, backup)
            self.assertTrue(result['changed'])
            self.assertEqual(module.digest(script.read_bytes()), module.PATCHED)
            self.assertEqual((backup / ('public-services-autopilot.' + module.ORIGINAL + '.sh')).read_bytes(), self.original)
            self.assertEqual(script.stat().st_mode & 0o777, 0o755)
            self.assertFalse(module.apply(script, backup)['changed'])

    def test_unknown_source_and_unsafe_file_are_refused(self):
        with self.assertRaises(ValueError):
            module.transform(self.original + b'\n')
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            backup = directory / 'backup'
            backup.mkdir(mode=0o700)
            target = directory / 'actual'
            target.write_bytes(self.original)
            link = directory / 'autopilot.sh'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                module.apply(link, backup)
            self.assertEqual(target.read_bytes(), self.original)

    def test_legacy_backport_keeps_vpn_during_db_outage_and_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'autopilot.sh'
            script.write_bytes(module.transform(self.original))
            script.chmod(0o755)
            env = os.environ.copy()
            env['HETERONETWORK_PUBLIC_SERVICES_SMOKE_AUTOPILOT'] = str(script)
            subprocess.run([str(ROOT / 'scripts/public-services-autopilot-smoke.sh'), '--db-outage-only'],
                           cwd=ROOT, env=env, check=True, timeout=90)


if __name__ == '__main__':
    unittest.main()
