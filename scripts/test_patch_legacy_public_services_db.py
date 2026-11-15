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
            self.assertEqual(module.digest(script.read_bytes()), module.DEDUPED)
            self.assertEqual((backup / ('public-services-autopilot.' + module.ORIGINAL + '.sh')).read_bytes(), self.original)
            self.assertEqual(script.stat().st_mode & 0o777, 0o755)
            self.assertFalse(module.apply(script, backup)['changed'])

    def test_backport_upgrades_existing_db_patch_and_deduplicates_signal_urls(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            script = directory / 'autopilot.sh'
            previous = module.transform(self.original)
            script.write_bytes(previous)
            script.chmod(0o755)
            backup = directory / 'backup'
            backup.mkdir(mode=0o700)
            self.assertTrue(module.apply(script, backup)['changed'])
            self.assertEqual(module.digest(script.read_bytes()), module.DEDUPED)
            self.assertEqual((backup / ('public-services-autopilot.' + module.PATCHED + '.sh')).read_bytes(), previous)
            self.assertFalse(module.apply(script, backup)['changed'])

            current = (ROOT / 'scripts/public-services-autopilot.sh').read_text()
            helper = current.split('dedupe_control_plane_urls() {', 1)[1].split('\n}\n', 1)[0]
            self.assertEqual(module.URL_DEDUPE_HELPER, 'dedupe_control_plane_urls() {' + helper + '\n}\n')
            probe = module.URL_DEDUPE_HELPER + '''\ndedupe_control_plane_urls "http://10.250.0.10:19088,http://10.250.0.10:19088/,https://a.example,https://a.example/"\n'''
            result = subprocess.check_output(['/bin/sh', '-c', probe], text=True)
            self.assertEqual(result, 'http://10.250.0.10:19088,https://a.example')

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
            script.write_bytes(module.transform_signal_urls(module.transform(self.original)))
            script.chmod(0o755)
            env = os.environ.copy()
            env['HETERONETWORK_PUBLIC_SERVICES_SMOKE_AUTOPILOT'] = str(script)
            subprocess.run([str(ROOT / 'scripts/public-services-autopilot-smoke.sh'), '--db-outage-only'],
                           cwd=ROOT, env=env, check=True, timeout=90)


if __name__ == '__main__':
    unittest.main()
