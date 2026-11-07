import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('control_plane_dr', ROOT / 'control_plane_dr.py')
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)
RESTIC = os.environ.get('HC_DR_TEST_RESTIC', '')


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.password = self.root / 'password'
        self.password.write_text('test password\n')
        self.password.chmod(0o600)
        self.source = self.root / 'source'
        self.source.write_text('#!/bin/sh\nprintf test\n')
        self.source.chmod(0o700)
        self.file = self.root / 'config.json'
        self.config = {'repository': 's3:https://example.invalid/private-bucket/dr',
                       'password_file': str(self.password),
                       'sources': [{'name': 'postgres', 'executable': str(self.source)}],
                       'max_component_bytes': 1024, 'max_total_bytes': 2048}

    def write(self):
        self.file.write_text(json.dumps(self.config))
        self.file.chmod(0o600)

    def test_accepts_private_s3_config_and_rejects_cleartext_credentials(self):
        self.write()
        self.assertEqual(dr.read_config(self.file)['sources'][0]['name'], 'postgres')
        for repository in ('s3:http://example.invalid/bucket',
                           's3:https://user:secret@example.invalid/bucket',
                           's3:https://example.invalid/bucket?token=secret'):
            self.config['repository'] = repository
            self.write()
            with self.assertRaises(ValueError):
                dr.read_config(self.file)

    def test_recovery_does_not_require_original_source_programs(self):
        self.write()
        self.source.unlink()
        self.assertEqual(dr.read_config(self.file, require_sources=False)['sources'][0]['name'], 'postgres')
        with self.assertRaises(FileNotFoundError):
            dr.read_config(self.file, require_sources=True)

    def test_rejects_public_config_and_duplicate_components(self):
        self.write()
        self.file.chmod(0o644)
        with self.assertRaises(ValueError):
            dr.read_config(self.file)
        self.config['sources'].append(dict(self.config['sources'][0]))
        self.write()
        with self.assertRaises(ValueError):
            dr.read_config(self.file)

    def test_complete_mode_fails_before_calling_storage(self):
        self.write()
        config = dr.read_config(self.file)
        with mock.patch.object(dr, 'invoke') as invoke:
            with self.assertRaisesRegex(ValueError, 'missing required sources'):
                dr.backup(config, '/not-used', require_complete=True)
            invoke.assert_not_called()

    def test_timeout_kills_unresponsive_process(self):
        with self.assertRaises(TimeoutError):
            dr.stream_process(['/bin/sleep', '30'], {}, 0.1)

    def test_timeout_allows_child_process_to_clean_up(self):
        marker = self.root / 'cleaned'
        child = self.root / 'child.py'
        child.write_text('import signal,sys,time\n'
                         'def finish(*_):\n'
                         ' open(sys.argv[1], "w").write("cleaned")\n'
                         ' sys.exit(0)\n'
                         'signal.signal(signal.SIGTERM, finish)\n'
                         'print("ready", flush=True)\n'
                         'while True: time.sleep(1)\n')
        with self.assertRaises(TimeoutError):
            dr.stream_process([sys.executable, str(child), str(marker)], {}, 0.4)
        self.assertEqual(marker.read_text(), 'cleaned')

    def test_inherited_restic_commands_and_password_cannot_override_configuration(self):
        self.write()
        with mock.patch.dict(os.environ, {'RESTIC_PASSWORD_COMMAND': 'unsafe',
                                          'RESTIC_REPOSITORY_COMMAND': 'unsafe',
                                          'RESTIC_PASSWORD': 'unsafe'}):
            env = dr.restic_env(dr.read_config(self.file))
        self.assertNotIn('RESTIC_PASSWORD_COMMAND', env)
        self.assertNotIn('RESTIC_REPOSITORY_COMMAND', env)
        self.assertNotIn('RESTIC_PASSWORD', env)
        self.assertEqual(env['RESTIC_PASSWORD_FILE'], str(self.password))


@unittest.skipUnless(RESTIC and Path(RESTIC).is_file(), 'Set HC_DR_TEST_RESTIC to a real restic binary')
class RealResticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root
        password = root / 'password'
        password.write_text('fixture password only\n')
        password.chmod(0o600)
        self.marker = b'private-fixture-' + os.urandom(24).hex().encode()
        source = root / 'source'
        source.write_text('#!/bin/sh\nprintf %s ' + self.marker.decode() + '\n')
        source.chmod(0o700)
        self.raw_config = {'repository': str(root / 'repo'), 'password_file': str(password),
                           'sources': [{'name': 'postgres', 'executable': str(source)}],
                           'max_component_bytes': 1024 * 1024, 'max_total_bytes': 1024 * 1024,
                           'timeout_seconds': 120}
        config_file = root / 'config.json'
        config_file.write_text(json.dumps(self.raw_config))
        config_file.chmod(0o600)
        self.config = dr.read_config(config_file, allow_local=True)
        subprocess.run([RESTIC, 'init', '--quiet'], env=dr.restic_env(self.config), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_real_encrypted_backup_verify_and_restore(self):
        result = dr.backup(self.config, RESTIC)
        self.assertFalse(result['required_components_present'])
        self.assertEqual(dr.verify(self.config, RESTIC, result['snapshot'])['components_verified'], 1)
        target = self.root / 'restore'
        target.mkdir(mode=0o700)
        self.assertEqual(dr.restore(self.config, RESTIC, result['snapshot'], target)['components_restored'], 1)
        self.assertEqual((target / 'postgres').read_bytes(), self.marker)
        self.assertEqual((target / 'postgres').stat().st_mode & 0o777, 0o600)
        for path in (self.root / 'repo').rglob('*'):
            if path.is_file():
                self.assertNotIn(self.marker, path.read_bytes())

    def test_failed_source_never_commits_a_recovery_manifest(self):
        source = Path(self.raw_config['sources'][0]['executable'])
        source.write_text('#!/bin/sh\nprintf partial\nexit 1\n')
        with self.assertRaises(RuntimeError):
            dr.backup(self.config, RESTIC)
        output = subprocess.check_output([RESTIC, 'snapshots', '--json', '--tag', 'hc-dr-commit'],
                                         env=dr.restic_env(self.config))
        self.assertEqual(json.loads(output), [])

    def test_size_budget_fails_without_committing(self):
        self.config['max_component_bytes'] = 3
        with self.assertRaises(RuntimeError):
            dr.backup(self.config, RESTIC)
        output = subprocess.check_output([RESTIC, 'snapshots', '--json', '--tag', 'hc-dr-commit'],
                                         env=dr.restic_env(self.config))
        self.assertEqual(json.loads(output), [])

    def test_restore_refuses_nonempty_target(self):
        result = dr.backup(self.config, RESTIC)
        target = self.root / 'existing'
        target.mkdir(mode=0o700)
        (target / 'keep').write_text('do not touch')
        with self.assertRaisesRegex(ValueError, 'empty'):
            dr.restore(self.config, RESTIC, result['snapshot'], target)
        self.assertEqual((target / 'keep').read_text(), 'do not touch')

    def test_source_program_does_not_receive_s3_or_repository_secrets(self):
        source = Path(self.raw_config['sources'][0]['executable'])
        source.write_text('#!/bin/sh\n'
                          'if env | grep -Eq "^(AWS_|RESTIC_)"; then exit 1; fi\n'
                          'printf fixture\n')
        with mock.patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY': 'private-test-marker'}):
            result = dr.backup(self.config, RESTIC)
        self.assertEqual(dr.verify(self.config, RESTIC, result['snapshot'])['components_verified'], 1)

    def test_restore_cleans_its_partial_output_on_mismatch(self):
        result = dr.backup(self.config, RESTIC)
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        with mock.patch.object(dr, 'dump', return_value={'size': 1, 'sha256': '0' * 64}):
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                dr.restore(self.config, RESTIC, result['snapshot'], target)
        self.assertEqual(list(target.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
