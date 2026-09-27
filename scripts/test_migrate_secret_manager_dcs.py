import importlib.util
from pathlib import Path
import unittest
from unittest import mock

import test_recover_database_authority as fixture


SOURCE = Path(__file__).with_name('migrate-secret-manager-dcs.py')
SPEC = importlib.util.spec_from_file_location('dcs_migration', SOURCE)
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)


class SecretManagerDcsMigrationTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.DatabaseAuthorityRecoveryTest()
        self.fixture.setUp()
        self.root = self.fixture.root
        self.bundle = self.fixture.bundle
        self.archive = self.fixture.archive
        result = self.fixture.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.stage = self.root / 'staged'

    def tearDown(self):
        self.fixture.tearDown()

    def test_stages_new_certificate_without_touching_authority(self):
        before = fixture.digest(self.archive)
        with mock.patch.object(MIGRATION.os, 'geteuid', return_value=0):
            result = MIGRATION.prepare(self.bundle, self.archive, self.stage, fixture.HELPER)
        self.assertEqual(result['phase'], 'staged')
        self.assertEqual(fixture.digest(self.archive), before)
        self.assertEqual(fixture.manifest(self.bundle / 'manifest.env')['HETERONETWORK_DB_DCS_MEMBERS'],
                         'db-b=100.96.127.54,db-e=100.111.33.52,db-g=100.94.130.38')
        staged = fixture.manifest(self.stage / 'bundle/manifest.env')
        self.assertEqual(staged['HETERONETWORK_DB_DCS_MEMBERS'],
                         'db-b=100.96.127.54,db-e=100.111.33.52,db-h=100.65.54.75')
        self.assertTrue((self.stage / 'bundle/nodes/db-h/node.key').is_file())

    def test_commit_requires_new_quorum_and_keeps_recovery_copy(self):
        before = fixture.digest(self.archive)
        with mock.patch.object(MIGRATION.os, 'geteuid', return_value=0):
            MIGRATION.prepare(self.bundle, self.archive, self.stage, fixture.HELPER)
            with mock.patch.object(MIGRATION, 'healthy_new_quorum', side_effect=RuntimeError('unhealthy')):
                with self.assertRaises(RuntimeError):
                    MIGRATION.commit(self.bundle, self.archive, self.stage)
            self.assertEqual(fixture.digest(self.archive), before)
            with mock.patch.object(MIGRATION, 'healthy_new_quorum'):
                result = MIGRATION.commit(self.bundle, self.archive, self.stage)
        self.assertEqual(result['phase'], 'committed')
        self.assertEqual(fixture.digest(self.stage / 'previous/bundle.tar.gz'), before)
        self.assertEqual(fixture.manifest(self.bundle / 'manifest.env')['HETERONETWORK_DB_DCS_MEMBERS'],
                         'db-b=100.96.127.54,db-e=100.111.33.52,db-h=100.65.54.75')
        authority = MIGRATION.recovery.inspect_authority(self.bundle, self.archive)
        self.assertEqual(authority['revision'], 3)
        self.assertEqual(authority['dcs'], MIGRATION.NEW_DCS)

    def test_refuses_to_retire_old_voter_before_new_one_is_promoted(self):
        peers = {
            f'https://{address}:12380': {
                'name': name, 'ID': index, 'isLearner': name == 'db-h',
            }
            for index, (name, address) in enumerate(
                {**MIGRATION.OLD_DCS, 'db-h': MIGRATION.NEW_DCS['db-h']}.items(), 1)
        }
        with mock.patch.object(MIGRATION, 'members_by_peer', return_value=peers), \
             mock.patch.object(MIGRATION, 'etcdctl') as ctl:
            with self.assertRaisesRegex(RuntimeError, 'not composed of voters'):
                MIGRATION.retire_old_voter(self.bundle)
            ctl.assert_not_called()

    def test_refuses_learner_addition_when_unmanaged_voter_exists(self):
        peers = {
            f'https://{address}:12380': {'name': name, 'ID': index}
            for index, (name, address) in enumerate(MIGRATION.OLD_DCS.items(), 1)
        }
        peers['https://100.64.0.99:12380'] = {'name': 'unmanaged', 'ID': 99}
        with mock.patch.object(MIGRATION, 'members_by_peer', return_value=peers), \
             mock.patch.object(MIGRATION, 'etcdctl') as ctl:
            with self.assertRaisesRegex(RuntimeError, 'unexpected membership'):
                MIGRATION.add_learner(self.bundle)
            ctl.assert_not_called()

    def test_promote_passes_member_id_as_hexadecimal(self):
        peers = {
            f'https://{address}:12380': {
                'name': name, 'ID': 26 if name == 'db-h' else index,
                'isLearner': name == 'db-h',
            }
            for index, (name, address) in enumerate(
                {**MIGRATION.OLD_DCS, 'db-h': MIGRATION.NEW_DCS['db-h']}.items(), 1)
        }
        with mock.patch.object(MIGRATION, 'members_by_peer', side_effect=[
            peers,
            {peer: {**member, 'isLearner': False} for peer, member in peers.items()},
        ]), mock.patch.object(MIGRATION, 'etcdctl') as ctl:
            MIGRATION.promote_learner(self.bundle)
            self.assertEqual(ctl.call_args_list[0].args[1:4],
                             ('member', 'promote', '1a'))


if __name__ == '__main__':
    unittest.main()
