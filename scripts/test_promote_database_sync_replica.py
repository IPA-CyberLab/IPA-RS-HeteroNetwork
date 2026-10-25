import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('promotion', ROOT/'scripts/promote-database-sync-replica.py')
PROMOTE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROMOTE)


class SyncReplicaPromotionTest(unittest.TestCase):
    def test_preserves_keys_and_promoted_member_across_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, archive = root/'bundle', root/'bundle.tar.gz'
            helper = ROOT/'scripts/postgres-ha-node.sh'
            env = {**os.environ,
                   'HETERONETWORK_DB_MEMBERS': 'db-b=100.96.127.54,db-e=100.111.33.52',
                   'HETERONETWORK_DB_MEMBER_IDENTITIES': 'db-b=node-b,db-e=node-e',
                   'HETERONETWORK_DB_DCS_MEMBERS': 'db-b=100.96.127.54,db-e=100.111.33.52,db-h=100.65.54.75',
                   'HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS': 'db-b=100.96.127.54,db-e=100.111.33.52,db-h=100.65.54.75',
                   'HETERONETWORK_DB_TOPOLOGY_REVISION': '3'}
            subprocess.run([str(helper),'init-bundle',str(bundle)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            (bundle/'cluster-id').write_text('non-sensitive-test-cluster\n')
            (bundle/'cluster-id').chmod(0o600)
            PROMOTE.AUTH.pack_bundle(bundle, archive)
            before=PROMOTE.AUTH.tree_digest(bundle)
            roster=ROOT/'deploy/terraform/master-only/overlay-boot-peers.json'
            preview=PROMOTE.promote(bundle,archive,root/'backups',helper,roster)
            self.assertEqual(preview['result'],'promotion-required')
            self.assertEqual(PROMOTE.AUTH.tree_digest(bundle),before)
            actual=PROMOTE.promote(bundle,archive,root/'backups',helper,roster,True)
            self.assertEqual(actual,{'result':'changed','members':3,'revision':4})
            after=PROMOTE.AUTH.tree_digest(bundle)
            self.assertEqual({k:v for k,v in before.items() if k!='manifest.env'},
                             {k:v for k,v in after.items() if k!='manifest.env'})
            self.assertEqual(PROMOTE.promote(bundle,archive,root/'backups',helper,roster,True)['result'],'unchanged')
            authority=PROMOTE.AUTH.inspect_authority(bundle,archive)
            self.assertFalse(authority['retired'])
            self.assertIn('db-h=100.65.54.75',PROMOTE.AUTH.render_manifest(authority).decode())


if __name__=='__main__':
    unittest.main()
