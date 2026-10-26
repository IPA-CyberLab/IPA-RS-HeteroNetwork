import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('boot_recovery',ROOT/'scripts/reconcile-overlay-boot.py')
BOOT=importlib.util.module_from_spec(spec)
spec.loader.exec_module(BOOT)


class OverlayBootRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
        self.roster=json.loads((ROOT/'deploy/terraform/master-only/overlay-boot-peers.json').read_text())
        node=next(p for p in self.roster['peers'] if p['hostname']=='uc-k8sp5')
        dead=next(p for p in self.roster['peers'] if p['hostname']=='uc-k8sp4')
        self.state={'node_id':node['node_id'],'registered_node':node,
                    'wireguard_public_key_b64':node['wireguard_public_key'],
                    'identity_public_key_b64':node['identity_public_key'],
                    'identity_private_key_b64':'inert-private-test-value',
                    'wireguard_private_key_b64':'another-inert-private-value',
                    'created_at':'2026-01-01T00:00:00Z','updated_at':'2026-10-01T00:00:00Z',
                    'bootstrap_peer_cache':{'cluster_id':node['cluster_id'],'peers':[dead],
                                            'bootstrap_endpoints':[],'generated_at':'2026-10-01T00:00:00Z'}}
        self.state_path=self.root/'agent.json';self.roster_path=self.root/'roster.json'
        self.state_path.write_text(json.dumps(self.state));self.state_path.chmod(0o600)
        self.roster_path.write_text(json.dumps(self.roster));self.roster_path.chmod(0o600)

    def tearDown(self):self.temporary.cleanup()

    def test_single_dead_cached_peer_does_not_strand_a_cold_boot(self):
        preview=BOOT.reconcile(self.state_path,self.roster_path,'uc-k8sp5',True)
        self.assertFalse(preview['changed'])
        self.assertEqual(json.loads(self.state_path.read_text()),self.state)
        result=BOOT.reconcile(self.state_path,self.roster_path,'uc-k8sp5')
        self.assertEqual(result['approved_bootstrap_peers'],4)
        after=json.loads(self.state_path.read_text())
        self.assertEqual({p['vpn_ip'] for p in after['bootstrap_peer_cache']['peers']},
                         {'10.250.0.4','10.250.0.5','10.250.0.6','10.250.0.10'})
        self.assertTrue(all(not p['routes'] for p in after['bootstrap_peer_cache']['peers']))
        for key in self.state:
            if key not in ['updated_at','bootstrap_peer_cache']:self.assertEqual(after[key],self.state[key])
        self.assertEqual(self.state_path.stat().st_mode&0o777,0o600)
        self.assertFalse(BOOT.reconcile(self.state_path,self.roster_path,'uc-k8sp5')['changed'])

    def test_rejects_identity_rotation_without_an_operator_roster_update(self):
        self.state['wireguard_public_key_b64']='unapproved-new-key'
        self.state_path.write_text(json.dumps(self.state))
        with self.assertRaises(RuntimeError):BOOT.reconcile(self.state_path,self.roster_path,'uc-k8sp5')
        self.assertEqual(json.loads(self.state_path.read_text()),self.state)

    def test_rejects_cross_cluster_and_duplicate_rosters(self):
        for mutate in [lambda r:r.update(cluster_id='other-cluster'),
                       lambda r:r['peers'].append(copy.deepcopy(r['peers'][0]))]:
            roster=copy.deepcopy(self.roster);mutate(roster)
            with self.assertRaises(RuntimeError):BOOT.recovery_map(self.state,roster,'uc-k8sp5')

    def test_rejects_workload_route_and_linked_or_public_state(self):
        roster=copy.deepcopy(self.roster);roster['peers'][0]['routes']=[{'cidr':'0.0.0.0/0'}]
        with self.assertRaises(RuntimeError):BOOT.recovery_map(self.state,roster,'uc-k8sp5')
        self.state_path.chmod(0o644)
        with self.assertRaises(RuntimeError):BOOT.reconcile(self.state_path,self.roster_path,'uc-k8sp5')
        self.state_path.chmod(0o600)
        link=self.root/'linked.json';link.symlink_to(self.state_path)
        with self.assertRaises(OSError):BOOT.reconcile(link,self.roster_path,'uc-k8sp5')


if __name__=='__main__':unittest.main()
