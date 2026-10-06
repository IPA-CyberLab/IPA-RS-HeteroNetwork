import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import controller as q
import render

HERE=Path(__file__).resolve().parent


class MajorityTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((HERE/'pool.json').read_text());self.config['enabled']=True
        self.config['down_samples']=3;self.config['up_samples']=2
        self.published=['163.220.236.61'];self.now=1000.0;self.serial=0
    def votes(self, unhealthy=(), voters=None):
        self.serial+=1
        result={}
        for index,m in enumerate(self.config['members']):
            if voters is not None and m['id'] not in voters:continue
            result[m['id']]={'schema_version':1,'config_digest':q.digest(self.config),'voter_id':m['id'],'node':m['node'],'sample_id':f'{self.serial*10+index:032x}','observed_at':self.now,'origins':{x['id']:{'healthy':(m['id'],x['id']) not in unhealthy,'reason':'ok' if (m['id'],x['id']) not in unhealthy else 'timeout'} for x in self.config['origins']}}
        return result
    def round(self, previous=None, unhealthy=(), voters=None):
        s,d,r=q.decide(self.config,self.votes(unhealthy,voters),previous,self.published,self.now)
        self.published=d;self.now+=5
        return s,d,r
    def endpoint(self):
        return {'apiVersion':'externaldns.k8s.io/v1alpha1','kind':'DNSEndpoint','metadata':{'name':self.config['dns_resource'],'namespace':self.config['dns_namespace'],'uid':'endpoint-uid','resourceVersion':'10','labels':{'dns.heterocloud.io/publish':'true'}},'spec':{'endpoints':[{'dnsName':n,'recordType':'A','recordTTL':60,'targets':self.published} for n in self.config['records']]}}
    def test_second_origin_requires_two_new_majority_samples(self):
        s,d,r=self.round();self.assertEqual(d,['163.220.236.61'])
        s,d,r=self.round(s);self.assertEqual(d,['163.220.236.54','163.220.236.61'])
    def test_same_votes_cannot_be_counted_repeatedly(self):
        votes=self.votes();state=None
        for _ in range(8):state,d,r=q.decide(self.config,votes,state,self.published,self.now)
        self.assertEqual(d,self.published);self.assertEqual(state['origins']['uc-k8sp4']['streak'],1)
    def test_one_voters_repeated_samples_cannot_form_new_majority_rounds(self):
        votes=self.votes();state,d,r=q.decide(self.config,votes,None,self.published,self.now)
        for _ in range(8):
            votes['ichikawap1']=self.votes()['ichikawap1']
            state,d,r=q.decide(self.config,votes,state,self.published,self.now)
        self.assertEqual(d,self.published)
    def test_one_isolated_observer_does_not_withdraw_origin(self):
        bad=[('ichikawap1','ichikawap1')];s=None
        for _ in range(5):s,d,r=self.round(s,bad)
        self.assertIn('163.220.236.61',d);self.assertEqual(r['origins']['ichikawap1']['healthy_votes'],2)
    def test_majority_failure_withdraws_only_failed_origin_and_recovers(self):
        s,d,r=self.round();s,d,r=self.round(s)
        bad=[('ichikawap1','ichikawap1'),('uc-k8sp4','ichikawap1')]
        for _ in range(2):s,d,r=self.round(s,bad);self.assertIn('163.220.236.61',d)
        s,d,r=self.round(s,bad);self.assertEqual(d,['163.220.236.54'])
        s,d,r=self.round(s);self.assertEqual(d,['163.220.236.54'])
        s,d,r=self.round(s);self.assertEqual(d,['163.220.236.54','163.220.236.61'])
    def test_missing_majority_retains_last_dns_without_shrinking_denominator(self):
        s,d,r=self.round(voters=['ichikawap1']);self.assertEqual(d,self.published)
        self.assertEqual(r['majority_required'],2);self.assertEqual(r['fresh_voters'],1)
        self.assertEqual(r['origins']['ichikawap1']['decision'],'unknown')
    def test_expired_votes_are_unknown_not_unhealthy(self):
        votes=self.votes();state,d,r=q.decide(self.config,votes,None,self.published,self.now+31)
        self.assertEqual(d,self.published);self.assertEqual(r['fresh_voters'],0)
    def test_future_wrong_generation_and_copied_identity_votes_cannot_vote(self):
        for kind in ['future','generation','identity','node','malformed']:
            votes=self.votes()
            for v in votes.values():
                if kind=='future':v['observed_at']=self.now+4
                elif kind=='generation':v['config_digest']='f'*64
                elif kind=='identity':v['voter_id']='another-member'
                elif kind=='node':v['node']='another-node'
                else:v['origins']['ichikawap1']['healthy']='true'
            s,d,r=q.decide(self.config,votes,None,self.published,self.now)
            self.assertEqual(r['fresh_voters'],0);self.assertEqual(d,self.published)
    def test_quorum_loss_breaks_consecutive_failure_streak(self):
        bad=[(m['id'],'ichikawap1') for m in self.config['members']]
        s,d,r=self.round(unhealthy=bad);s,d,r=self.round(s,bad)
        s,d,r=self.round(s,bad,voters=['ichikawap1']);self.assertEqual(s['origins']['ichikawap1']['streak'],0)
        s,d,r=self.round(s,bad);self.assertIn('163.220.236.61',d)
    def test_config_change_does_not_reuse_previous_quorum(self):
        s,d,r=self.round();s,d,r=self.round(s)
        self.config['fresh_seconds']=35
        s,d,r=q.decide(self.config,{},s,self.published,self.now)
        self.assertEqual(d,self.published);self.assertEqual(s['origins']['ichikawap1']['streak'],0)
    def test_shadow_mode_never_changes_dns(self):
        self.config['enabled']=False;s=None
        for _ in range(5):s,d,r=self.round(s)
        self.assertEqual(d,['163.220.236.61'])
    def test_all_down_retain_preserves_dns_and_reports_outage(self):
        bad=[(m['id'],o['id']) for m in self.config['members'] for o in self.config['origins']];s=None
        for _ in range(3):s,d,r=self.round(s,bad)
        self.assertEqual(d,['163.220.236.61']);self.assertTrue(r['all_down_retained'])
        self.assertTrue(all(not x['active'] for x in r['origins'].values()))
    def test_explicit_all_down_withdraw_requires_valid_majority(self):
        self.config['all_down_policy']='withdraw';bad=[(m['id'],o['id']) for m in self.config['members'] for o in self.config['origins']];s=None
        for _ in range(3):s,d,r=self.round(s,bad)
        self.assertEqual(d,[]);self.assertTrue(r['all_down'])
        s,d,r=self.round(s);s,d,r=self.round(s);self.assertEqual(len(d),2)
    def test_patch_has_uid_version_and_entry_preconditions(self):
        endpoint=self.endpoint();ops=q.dns_patch(self.config,endpoint,['163.220.236.54'])
        self.assertEqual(ops[0]['path'],'/metadata/resourceVersion');self.assertEqual(ops[1]['path'],'/metadata/uid')
        self.assertTrue(all(x['path'].endswith('/targets') for x in ops if x['op']=='replace'))
        self.assertEqual(sum(x['op']=='replace' for x in ops),5)
    def test_unmanaged_private_record_and_record_settings_are_preserved(self):
        endpoint=self.endpoint();private={'dnsName':'secrets.heterocloud.mizuame.app','recordType':'A','targets':['10.250.0.10','10.250.0.11']}
        endpoint['spec']['endpoints'].insert(2,private)
        ops=q.dns_patch(self.config,endpoint,['163.220.236.54'])
        self.assertFalse(any(x['path'].startswith('/spec/endpoints/2') for x in ops))
        self.assertFalse(any(x['path'].endswith('/recordTTL') for x in ops))
    def test_missing_duplicate_unknown_target_or_wrong_owner_rejects_dns_patch(self):
        for kind in ['missing','duplicate','target','owner','type','deleting']:
            e=self.endpoint()
            if kind=='missing':e['spec']['endpoints'].pop()
            elif kind=='duplicate':e['spec']['endpoints'].append(copy.deepcopy(e['spec']['endpoints'][0]))
            elif kind=='target':e['spec']['endpoints'][0]['targets']=['8.8.8.8']
            elif kind=='owner':e['metadata']['name']='foreign-record'
            elif kind=='type':e['spec']['endpoints'][0]['recordType']='CNAME'
            else:e['metadata']['deletionTimestamp']='2026-10-06T00:00:00Z'
            with self.subTest(kind=kind),self.assertRaises(ValueError):q.dns_patch(self.config,e,['163.220.236.54'])
    def test_duplicate_node_and_invalid_probe_or_private_origin_rejected(self):
        for kind in ['node','resource','ip','hostname','path','timeout','bool']:
            c=copy.deepcopy(self.config)
            if kind=='node':c['members'][1]['node']=c['members'][0]['node']
            elif kind=='resource':c['members'][1]['vote_resource']=c['members'][0]['vote_resource']
            elif kind=='ip':c['origins'][0]['address']='10.250.0.10'
            elif kind=='hostname':c['probe']['hostname']='user:password@localhost'
            elif kind=='path':c['probe']['path']='//evil.example/path'
            elif kind=='timeout':c['probe']['timeout_seconds']=30
            else:c['enabled']=1
            with self.subTest(kind=kind),self.assertRaises(ValueError):q.validate_config(c)
    def test_voters_only_write_their_own_vote_and_cannot_read_secrets(self):
        docs=render.objects(self.config)
        for member in self.config['members']:
            role=next(x for x in docs if x['kind']=='Role' and x['metadata']['name']=='public-dns-voter-'+member['id'])
            self.assertEqual(role['rules'],[{'apiGroups':[''],'resources':['configmaps'],'resourceNames':[member['vote_resource']],'verbs':['get','patch']}])
        publisher=next(x for x in docs if x['kind']=='Role' and x['metadata']['name']=='public-dns-publisher-dns')
        self.assertEqual(publisher['rules'][0]['resourceNames'],['heterocloud-web-gateways'])
    def test_voters_have_distinct_fixed_nodes_and_no_secret_manager_placement(self):
        docs=render.objects(self.config);nodes=[]
        for d in docs:
            if d['kind']!='Deployment':continue
            pod=d['spec']['template']['spec']
            self.assertEqual(pod['securityContext']['runAsUser'],65532)
            self.assertTrue(pod['containers'][0]['securityContext']['readOnlyRootFilesystem'])
            chosen=pod['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms'][0]['matchExpressions'][0]['values']
            self.assertFalse(set(chosen)&{'uc-k8sp1','uc-k8sp2','uc-k8s3p'})
            if d['spec']['template']['metadata']['labels']['app.kubernetes.io/component']=='voter':nodes.extend(chosen)
        self.assertEqual(len(nodes),len(set(nodes)))
    def test_generated_workloads_match_declared_config(self):
        import yaml
        config=json.loads((HERE/'pool.json').read_text())
        self.assertEqual(list(yaml.safe_load_all((HERE/'workloads.yaml').read_text())),render.objects(config))


if __name__=='__main__':unittest.main()
