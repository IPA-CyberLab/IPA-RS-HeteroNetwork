import copy
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import tomllib
import urllib.parse
import unittest
from unittest.mock import patch
import controller as q
import render

HERE=Path(__file__).resolve().parent


class MajorityTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((HERE/'pool.json').read_text());self.config['enabled']=True
        self.config.pop('witness',None)
        # Tests use a synthetic three-voter topology, independent of the live
        # inventory, so retiring a production node does not delete coverage.
        self.config['members']=[
            {'id':'ichikawap1','node':'ichikawap1','vote_resource':'public-dns-vote-ichikawap1'},
            {'id':'simulated-worker','node':'simulated-worker','vote_resource':'public-dns-vote-simulated-worker'},
            {'id':'uc-k8sp5','node':'uc-k8sp5','vote_resource':'public-dns-vote-uc-k8sp5'}]
        self.config['origins']=[{'id':'ichikawap1','address':'163.220.236.61'},
                                {'id':'simulated-worker','address':'163.220.236.45'}]
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
        s,d,r=self.round(s);self.assertEqual(d,['163.220.236.45','163.220.236.61'])
    def test_same_votes_cannot_be_counted_repeatedly(self):
        votes=self.votes();state=None
        for _ in range(8):state,d,r=q.decide(self.config,votes,state,self.published,self.now)
        self.assertEqual(d,self.published);self.assertEqual(state['origins']['simulated-worker']['streak'],1)
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
        bad=[('ichikawap1','ichikawap1'),('simulated-worker','ichikawap1')]
        for _ in range(2):s,d,r=self.round(s,bad);self.assertIn('163.220.236.61',d)
        s,d,r=self.round(s,bad);self.assertEqual(d,['163.220.236.45'])
        s,d,r=self.round(s);self.assertEqual(d,['163.220.236.45'])
        s,d,r=self.round(s);self.assertEqual(d,['163.220.236.45','163.220.236.61'])
    def test_missing_majority_retains_last_dns_without_shrinking_denominator(self):
        s,d,r=self.round(voters=['ichikawap1']);self.assertEqual(d,self.published)
        self.assertEqual(r['majority_required'],2);self.assertEqual(r['fresh_voters'],1)
        self.assertEqual(r['origins']['ichikawap1']['decision'],'unknown')
    def test_two_voters_require_both_independent_observations(self):
        self.config['members']=self.config['members'][:2]
        self.config['origins']=self.config['origins'][:1]
        q.validate_config(self.config)
        state,targets,status=self.round(voters=['ichikawap1'])
        self.assertEqual(targets,['163.220.236.61'])
        self.assertEqual(status['majority_required'],2)
        self.assertEqual(status['origins']['ichikawap1']['decision'],'unknown')
        for _ in range(3):
            state,targets,status=self.round(state,unhealthy=[('ichikawap1','ichikawap1')])
        self.assertEqual(targets,['163.220.236.61'])
        self.assertEqual(status['origins']['ichikawap1']['decision'],'unknown')
        with self.assertRaises(ValueError):
            q.validate_config({**self.config,'members':self.config['members'][:1]})
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
        endpoint=self.endpoint();ops=q.dns_patch(self.config,endpoint,['163.220.236.45'])
        self.assertEqual(ops[0]['path'],'/metadata/resourceVersion');self.assertEqual(ops[1]['path'],'/metadata/uid')
        self.assertTrue(all(x['path'].endswith('/targets') for x in ops if x['op']=='replace'))
        self.assertEqual(sum(x['op']=='replace' for x in ops),5)
    def test_unmanaged_private_record_and_record_settings_are_preserved(self):
        endpoint=self.endpoint();private={'dnsName':'secrets.heterocloud.mizuame.app','recordType':'A','targets':['10.250.0.10','10.250.0.12']}
        endpoint['spec']['endpoints'].insert(2,private)
        ops=q.dns_patch(self.config,endpoint,['163.220.236.45'])
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
            with self.subTest(kind=kind),self.assertRaises(ValueError):q.dns_patch(self.config,e,['163.220.236.45'])
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
        deployment=next(x for x in docs if x['kind']=='Deployment' and x['metadata']['name']=='public-dns-publisher')
        self.assertEqual(deployment['spec']['strategy']['rollingUpdate'],{'maxSurge':0,'maxUnavailable':1})
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

    def test_external_witness_forms_majority_only_with_fresh_local_vote(self):
        self.config['members']=self.config['members'][:2]
        self.config['witness']={'id':'external-witness','url':'https://witness.example.org/v1/probe'}
        local=self.config['members'][0]['id'];self.published=['163.220.236.45','163.220.236.61']
        state=None
        for index in range(3):
            votes=self.votes(unhealthy=[(local,'ichikawap1')],voters=[local])
            votes['external-witness']={'schema_version':1,'config_digest':q.digest(self.config),
                'voter_id':'external-witness','node':'external','sample_id':f'{index+100:032x}',
                'observed_at':self.now,'origins':{
                    'ichikawap1':{'healthy':False,'reason':'timeout'},
                    'simulated-worker':{'healthy':True,'reason':'ok'}}}
            state,targets,status=q.decide(self.config,votes,state,self.published,self.now)
            self.now+=5
        self.assertEqual(targets,['163.220.236.45'])
        self.assertEqual(status['membership_size'],3)
        self.assertEqual(status['majority_required'],2)
        # No local observation means the witness alone cannot change DNS.
        state,targets,status=q.decide(self.config,{'external-witness':votes['external-witness']},
                                      state,targets,self.now)
        self.assertEqual(targets,['163.220.236.45'])
        self.assertEqual(status['origins']['ichikawap1']['decision'],'unknown')

    def test_witness_only_polled_when_it_can_complete_a_majority(self):
        self.config['members']=self.config['members'][:2]
        self.config['witness']={'id':'external-witness','url':'https://witness.example.org/v1/probe'}
        votes=self.votes()
        self.assertFalse(q.witness_needed(self.config,votes,self.now))
        self.assertTrue(q.witness_needed(self.config,{self.config['members'][0]['id']:votes[self.config['members'][0]['id']]},self.now))
        self.assertFalse(q.witness_needed(self.config,{},self.now))
        votes[self.config['members'][0]['id']]['origins']['ichikawap1']={'healthy':False,'reason':'timeout'}
        self.assertTrue(q.witness_needed(self.config,votes,self.now))

    def test_external_response_must_match_nonce_and_configured_origins(self):
        self.config['members']=self.config['members'][:2]
        self.config['witness']={'id':'external-witness','url':'https://witness.example.org/v1/probe'}
        config=self.config
        class Response:
            status=200
            def __init__(self,data):self.data=data
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def read(self,_):return self.data
        class Opener:
            def __init__(self,forged=False):self.forged=forged
            def open(self,request,timeout):
                nonce=urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)['nonce'][0]
                data={'schema_version':1,'nonce':'f'*32 if self.forged else nonce,
                      'origins':{x['id']:{'healthy':True,'reason':'ok'} for x in config['origins']}}
                return Response(json.dumps(data).encode())
        with tempfile.NamedTemporaryFile() as token:
            token.write(b'a'*64);token.flush()
            self.assertIsNotNone(q.witness_vote(config,token.name,Opener()))
            self.assertIsNone(q.witness_vote(config,token.name,Opener(forged=True)))

    def test_external_witness_secret_is_only_mounted_on_publishers(self):
        self.config['witness']={'id':'external-witness','url':'https://witness.example.org/v1/probe'}
        docs=render.objects(self.config)
        for deployment in (x for x in docs if x['kind']=='Deployment'):
            component=deployment['spec']['template']['metadata']['labels']['app.kubernetes.io/component']
            volumes=deployment['spec']['template']['spec']['volumes']
            self.assertEqual(any(x['name']=='witness-token' for x in volumes),component=='publisher')
        policy=next(x for x in docs if x['kind']=='NetworkPolicy' and x['metadata']['name']=='public-dns-quorum-witness')
        self.assertEqual(policy['spec']['podSelector']['matchLabels']['app.kubernetes.io/component'],'publisher')

    def test_external_witness_rejects_insecure_or_ambiguous_urls(self):
        for url in ('http://example.com/v1/probe','https://user:password@example.com/v1/probe',
                    'https://localhost/v1/probe','https://127.0.0.1/v1/probe',
                    'https://example.com/v1/probe?other=value','https://example.com:444/v1/probe'):
            c=copy.deepcopy(self.config);c['witness']={'id':'external-witness','url':url}
            with self.subTest(url=url),self.assertRaises(ValueError):q.validate_config(c)

    def test_witness_probe_names_match_the_declared_public_origins(self):
        import yaml
        root=HERE.parents[2]
        config=json.loads((HERE/'pool.json').read_text())
        worker=tomllib.loads((root/'deploy/public-dns-witness/wrangler.toml').read_text())
        names={x['id']:x['host'] for x in json.loads(worker['vars']['WITNESS_ORIGINS'])}
        docs=list(yaml.safe_load_all((root/'deploy/gitops/envoy-gateway/public-web-dns.yaml').read_text()))
        record=next(x for x in docs if x['metadata']['name']=='heterocloud-gateway-observer-addresses')
        targets={x['dnsName']:x['targets'] for x in record['spec']['endpoints']}
        route=list(yaml.safe_load_all((root/'deploy/gitops/envoy-gateway/public-gateway-health.yaml').read_text()))[0]
        self.assertEqual(set(names),{x['id'] for x in config['origins']})
        for origin in config['origins']:
            self.assertEqual(targets[names[origin['id']]],[origin['address']])
            self.assertIn(names[origin['id']],route['spec']['hostnames'])

    def test_metrics_show_fresh_probe_latency_and_do_not_invent_witness_health(self):
        self.config['witness']={'id':'external-witness','url':'https://witness.example.org/v1/probe'}
        votes=self.votes()
        for vote in votes.values():
            for result in vote['origins'].values():result['latency_seconds']=0.125
            vote['overlay_dns']={x['id']:{'healthy':True,'reason':'ok','latency_seconds':0.01}
                                  for x in self.config['overlay_dns']['targets']}
            vote['overlay_dns_counters']={x['id']:{'attempts':8,'failures':1}
                                           for x in self.config['overlay_dns']['targets']}
        _,_,status=q.decide(self.config,votes,None,self.published,self.now)
        status['witness']={'polled':False,'available':False}
        class Api:
            def call(_,method,path):
                if path.endswith('/'+self.config['state_resource']):
                    return {'data':{'status.json':json.dumps(status)}}
                member=next(x for x in self.config['members'] if path.endswith('/'+x['vote_resource']))
                return {'data':{'vote.json':json.dumps(votes[member['id']])}}
        output=q.metrics(self.config,Api(),self.now).decode()
        self.assertIn('heteronetwork_public_dns_majority_required 3',output)
        self.assertIn('heteronetwork_public_dns_probe_duration_seconds{voter="ichikawap1",origin="ichikawap1"} 0.125',output)
        self.assertIn('heteronetwork_overlay_dns_probe_healthy{voter="ichikawap1",server="uc-k8sp5"} 1',output)
        self.assertIn('heteronetwork_overlay_dns_probe_failures_total{voter="ichikawap1",server="uc-k8sp5"} 1',output)
        self.assertNotIn('heteronetwork_public_dns_witness_available',output)
        self.assertNotIn('Bearer',output)
        status['config_digest']='stale'
        with self.assertRaises(ValueError):q.metrics(self.config,Api(),self.now)

    def test_overlay_dns_probe_checks_real_udp_response_and_rejects_wrong_id(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server.bind(('127.0.0.1',0));port=server.getsockname()[1]
        def reply():
            request,peer=server.recvfrom(1024)
            answer=(b'\xc0\x0c'+struct.pack('!HHIH',1,1,5,4)+socket.inet_aton('127.0.0.1'))
            server.sendto(request[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+request[12:]+answer,peer)
        thread=threading.Thread(target=reply,daemon=True);thread.start()
        try:
            result=q.probe_overlay_dns({'address':'127.0.0.1'},'console.heteronetwork.internal',1,port=port)
            self.assertTrue(result['healthy'])
            self.assertEqual(result['reason'],'ok')
            query=q.overlay_dns_query('console.heteronetwork.internal',123)
            malformed=struct.pack('!HHHHHH',124,0x8180,1,0,0,0)+query[12:]
            with self.assertRaises(ValueError):q.overlay_dns_answer(malformed,query,'127.0.0.1')
        finally:
            thread.join(timeout=2);server.close()

    def test_overlay_dns_health_does_not_change_public_dns_vote(self):
        votes=self.votes()
        for vote in votes.values():
            vote['overlay_dns']={x['id']:{'healthy':False,'reason':'timeout','latency_seconds':1}
                                  for x in self.config['overlay_dns']['targets']}
        _,_,status=q.decide(self.config,votes,None,self.published,self.now)
        self.assertTrue(all(x['decision']=='healthy' for x in status['origins'].values()))
        for vote in votes.values():vote['overlay_dns']={'bad':'malformed'}
        _,_,status=q.decide(self.config,votes,None,self.published,self.now)
        self.assertTrue(all(x['decision']=='healthy' for x in status['origins'].values()))
        docs=render.objects(self.config)
        policy=next(x for x in docs if x['kind']=='NetworkPolicy' and x['metadata']['name']=='public-dns-quorum-overlay-dns')
        self.assertEqual(policy['spec']['podSelector']['matchLabels']['app.kubernetes.io/component'],'voter')

    def test_overlay_dns_counters_survive_each_vote_and_ignore_bad_history(self):
        member=self.config['members'][0]
        class Api:
            def __init__(self):self.doc={'metadata':{'uid':'u','resourceVersion':'1'},'data':{}}
            def call(self,method,path,value=None,content_type=None):
                if method=='GET':return self.doc
                self.doc['data']=value[-1]['value']
        api=Api()
        def dns(target,*_):
            good=target['id']=='ichikawap1'
            return {'healthy':good,'reason':'ok' if good else 'timeout','latency_seconds':0.1}
        with patch.dict(os.environ,{'NODE_NAME':member['node']}),\
             patch.object(q,'timed_probe',return_value={'healthy':True,'reason':'ok'}),\
             patch.object(q,'probe_overlay_dns',side_effect=dns):
            q.vote_once(self.config,member['id'],api)
            q.vote_once(self.config,member['id'],api)
            stored=json.loads(api.doc['data']['vote.json'])
            self.assertEqual(stored['overlay_dns_counters']['ichikawap1'],{'attempts':2,'failures':0})
            self.assertEqual(stored['overlay_dns_counters']['uc-k8sp5'],{'attempts':2,'failures':2})
            api.doc['data']['vote.json']='[]'
            q.vote_once(self.config,member['id'],api)
            stored=json.loads(api.doc['data']['vote.json'])
            self.assertEqual(stored['overlay_dns_counters']['uc-k8sp5'],{'attempts':1,'failures':1})


if __name__=='__main__':unittest.main()
