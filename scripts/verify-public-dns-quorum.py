#!/usr/bin/env python3
"""Real majority/DNS acceptance using an owned namespace and hostname.

Only fixture Pods' egress is blocked. No gateway or tenant Pod is stopped.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import yaml

ROOT=Path(__file__).resolve().parents[1]
MODULE=ROOT/'deploy/gitops/public-dns-quorum'
sys.path.insert(0,str(MODULE))
import controller as q
import render


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--dns-zone',required=True)
    parser.add_argument('--keep-on-failure',action='store_true')
    args=parser.parse_args()
    q.dns_name(args.dns_zone)
    nonce=uuid.uuid4().hex[:10]
    namespace='dns-quorum-e2e-'+nonce
    config=json.loads((MODULE/'pool.json').read_text())
    config.update(namespace=namespace,dns_namespace=namespace,dns_resource='quorum-fixture',state_resource='quorum-state',enabled=True)
    hostname='quorum-e2e-'+nonce+'.'+config['probe']['hostname'].split('.',1)[1]
    assert hostname.endswith('.'+args.dns_zone)
    config['records']=[hostname];config['probe']['hostname']=hostname
    report={'schema_version':1,'passed':False,'namespace':namespace,'hostname':hostname,'checks':[],'production_gateways_stopped':False,'tenant_pods_modified':False}
    args.output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    def save():args.output.write_text(json.dumps(report,indent=2)+'\n')
    def check(name,**details):
        report['checks'].append({'name':name,'passed':True,**details});save();print('PASS '+name,flush=True)
    def kube(*argv,body=None,success=True):
        result=subprocess.run(['kubectl','--request-timeout=15s',*argv],input=None if body is None else yaml.safe_dump_all(body,sort_keys=False),text=True,capture_output=True,timeout=25)
        if success and result.returncode:raise RuntimeError('Fixture Kubernetes operation failed')
        return result
    def get(kind,name=None):
        argv=['-n',namespace,'get',kind]+([name] if name else [])+['-o','json']
        return json.loads(kube(*argv).stdout)
    def apply(documents):kube('apply','-f','-',body=documents)
    def owned():
        value=json.loads(kube('get','namespace',namespace,'-o','json').stdout)
        assert value['metadata']['labels'].get('dns.heterocloud.io/e2e-owner')==nonce
    def status():
        data=get('configmap',config['state_resource']).get('data',{})
        return json.loads(data.get('status.json','{}'))
    def wait(predicate,seconds=150):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if predicate():return
            time.sleep(2)
        raise RuntimeError('Fixture convergence deadline exceeded')
    def target_set():return sorted(get('dnsendpoint',config['dns_resource'])['spec']['endpoints'][0]['targets'])
    ns=kube('get','namespace',namespace,'-o','json',success=False)
    assert ns.returncode!=0,'Fixture namespace already exists'
    stage='create'
    try:
        apply([{'apiVersion':'v1','kind':'Namespace','metadata':{'name':namespace,'labels':{'dns.heterocloud.io/e2e-owner':nonce}}}]);owned()
        documents=render.objects(config)
        documents += [{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'public-dns-quorum-runtime','namespace':namespace},'data':{'controller.py':(MODULE/'controller.py').read_text(),'pool.json':json.dumps(config)}}]
        documents += [{'apiVersion':'externaldns.k8s.io/v1alpha1','kind':'DNSEndpoint','metadata':{'name':config['dns_resource'],'namespace':namespace,'labels':{'dns.heterocloud.io/publish':'true'}},'spec':{'endpoints':[{'dnsName':hostname,'recordType':'A','recordTTL':60,'targets':[x['address'] for x in config['origins']],'providerSpecific':[{'name':'external-dns.alpha.kubernetes.io/cloudflare-proxied','value':'false'}]}]}}]
        health=list(yaml.safe_load_all((ROOT/'deploy/gitops/envoy-gateway/public-gateway-health.yaml').read_text()))
        for doc in health:
            doc['metadata']['namespace']=namespace
            if doc['kind']=='HTTPRoute':doc['spec']['hostnames']=[hostname]
        documents += health
        apply(documents)
        stage='initial_ready'
        wait(lambda:len(get('pods')['items'])==5 and all(any(c['type']=='Ready' and c['status']=='True' for c in x.get('status',{}).get('conditions',[])) for x in get('pods')['items']))
        wait(lambda:status().get('fresh_voters')==3 and all(x['decision']=='healthy' and x['streak']>=2 for x in status().get('origins',{}).values()))
        nodes={x['metadata']['labels']['dns.heterocloud.io/voter-id']:x['spec']['nodeName'] for x in get('pods')['items'] if x['metadata']['labels'].get('app.kubernetes.io/component')=='voter'}
        assert len(set(nodes.values()))==3
        check('three_real_distinct_voters_validate_both_public_https_origins',nodes=nodes)
        for member in config['members']:
            subject='system:serviceaccount:'+namespace+':public-dns-voter-'+member['id']
            for resource,allowed in [('configmap/'+member['vote_resource'],True),('configmap/'+config['state_resource'],False),('secrets',False)]:
                result=kube('auth','can-i','patch',resource,'-n',namespace,'--as='+subject,success=False)
                assert (result.stdout.strip()=='yes')==allowed
            other=next(x for x in config['members'] if x['id']!=member['id'])
            assert kube('auth','can-i','patch','configmap/'+other['vote_resource'],'-n',namespace,'--as='+subject,success=False).stdout.strip()=='no'
        check('real_rbac_prevents_voters_from_writing_each_others_votes')
        nameservers=subprocess.check_output(['dig','+short',args.dns_zone,'NS'],text=True,timeout=10).splitlines()
        assert nameservers
        def dns():
            values=subprocess.check_output(['dig','+time=2','+tries=1','+short','@'+nameservers[0],hostname,'A'],text=True,timeout=5).splitlines()
            return sorted(x.strip() for x in values if x.strip())
        both=sorted(x['address'] for x in config['origins'])
        wait(lambda:dns()==both)
        check('authoritative_dns_publishes_both_healthy_origins')
        # Additional policies are additive. Replace the fixture's broad policy
        # with per-voter policies before trying to isolate a single observer.
        base=next(x for x in documents if x['kind']=='NetworkPolicy')
        def policies(blocked):
            result=[]
            for member in config['members']:
                value=copy.deepcopy(base);value['metadata']['name']='voter-'+member['id']
                value['spec']['podSelector']['matchLabels'].update({'app.kubernetes.io/component':'voter','dns.heterocloud.io/voter-id':member['id']})
                allowed=[x for x in config['origins'] if x['id'] not in blocked.get(member['id'],[])]
                value['spec']['egress']=value['spec']['egress'][:1]+([{'to':[{'ipBlock':{'cidr':x['address']+'/32'}} for x in allowed],'ports':[{'protocol':'TCP','port':80},{'protocol':'TCP','port':443}]}] if allowed else [])
                result.append(value)
            value=copy.deepcopy(base);value['metadata']['name']='publisher'
            value['spec']['podSelector']['matchLabels']['app.kubernetes.io/component']='publisher';value['spec']['egress']=value['spec']['egress'][:1];result.append(value)
            apply(result)
        policies({});kube('-n',namespace,'delete','networkpolicy',render.APP)
        # The first origin can be unreachable from its own node because of
        # upstream NAT hairpin rules. Choose an origin every voter currently
        # reaches, so isolating one observer actually adds exactly one failure.
        votes=[json.loads(get('configmap',m['vote_resource'])['data']['vote.json']) for m in config['members']]
        victim=next(o for o in config['origins'] if all(v['origins'][o['id']]['healthy'] for v in votes))
        survivor=next(o for o in config['origins'] if o['id']!=victim['id'])
        first,second=config['members'][:2]
        stage='isolated_voter'
        start=time.time();policies({first['id']:[victim['id']]})
        wait(lambda:status().get('observed_at',0)>=start+15 and status().get('origins',{}).get(victim['id'],{}).get('unhealthy_votes')==1)
        assert target_set()==both and dns()==both
        check('one_isolated_observer_cannot_remove_a_healthy_gateway')
        stage='majority_withdrawal'
        start=time.monotonic();policies({first['id']:[victim['id']],second['id']:[victim['id']]})
        wait(lambda:target_set()==[survivor['address']])
        wait(lambda:dns()==[survivor['address']])
        check('real_majority_failure_removes_only_the_failed_origin_from_public_dns',convergence_ms=round((time.monotonic()-start)*1000))
        stage='all_down'
        policies({m['id']:[x['id'] for x in config['origins']] for m in config['members']})
        wait(lambda:status().get('all_down_retained') is True)
        assert target_set()==[survivor['address']] and dns()==[survivor['address']]
        check('complete_probe_failure_retains_dns_and_reports_all_down')
        stage='quorum_loss'
        for member in config['members'][:2]:kube('-n',namespace,'scale','deployment/public-dns-voter-'+member['id'],'--replicas=0')
        wait(lambda:status().get('fresh_voters')==1,seconds=90)
        assert target_set()==[survivor['address']] and dns()==[survivor['address']]
        check('lost_majority_keeps_last_dns_without_reducing_vote_threshold')
        stage='recovery'
        policies({})
        for member in config['members'][:2]:kube('-n',namespace,'scale','deployment/public-dns-voter-'+member['id'],'--replicas=1')
        wait(lambda:target_set()==both and status().get('fresh_voters')==3)
        wait(lambda:dns()==both)
        check('recovered_gateways_are_automatically_readded_to_authoritative_dns')
        stage='publisher_failover'
        lease=json.loads(get('configmap',config['state_resource'])['data']['lease.json'])
        leader=next(x for x in get('pods')['items'] if x['metadata']['uid']==lease['owner'])
        assert leader['metadata']['labels']['app.kubernetes.io/component']=='publisher'
        owned();kube('-n',namespace,'delete','pod',leader['metadata']['name'],'--wait=false')
        def fenced_new_writer():
            new_owner=json.loads(get('configmap',config['state_resource']).get('data',{}).get('lease.json','{}')).get('owner')
            return new_owner not in (None,lease['owner']) and get('dnsendpoint',config['dns_resource'])['metadata'].get('annotations',{}).get('dns.heterocloud.io/quorum-writer')==new_owner
        wait(fenced_new_writer)
        assert target_set()==both and dns()==both
        check('publisher_failover_preserves_dns_and_fences_old_writer')
        report['passed']=True;report['observed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());save()
    except Exception:
        report['failure_stage']=stage;save();print('Public DNS quorum verification failed at '+stage+'; credentials are excluded',file=sys.stderr)
        raise SystemExit(1)
    finally:
        if report['passed'] or not args.keep_on_failure:
            owned()
            kube('-n',namespace,'delete','dnsendpoint',config['dns_resource'],'--ignore-not-found','--wait=true')
            # Wait for ExternalDNS to remove the fixture's TXT ownership record.
            if 'nameservers' in locals():
                txt='_heterocloud-'+hostname
                wait(lambda:not subprocess.check_output(['dig','+time=2','+tries=1','+short','@'+nameservers[0],txt,'TXT'],text=True,timeout=5).strip(),seconds=90)
            kube('delete','namespace',namespace,'--wait=false');report['fixture_removed']=True;save()


if __name__=='__main__':main()
