#!/usr/bin/env python3
"""Verify dedicated master placement against the live Kubernetes API."""
import argparse
import copy
import datetime
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
NODES=json.loads((ROOT/'deploy/terraform/master-only/nodes.json').read_text())
REQUIRED={('node-role.kubernetes.io/control-plane','','NoSchedule'),
          ('heteronetwork.io/control-plane-only','true','NoSchedule'),
          ('heteronetwork.io/control-plane-only','true','NoExecute')}


def k(args,obj=None,check=True):
    return subprocess.run(['kubectl','--request-timeout=15s',*args],input=None if obj is None else json.dumps(obj),text=True,capture_output=True,check=check,timeout=25)


def get(resource,*args):
    return json.loads(k(['get',resource,*args,'-o','json']).stdout)


def dry(obj,replace=False):
    return json.loads(k(['replace' if replace else 'create','--dry-run=server','-f','-','-o','json'],obj).stdout)


def taints(obj):
    return {(t['key'],t.get('value',''),t['effect']) for t in obj['spec'].get('taints',[])}


def excluded(terms):
    return bool(terms) and all(any(e.get('key')=='heteronetwork.io/control-plane-only' and e.get('operator')=='NotIn' and 'true' in e.get('values',[]) for e in t.get('matchExpressions',[])) for t in terms)


def exercise():
    ns='hnn-master-iac-check-'+str(int(time.time()))
    k(['create','-f','-'],{'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}})
    tests=[]
    try:
        for index,name in enumerate(NODES):
            pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'direct-'+str(index),'namespace':ns},'spec':{'nodeName':name,'tolerations':[{'operator':'Exists'}],'containers':[{'name':'test','image':'busybox:1.37','command':['sleep','300']}]}}
            result=k(['create','-f','-'],pod,check=False)
            assert result.returncode and 'heteronetwork-control-plane-only-pods' in result.stderr,result.stderr
            tests.append({'node':name,'direct_node_name_rejected':True})
            pod['metadata']['name']='binding-'+str(index)
            del pod['spec']['nodeName']
            pod['spec']['schedulerName']='hnn-iac-verification-no-scheduler'
            k(['create','-f','-'],pod)
            binding={'apiVersion':'v1','kind':'Binding','metadata':pod['metadata'],'target':{'apiVersion':'v1','kind':'Node','name':name}}
            result=k(['create','--raw=/api/v1/namespaces/'+ns+'/pods/'+pod['metadata']['name']+'/binding','-f','-'],binding,check=False)
            assert result.returncode and 'heteronetwork-control-plane-only-bindings' in result.stderr,result.stderr
            tests[-1]['binding_rejected']=True
        fixture={'apiVersion':'apps/v1','kind':'DaemonSet','metadata':{'name':'affinity-check','namespace':ns},'spec':{'selector':{'matchLabels':{'app':'hnn-iac-check'}},'template':{'metadata':{'labels':{'app':'hnn-iac-check'}},'spec':{'nodeSelector':{'hnn-iac-check':'no-node-has-this-label'},'tolerations':[{'operator':'Exists'}],'containers':[{'name':'test','image':'busybox:1.37'}]}}}}
        obj=dry(fixture)
        terms=obj['spec']['template']['spec']['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms']
        assert excluded(terms)
        original=[{'matchExpressions':[{'key':'kubernetes.io/hostname','operator':'In','values':['uc-k8sp5']}],'matchFields':[{'key':'metadata.name','operator':'In','values':['uc-k8sp5']}]},
                  {'matchExpressions':[{'key':'kubernetes.io/hostname','operator':'In','values':['ichikawap1']}]}]
        fixture['spec']['template']['spec']['affinity']={'nodeAffinity':{'requiredDuringSchedulingIgnoredDuringExecution':{'nodeSelectorTerms':original}}}
        obj=dry(fixture)
        terms=obj['spec']['template']['spec']['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms']
        assert len(terms)==2 and excluded(terms)
        for actual,before in zip(terms,original):
            assert all(e in actual['matchExpressions'] for e in before['matchExpressions'])
            assert actual.get('matchFields',[])==before.get('matchFields',[])
        node=get('node',next(iter(NODES)))
        node.pop('status',None)
        node['metadata'].pop('managedFields',None)
        node['spec']['unschedulable']=False
        kept=[t for t in node['spec']['taints'] if (t['key'],t.get('value',''),t['effect']) not in REQUIRED]
        node['spec']['taints']=kept
        obj=dry(node,replace=True)
        assert obj['spec']['unschedulable'] is True and REQUIRED<=taints(obj)
        assert all(t in obj['spec']['taints'] for t in kept)
        network=[]
        for namespace,name in [('kube-system','kube-proxy'),('kube-flannel','kube-flannel-ds')]:
            ds=get('daemonset',name,'-n',namespace)
            ds.pop('status',None)
            ds['metadata'].pop('managedFields',None)
            ds['spec']['template']['spec']['tolerations']=[t for t in ds['spec']['template']['spec'].get('tolerations',[]) if t.get('key')!='heteronetwork.io/control-plane-only']
            obj=dry(ds,replace=True)
            own=[t for t in obj['spec']['template']['spec']['tolerations'] if t.get('key')=='heteronetwork.io/control-plane-only']
            assert len(own)==2 and {t.get('effect') for t in own}=={'NoExecute','NoSchedule'} and all(t.get('value')=='true' for t in own)
            network.append(namespace+'/'+name)
        return {'placement_negative_tests':tests,'daemonset_affinity_create_and_or_preservation':True,'node_cordon_and_taints_restore_preserving_controller_taints':True,'network_tolerations_restore':network}
    finally:
        k(['delete','namespace',ns,'--wait=false'],check=False)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--exercise-admission',action='store_true')
    parser.add_argument('--output')
    args=parser.parse_args()
    pods=get('pods','-A')['items']
    report={'checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nodes':[]}
    for name,host in NODES.items():
        node=get('node',name)
        assert node['spec'].get('unschedulable') is True and REQUIRED<=taints(node),name
        assert node['metadata']['labels'].get('heteronetwork.io/control-plane-only')=='true',name
        assert 'node-role.kubernetes.io/control-plane' in node['metadata']['labels'],name
        assert any(c['type']=='Ready' and c['status']=='True' for c in node['status']['conditions']),name
        assert any(a['type']=='InternalIP' and a['address']==host['vpn_ip'] for a in node['status']['addresses']),name
        selected=[p for p in pods if p['spec'].get('nodeName')==name]
        assert len(selected)==6,(name,'unexpected Pod count',len(selected))
        rows=[]
        for pod in selected:
            ns=pod['metadata']['namespace'];pn=pod['metadata']['name']
            cp=ns=='kube-system' and pn in [prefix+'-'+name for prefix in ['etcd','kube-apiserver','kube-controller-manager','kube-scheduler']] and bool(pod['metadata'].get('annotations',{}).get('kubernetes.io/config.mirror'))
            network=(ns=='kube-system' and pn.startswith('kube-proxy-')) or (ns=='kube-flannel' and pn.startswith('kube-flannel-ds-'))
            assert cp or network,(name,'unexpected workload',ns,pn)
            cs=pod['status'].get('containerStatuses',[])
            assert pod['status']['phase']=='Running' and len(cs)==len(pod['spec']['containers']) and all(c['ready'] for c in cs),(name,pn,'not Ready')
            rows.append({'namespace':ns,'name':pn,'ready':True})
        assert get('nodes.longhorn.io',name,'-n','longhorn-system')['spec']['allowScheduling'] is False
        report['nodes'].append({'name':name,'vpn_ip':host['vpn_ip'],'ready':True,'unschedulable':True,'essential_pods':rows,'application_or_storage_pods':0})
    app=get('application','control-plane-only','-n','argocd')
    assert app['spec']['syncPolicy']['automated']['selfHeal'] is True
    assert app['status']['sync']['status']=='Synced' and app['status']['health']['status']=='Healthy',app.get('status')
    report['argocd']={'sync':'Synced','health':'Healthy','revision':app['status']['sync']['revision']}
    for name in ['heteronetwork-control-plane-only-pods','heteronetwork-control-plane-only-bindings']:
        policy=get('validatingadmissionpolicy',name)
        assert not policy.get('status',{}).get('typeChecking',{}).get('expressionWarnings',[])
    if args.exercise_admission: report['admission']=exercise()
    report['passed']=True
    if args.output:
        path=Path(args.output)
        path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        path.chmod(0o600)
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__': main()
