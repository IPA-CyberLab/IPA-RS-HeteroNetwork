#!/usr/bin/env python3
"""Render the GitOps node inventory from Terraform's public host inventory."""
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from node_lifecycle import stopped_hosts

roster = json.loads((Path(__file__).parent / 'overlay-boot-peers.json').read_text())
stopped = stopped_hosts(roster)


def apply_lifecycle(resources):
    for resource in resources:
        name = resource['metadata']['name']
        if name not in stopped:
            continue
        if resource['apiVersion'] == 'v1' and resource['kind'] == 'Node':
            labels = resource['metadata'].setdefault('labels', {})
            labels['heteronetwork.io/lifecycle'] = 'stopped'
            for key in ['networking.heteronetwork.io/public-ingress', 'database.heteronetwork.io/proxy-ready',
                        'monitoring.heteronetwork.io/ha', 'networking.heteronetwork.io/overlay-dns-sync',
                        'flash.heterocloud.io/gvisor-ready']:
                labels[key] = 'false'
            resource['metadata'].setdefault('annotations', {}).update({
                'networking.heteronetwork.io/public-ingress-enabled': 'false',
                'heteronetwork.io/lifecycle-reason': roster['node_states'][name]['reason']})
            resource.setdefault('spec', {})['unschedulable'] = True
        elif resource['apiVersion'].startswith('longhorn.io/') and resource['kind'] == 'Node':
            resource['spec']['allowScheduling'] = False
            for disk in resource['spec'].get('disks', {}).values():
                disk['allowScheduling'] = False
    return resources

nodes = json.loads((Path(__file__).parent / 'nodes.json').read_text())
resources = []
for name, node in nodes.items():
    resources.append({
        'apiVersion': 'v1', 'kind': 'Node',
        'metadata': {'name': name, 'labels': {
            'kubernetes.io/hostname': name,
            'node-role.kubernetes.io/control-plane': '',
            'node.kubernetes.io/exclude-from-external-load-balancers': '',
            'heteronetwork.io/control-plane-only': 'true',
            'networking.heteronetwork.io/public-ingress': 'false'},
            'annotations': {
                'networking.heteronetwork.io/public-ingress-enabled': 'false',
                'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false',
                'argocd.argoproj.io/sync-wave': '0'}},
        'spec': {'unschedulable': False}})
    resources.append({
        'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Node',
        'metadata': {'name': name, 'namespace': 'longhorn-system', 'annotations': {
            'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false',
            'argocd.argoproj.io/sync-wave': '0'}},
        'spec': {'allowScheduling': False}})
dest = ROOT / 'deploy/gitops/control-plane-only'
(dest / 'nodes.yaml').write_text(yaml.safe_dump_all(apply_lifecycle(resources),sort_keys=False))
policies = list(yaml.safe_load_all((ROOT / 'deploy/kubernetes/control-plane-only-policy.yaml').read_text()))
for policy in policies:
    policy['metadata'].setdefault('annotations', {})['argocd.argoproj.io/sync-wave'] = '-3' if policy['kind']=='ValidatingAdmissionPolicy' else '-2'
(dest / 'placement-policy.yaml').write_text(yaml.safe_dump_all(policies,sort_keys=False))

standard=json.loads((Path(__file__).parent/'standard-nodes.json').read_text())
edge_nodes=json.loads((Path(__file__).parent/'edge-nodes.json').read_text())
standard_dest=ROOT/'deploy/gitops/standard-nodes'
standard_dest.mkdir(exist_ok=True)
standard_resources=[]
for name in standard:
    standard_resources.append({'apiVersion':'v1','kind':'Node','metadata':{'name':name,
        'labels':{'kubernetes.io/hostname':name,'node-role.kubernetes.io/control-plane':'',
                  'heteronetwork.io/control-plane-only':'false','networking.heteronetwork.io/public-ingress':'true',
                  'database.heteronetwork.io/proxy-ready':'true','monitoring.heteronetwork.io/ha':'true',
                  'networking.heteronetwork.io/overlay-dns-sync':'true'},
        'annotations':{'networking.heteronetwork.io/public-ingress-enabled':'true',
                       'argocd.argoproj.io/sync-options':'Prune=false,Delete=false','argocd.argoproj.io/sync-wave':'0'}},
        'spec':{'unschedulable':False}})
    standard_resources.append({'apiVersion':'longhorn.io/v1beta2','kind':'Node',
        'metadata':{'name':name,'namespace':'longhorn-system','annotations':{
            'argocd.argoproj.io/sync-options':'Prune=false,Delete=false','argocd.argoproj.io/sync-wave':'0'}},
        'spec':{'name':name,'allowScheduling':True,'disks':{'iac-default-disk':{
            'path':'/var/lib/longhorn','diskType':'filesystem','allowScheduling':True,
            'evictionRequested':False,'storageReserved':68719476736,'tags':[]}}}})
for edge in ('bootstrap', 'enrollment_issuer'):
    name=edge_nodes[edge]['name']
    standard_resources.append({'apiVersion':'v1','kind':'Node','metadata':{'name':name,
        'labels':{'monitoring.heteronetwork.io/ha':'true',
                  'networking.heteronetwork.io/overlay-dns-sync':'true'},
        'annotations':{'argocd.argoproj.io/sync-options':'Prune=false,Delete=false',
                       'argocd.argoproj.io/sync-wave':'0'}}})
(standard_dest/'nodes.yaml').write_text(yaml.safe_dump_all(apply_lifecycle(standard_resources),sort_keys=False))
