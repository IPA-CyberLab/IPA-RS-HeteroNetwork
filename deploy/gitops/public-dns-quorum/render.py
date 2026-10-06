#!/usr/bin/env python3
"""Render the declared, least-privilege observers and publisher."""
import json
from pathlib import Path
import yaml
from controller import validate_config

IMAGE = 'python:3.13.7-bookworm@sha256:c900d35aba5fe4c1dc1cd358408baae2902ff2a2926a1d15cc5002c6061ddb2e'
APP = 'public-dns-quorum'


def objects(config):
    validate_config(config)
    namespace = config['namespace']
    def obj(kind, name, spec=None, group='v1'):
        value = {'apiVersion': group, 'kind': kind, 'metadata': {'name': name, 'namespace': namespace, 'labels': {'app.kubernetes.io/name': APP}}}
        if spec is not None: value['spec'] = spec
        return value
    def sa(name):
        value = obj('ServiceAccount', name);value['automountServiceAccountToken'] = True;return value
    def role(name, rules):
        value = obj('Role', name, group='rbac.authorization.k8s.io/v1');value['rules'] = rules;return value
    def binding(name):
        value = obj('RoleBinding', name, group='rbac.authorization.k8s.io/v1')
        value.update(roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name},subjects=[{'kind':'ServiceAccount','name':name,'namespace':namespace}]);return value
    def rule(group, resource, names, verbs):return {'apiGroups':[group], 'resources':[resource], 'resourceNames':names, 'verbs':verbs}
    def deployment(name, component, nodes, voter=None):
        labels = {'app.kubernetes.io/name':APP,'app.kubernetes.io/component':component}
        if voter:labels['dns.heterocloud.io/voter-id'] = voter
        container = {'name':component,'image':IMAGE,'imagePullPolicy':'IfNotPresent','command':['python3','-B','/config/controller.py',component],
                     'env':[{'name':'NODE_NAME','valueFrom':{'fieldRef':{'fieldPath':'spec.nodeName'}}},{'name':'POD_UID','valueFrom':{'fieldRef':{'fieldPath':'metadata.uid'}}}],
                     'resources':{'requests':{'cpu':'5m','memory':'24Mi'},'limits':{'cpu':'200m','memory':'96Mi'}},
                     'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                     'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True},{'name':'tmp','mountPath':'/tmp'}]}
        if voter:container['command'] += ['--voter-id',voter]
        for probe,file,age in [('readinessProbe','last-success',30),('livenessProbe','loop-progress',120)]:
            container[probe] = {'exec':{'command':['python3','-c',f"import os,time; assert time.time()-os.stat('/tmp/{file}').st_mtime < {age}"]},'periodSeconds':10,'timeoutSeconds':3,'failureThreshold':3}
        container['livenessProbe']['initialDelaySeconds']=30
        affinity = {'nodeAffinity':{'requiredDuringSchedulingIgnoredDuringExecution':{'nodeSelectorTerms':[{'matchExpressions':[{'key':'kubernetes.io/hostname','operator':'In','values':nodes}]}]}}}
        if component=='publisher':affinity['podAntiAffinity']={'requiredDuringSchedulingIgnoredDuringExecution':[{'topologyKey':'kubernetes.io/hostname','labelSelector':{'matchLabels':labels}}]}
        spec = {'replicas':1 if voter else 2,'selector':{'matchLabels':labels},'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':0 if voter else 1,'maxUnavailable':1 if voter else 0}},
                'template':{'metadata':{'labels':labels},'spec':{'serviceAccountName':name,'automountServiceAccountToken':True,'affinity':affinity,
                    'tolerations':[{'key':'node-role.kubernetes.io/control-plane','operator':'Exists','effect':'NoSchedule'}],
                    'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[container],'volumes':[{'name':'config','configMap':{'name':'public-dns-quorum-runtime','defaultMode':292}},{'name':'tmp','emptyDir':{'medium':'Memory','sizeLimit':'4Mi'}}]}}}
        return obj('Deployment',name,spec,'apps/v1')
    result=[]
    for member in config['members']:
        name='public-dns-voter-'+member['id']
        result += [obj('ConfigMap',member['vote_resource']),sa(name),role(name,[rule('','configmaps',[member['vote_resource']],['get','patch'])]),binding(name),deployment(name,'voter',[member['node']],member['id'])]
    name='public-dns-publisher'
    result += [obj('ConfigMap',config['state_resource']),sa(name),role(name,[rule('','configmaps',[x['vote_resource'] for x in config['members']],['get']),rule('','configmaps',[config['state_resource']],['get','patch'])]),binding(name),deployment(name,'publisher',[x['node'] for x in config['members']]),obj('PodDisruptionBudget',name,{'minAvailable':1,'selector':{'matchLabels':{'app.kubernetes.io/name':APP,'app.kubernetes.io/component':'publisher'}}},'policy/v1')]
    dnsrole=role(name+'-dns',[rule('externaldns.k8s.io','dnsendpoints',[config['dns_resource']],['get','patch'])]);dnsrole['metadata']['namespace']=config['dns_namespace']
    dnsbinding=obj('RoleBinding',name+'-dns',group='rbac.authorization.k8s.io/v1');dnsbinding['metadata']['namespace']=config['dns_namespace'];dnsbinding.update(roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name+'-dns'},subjects=[{'kind':'ServiceAccount','name':name,'namespace':namespace}])
    result += [dnsrole,dnsbinding]
    egress=[{'to':[{'ipBlock':{'cidr':'10.96.0.1/32'}},{'ipBlock':{'cidr':'10.250.0.0/24'}}],'ports':[{'protocol':'TCP','port':443},{'protocol':'TCP','port':6443}]},
            {'to':[{'ipBlock':{'cidr':x['address']+('/32' if ':' not in x['address'] else '/128')}} for x in config['origins']],'ports':[{'protocol':'TCP','port':443},{'protocol':'TCP','port':80}]}]
    result += [obj('NetworkPolicy',APP,{'podSelector':{'matchLabels':{'app.kubernetes.io/name':APP}},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':egress},'networking.k8s.io/v1')]
    return result


if __name__ == '__main__':
    here=Path(__file__).resolve().parent
    config=json.loads((here/'pool.json').read_text())
    (here/'workloads.yaml').write_text(yaml.safe_dump_all(objects(config),sort_keys=False))
