#!/usr/bin/env python3
"""Safely spread an already healthy public gateway after a worker returns."""
import datetime
import json
import os
from pathlib import Path
import ssl
import time
import urllib.parse
import urllib.request

ROOT = Path('/var/run/secrets/kubernetes.io/serviceaccount')
NAMESPACE = 'envoy-gateway-system'
DEPLOYMENT = 'envoy-heterocloud-edge-heterocloud-edge-dd522bfb'
NODES = ('ichikawap1', 'uc-k8sp5')
SELECTOR = 'gateway.envoyproxy.io/owning-gateway-name=heterocloud-edge,app.kubernetes.io/component=proxy'


def timestamp(value):
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def candidate(deployment, pdb, pods, nodes, leases, quorum, now):
    """Return a single UID-fenced candidate only when all safety gates pass."""
    try:
        if deployment['metadata']['name'] != DEPLOYMENT or deployment['spec']['replicas'] != 5:
            return None
        status = deployment['status']
        if (status.get('observedGeneration', 0) < deployment['metadata']['generation'] or
            any(status.get(key) != 5 for key in ('replicas','readyReplicas','updatedReplicas','availableReplicas')) or
            pdb.get('status', {}).get('disruptionsAllowed', 0) < 1):
            return None
        constraints = deployment['spec']['template']['spec'].get('topologySpreadConstraints', [])
        if not any(x.get('topologyKey') == 'kubernetes.io/hostname' and x.get('maxSkew') == 1 and
                   x.get('whenUnsatisfiable') == 'DoNotSchedule' and x.get('nodeTaintsPolicy') == 'Honor' and
                   x.get('nodeAffinityPolicy') == 'Honor'
                   for x in constraints):
            return None
        if (not quorum.get('enabled') or now - quorum['observed_at'] > 30 or
            quorum['observed_at'] > now + 3 or quorum['fresh_voters'] < quorum['majority_required']):
            return None
        if len(set(quorum['published_targets'])) != 2 or set(quorum['origins']) != set(NODES) or any(
            quorum['origins'][name]['decision'] != 'healthy' or not quorum['origins'][name]['active']
            for name in NODES):
            return None
        for name in NODES:
            node = nodes[name]
            labels = node['metadata'].get('labels', {})
            if node['spec'].get('unschedulable') or labels.get('heteronetwork.io/control-plane-only') == 'true':
                return None
            if labels.get('networking.heteronetwork.io/public-ingress') != 'true' and labels.get('networking.heteronetwork.io/public-ingress-candidate') != 'true':
                return None
            if any(t.get('effect') == 'NoSchedule' and t.get('key') != 'node-role.kubernetes.io/control-plane'
                   or t.get('effect') == 'NoExecute' for t in node['spec'].get('taints', [])):
                return None
            ready = next(c for c in node['status']['conditions'] if c['type'] == 'Ready')
            if ready['status'] != 'True' or now - timestamp(ready['lastTransitionTime']) < 120:
                return None
            age = now - timestamp(leases[name]['spec']['renewTime'])
            if not -3 <= age <= 30:
                return None
        active = [p for p in pods if p['status'].get('phase') not in ('Succeeded','Failed')]
        if len(active) != 5:
            return None
        counts = {name:[] for name in NODES}
        for pod in active:
            meta = pod['metadata']
            node = pod['spec'].get('nodeName')
            if (meta.get('deletionTimestamp') or node not in counts or not meta['name'].startswith(DEPLOYMENT+'-') or
                not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod['status'].get('conditions', [])) or
                not any(o.get('kind') == 'ReplicaSet' and o.get('controller') is True and
                        o.get('name', '').startswith(DEPLOYMENT+'-') for o in meta.get('ownerReferences', []))):
                return None
            counts[node].append({'name':meta['name'], 'uid':meta['uid']})
        largest, smallest = sorted(NODES, key=lambda n:len(counts[n]), reverse=True)
        if len(counts[largest]) - len(counts[smallest]) <= 1:
            return None
        return sorted(counts[largest], key=lambda p:p['name'])[0]
    except (KeyError, ValueError, TypeError, StopIteration):
        return None


class Kubernetes:
    def __init__(self):
        host, port = os.environ['KUBERNETES_SERVICE_HOST'], os.environ['KUBERNETES_SERVICE_PORT_HTTPS']
        self.base = f'https://[{host}]:{port}' if ':' in host else f'https://{host}:{port}'
        context = ssl.create_default_context(cafile=str(ROOT/'ca.crt'))
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs): return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=context))

    def call(self, method, path, data=None):
        headers = {'Authorization':'Bearer '+(ROOT/'token').read_text().strip(), 'Accept':'application/json'}
        payload = None if data is None else json.dumps(data).encode()
        if payload is not None: headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.base+path, method=method, headers=headers, data=payload)
        with self.opener.open(request, timeout=5) as response:
            raw = response.read(4*1024*1024+1)
        if len(raw) > 4*1024*1024: raise ValueError('inventory too large')
        return json.loads(raw)


def main():
    api = Kubernetes()
    try:
        deploy = api.call('GET',f'/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{DEPLOYMENT}')
        pdb = api.call('GET',f'/apis/policy/v1/namespaces/{NAMESPACE}/poddisruptionbudgets/{DEPLOYMENT}')
        query = urllib.parse.urlencode({'labelSelector':SELECTOR})
        pods = api.call('GET',f'/api/v1/namespaces/{NAMESPACE}/pods?{query}')['items']
        nodes = {name:api.call('GET','/api/v1/nodes/'+name) for name in NODES}
        leases = {name:api.call('GET','/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/'+name)
                  for name in NODES}
        status = api.call('GET','/api/v1/namespaces/heterocloud-dns/configmaps/public-dns-quorum-state')
        quorum = json.loads(status['data']['status.json'])
        target = candidate(deploy,pdb,pods,nodes,leases,quorum,time.time())
        if not target:
            print(json.dumps({'result':'no_safe_rebalance_needed'}))
            return 0
        body = {'apiVersion':'policy/v1','kind':'Eviction',
                'metadata':{'name':target['name'],'namespace':NAMESPACE},
                'deleteOptions':{'preconditions':{'uid':target['uid']}}}
        api.call('POST',f'/api/v1/namespaces/{NAMESPACE}/pods/{target["name"]}/eviction',body)
        print(json.dumps({'result':'evicted_one_gateway_pod','pod':target['name']}))
        return 0
    except Exception:
        # No request headers, Kubernetes tokens, or response bodies in logs.
        print(json.dumps({'result':'rebalance_check_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
