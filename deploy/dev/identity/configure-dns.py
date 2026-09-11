#!/usr/bin/env python3
"""CAS update of the inspected isolated DEV CoreDNS configuration only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HOST = 'id.dev.heterocloud.mizuame.app'
SERVICE = 'dev-keycloak.hetero-dev-identity.svc.cluster.local'
BASELINE = '''.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
       max_concurrent 1000
    }
    cache 30 {
       disable success cluster.local
       disable denial cluster.local
    }
    loop
    reload
    loadbalance
}
'''
DESIRED = BASELINE.replace('    ready\n', f'    ready\n    rewrite name exact {HOST} {SERVICE}\n')


def patch_for(document):
    metadata = document['metadata']
    if (document.get('kind') != 'ConfigMap' or metadata.get('name') != 'coredns'
            or metadata.get('namespace') != 'kube-system'
            or metadata.get('uid') != 'e3077db4-e987-4159-83e2-423ff31299c9'
            or not metadata.get('resourceVersion')
            or document.get('data') not in ({'Corefile': BASELINE}, {'Corefile': DESIRED})):
        raise ValueError('Unexpected DEV CoreDNS identity or configuration; refusing overwrite')
    if document['data']['Corefile'] == DESIRED:
        return []
    return [
        {'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']},
        {'op': 'test', 'path': '/data', 'value': {'Corefile': BASELINE}},
        {'op': 'replace', 'path': '/data/Corefile', 'value': DESIRED},
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    source = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(source.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV identity guard')
    spec = importlib.util.spec_from_file_location('identity_apply', source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    service = json.loads(helper.run(['get', 'service', 'dev-keycloak', '-n', 'hetero-dev-identity', '-o', 'json']))
    helper.require(service['spec']['type'] == 'ClusterIP'
                   and service['spec']['selector'] == {'app.kubernetes.io/name': 'keycloak'}
                   and service['spec']['ports'][0]['port'] == 443)
    get = ['get', 'configmap', 'coredns', '-n', 'kube-system', '-o', 'json']
    operations = patch_for(json.loads(helper.run(get)))
    if operations:
        command = ['patch', 'configmap', 'coredns', '-n', 'kube-system', '--type=json',
                   '--patch', json.dumps(operations)]
        helper.run([*command, '--dry-run=server', '-o', 'name'])
        if args.apply:
            helper.guard()
            helper.run(command)
            helper.require(not patch_for(json.loads(helper.run(get))))
    print(json.dumps({'cluster_uid': helper.UID, 'changed': bool(operations) and args.apply,
                      'change_required': bool(operations), 'apply_requested': args.apply,
                      'dns_query_verified': False, 'workload_restart_requested': False}))


if __name__ == '__main__':
    main()
