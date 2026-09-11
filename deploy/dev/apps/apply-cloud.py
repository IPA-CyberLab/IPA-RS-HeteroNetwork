#!/usr/bin/env python3
"""Initial Cloud deployment from the verified revision16 isolated DEV bundle."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit

sys.dont_write_bytecode = True
import capacity

NS = 'heterocloud-dev'
STAMP = '3a6fb8239f19638765825c6363d5553beb317ebbf68ce88ed72faf30aa846011'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'
MANAGER = 'hetero-dev-runtime'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud:0.1.71-dev.5@sha256:70a41870b9e5c986512f2665bceb5a4d079dd7e1e0958ac36751b95e7928b9b3'
EXPECTED = {(kind, NS + suffix) for kind in ('NetworkPolicy', 'PodDisruptionBudget', 'Deployment')
            for suffix in ('', '-owner-console', '-worker')} | {
                ('ServiceAccount', NS), ('Service', NS), ('Service', NS + '-owner-console')}


def require(condition):
    if not condition:
        raise ValueError('DEV Cloud admission rejected')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select(document):
    require(document.get('kind') == 'List')
    items = document['items']
    require(len(items) == len(EXPECTED)
            and {(x['kind'], x['metadata']['name']) for x in items} == EXPECTED)
    for item in items:
        require(item['metadata'].get('namespace') == NS)
        if item['kind'] == 'Deployment':
            pod = item['spec']['template']['spec']
            require(item['spec']['replicas'] == 3 and len(pod['containers']) == 1
                    and pod['containers'][0]['image'] == IMAGE and not pod.get('initContainers')
                    and not pod.get('hostNetwork') and pod.get('automountServiceAccountToken') is False
                    and pod['serviceAccountName'] == NS
                    and pod['securityContext']['runAsNonRoot'] is True
                    and pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'])
            args = pod['containers'][0]['args']
            require('--database-url-file=/var/run/secrets/runtime/database-url' in args
                    and not any(arg.startswith('--bootstrap-') for arg in args))
        elif item['kind'] == 'NetworkPolicy':
            require(item['spec']['podSelector']['matchLabels']['app.kubernetes.io/instance'] == NS)
        elif item['kind'] == 'Service':
            require(item['spec']['type'] == 'ClusterIP' and not item['spec'].get('externalIPs'))
        elif item['kind'] == 'ServiceAccount':
            require(item.get('automountServiceAccountToken') is False)
    return sorted(items, key=lambda x: (x['kind'] == 'Deployment', x['metadata']['name']))


def runtime_contains(actual, desired, compare):
    actual = copy.deepcopy(actual)
    if desired['kind'] == 'Deployment' and isinstance(actual, dict):
        got = actual.get('spec', {}).get('template', {}).get('spec', {})
        wanted = desired['spec']['template']['spec']
        # PodSpec.hostNetwork is omitted by the API when false.
        if wanted.get('hostNetwork') is False and 'hostNetwork' not in got:
            got['hostNetwork'] = False
    return compare(actual, desired)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    helper = load('identity_apply', path)
    helper.guard()
    raw = helper.trusted_file(args.bundle / 'manifest.json', 1048576)
    require(hashlib.sha256(raw).hexdigest() == STAMP)
    manifest = json.loads(raw)
    filename = NS + '.json'
    raw = helper.trusted_file(args.bundle / filename, 2097152)
    require(hashlib.sha256(raw).hexdigest() == manifest['files'][filename])
    items = select(json.loads(raw))
    garage = Path(__file__).with_name('apply-garage.py')
    require(hashlib.sha256(helper.trusted_file(garage, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    compare = load('garage_apply', garage).contains
    contains = lambda actual, desired: runtime_contains(actual, desired, compare)

    def get(kind, name=None, namespace=NS):
        command = ['get', kind] + ([name] if name else []) + (['-n', namespace] if namespace else [])
        raw = helper.run([*command, '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    require(get('namespace', NS, None)['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    require(get('cluster.postgresql.cnpg.io', 'dev-postgres')['status']['readyInstances'] == 3)
    for namespace, deployment in [('hetero-dev-identity', 'dev-keycloak'),
                                 ('heterocloud-flow-dev', 'heterocloud-flow-dev-api'),
                                 ('heterocloud-syouyu-dev', 'heterocloud-syouyu-dev-api')]:
        require(get('deployment', deployment, namespace)['status'].get('availableReplicas') == 3)
    needed = []
    for item in items:
        if item['kind'] != 'Deployment':
            continue
        pod = item['spec']['template']['spec']
        for volume in pod['volumes']:
            ref = volume.get('secret')
            if ref:
                data = get('secret', ref['secretName'])['data']
                entries = ref.get('items')
                if entries is None:
                    require(ref['secretName'] == NS + '-tls' and set(data) == {'tls.crt', 'tls.key'})
                    entries = [{'key': key} for key in ('tls.crt', 'tls.key')]
                for entry in entries:
                    value = base64.b64decode(data[entry['key']], validate=True)
                    require(value)
                    if entry['key'] == 'database-url':
                        url = urlsplit(value.decode())
                        require(url.scheme == 'postgresql' and url.hostname == f'dev-postgres-rw.{NS}.svc.cluster.local'
                                and url.path == '/heterocloud_dev' and url.username == 'heterocloud_dev'
                                and parse_qs(url.query).get('sslmode') == ['verify-full'])
        for env in pod['containers'][0].get('env', []):
            ref = env.get('valueFrom', {}).get('secretKeyRef')
            if ref:
                require(base64.b64decode(get('secret', ref['name'])['data'][ref['key']], validate=True))
        if not get('deployment', item['metadata']['name']):
            needed.append(capacity.pod_requests(pod))
    pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
    for node in get('nodes', namespace=None)['items']:
        allocated = [capacity.pod_requests(p['spec']) for p in pods
                     if p['spec'].get('nodeName') == node['metadata']['name']
                     and p['status'].get('phase') not in ('Succeeded', 'Failed')]
        require(all(capacity.quantity(node['status']['allocatable'][key]) - sum(p[key] for p in allocated)
                    >= sum(p[key] for p in needed) for key in ('cpu', 'memory')))
    for item in items:
        item['metadata']['annotations'] = {**(item['metadata'].get('annotations') or {}), ANNOTATION: STAMP}
        actual = get(item['kind'], item['metadata']['name'])
        if actual:
            require(actual['metadata'].get('annotations', {}).get(ANNOTATION) == STAMP
                    and not actual['metadata'].get('deletionTimestamp') and contains(actual, item)
                    and any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
    command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
    for item in items:
        helper.run([*command, '--dry-run=server'], data=json.dumps(item).encode())
    print(json.dumps({'admitted': True, 'resources': len(items), 'apply': args.apply}), flush=True)
    if args.apply:
        for item in items:
            helper.guard()
            helper.run(command, data=json.dumps(item).encode())
            require(contains(get(item['kind'], item['metadata']['name']), item))
            if item['kind'] == 'Deployment':
                helper.run(['rollout', 'status', 'deployment/' + item['metadata']['name'], '-n', NS, '--timeout=100s'])
        print(json.dumps({'applied': True, 'rollouts_complete': True, 'oidc_login_verified': False}), flush=True)


if __name__ == '__main__':
    main()
