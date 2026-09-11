#!/usr/bin/env python3
"""Deploy the selected Flash control plane only into the identified DEV cluster."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capacity

NS = 'heterocloud-flash-dev'
WORKLOADS = NS + '-workloads'
STAMP = '3a6fb8239f19638765825c6363d5553beb317ebbf68ce88ed72faf30aa846011'
MANAGER = 'hetero-dev-runtime'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:0.1.30-dev.1@sha256:cd4150194ff1133ec6faf04567110dab14e905cd436744b02a4892ee1809357b'
HTTP_SHA = '1fdf37662a6bc45c4d7a6a205e73db7c8c018c6aca16841dd520bceab2c8b5f4'
SCOPED = {'CustomResourceDefinition', 'Namespace', 'ClusterRole', 'ClusterRoleBinding'}
EXPECTED = {('CustomResourceDefinition', 'flashservices.flash.heterocloud.io'), ('Namespace', WORKLOADS),
            ('ServiceAccount', NS), ('Service', NS + '-api'),
            ('ClusterRole', NS + '-node-reader'), ('ClusterRoleBinding', NS + '-node-reader'),
            ('Role', NS), ('RoleBinding', NS),
            *( (kind, NS + '-' + component) for kind in ('Deployment', 'PodDisruptionBudget')
               for component in ('api', 'controller'))}


def require(condition):
    if not condition:
        raise ValueError('DEV Flash admission rejected')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def desired_crd(document):
    require(document.get('kind') == 'CustomResourceDefinition')
    desired = copy.deepcopy(document)
    # CRD release archives may contain empty, server-owned status placeholders.
    desired.pop('status', None)
    return desired


def select(document):
    require(document.get('kind') == 'List')
    items = document['items']
    require(len(items) == 12 and {(x['kind'], x['metadata']['name']) for x in items} == EXPECTED)
    for item in items:
        expected_namespace = None if item['kind'] in SCOPED else WORKLOADS if item['kind'] in ('Role', 'RoleBinding') else NS
        require(item['metadata'].get('namespace') == expected_namespace)
        if item['kind'] == 'Deployment':
            pod = item['spec']['template']['spec']
            component = item['metadata']['name'].removeprefix(NS + '-')
            require(item['spec']['replicas'] == {'api': 3, 'controller': 2}[component]
                    and len(pod['containers']) == 1 and pod['containers'][0]['image'] == IMAGE
                    and not pod.get('initContainers') and not pod.get('hostNetwork')
                    and pod['serviceAccountName'] == NS and pod['securityContext']['runAsNonRoot'] is True
                    and pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'])
            env = {e['name']: e.get('value') for e in pod['containers'][0]['env']}
            require(env.get('FLASH_WORKLOAD_NAMESPACE') == WORKLOADS)
        elif item['kind'] == 'ClusterRole':
            require(item['rules'] == [{'apiGroups': [''], 'resources': ['nodes'], 'verbs': ['get', 'list', 'watch']}])
        elif item['kind'] in ('RoleBinding', 'ClusterRoleBinding'):
            require(item['subjects'] == [{'kind': 'ServiceAccount', 'name': NS, 'namespace': NS}])
        elif item['kind'] == 'Service':
            require(item['spec']['type'] == 'ClusterIP' and not item['spec'].get('externalIPs'))
    rank = {'Namespace': 0, 'CustomResourceDefinition': 1, 'Deployment': 3}
    return sorted([desired_crd(x) if x['kind'] == 'CustomResourceDefinition' else x for x in items],
                  key=lambda x: (rank.get(x['kind'], 2), x['metadata']['name']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    foundation = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(foundation.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    helper = load('identity_apply', foundation)
    helper.guard()
    raw = helper.trusted_file(args.bundle / 'manifest.json', 1048576)
    require(hashlib.sha256(raw).hexdigest() == STAMP)
    manifest = json.loads(raw)
    filename = NS + '.json'
    raw = helper.trusted_file(args.bundle / filename, 2097152)
    require(hashlib.sha256(raw).hexdigest() == manifest['files'][filename])
    items = select(json.loads(raw))
    http = helper.trusted_file(args.bundle / 'hetero-dev-httproute-crd.json', 2097152)
    require(hashlib.sha256(http).hexdigest() == HTTP_SHA)
    items.insert(1, desired_crd(json.loads(http)))
    garage = Path(__file__).with_name('apply-garage.py')
    require(hashlib.sha256(helper.trusted_file(garage, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    contains = load('garage_apply', garage).contains

    def get(kind, name=None, namespace=None):
        raw = helper.run(['get', kind, *([name] if name else []), *(['-n', namespace] if namespace else []),
                         '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    require(get('namespace', NS)['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    runtime = get('runtimeclass', 'gvisor')
    require(runtime['handler'] == 'runsc' and runtime['scheduling'] == {'nodeSelector': {'flash.heterocloud.io/gvisor-ready': 'true'}})
    nodes = get('nodes')['items']
    require(len(nodes) == 3 and all(n['metadata']['labels'].get('flash.heterocloud.io/gvisor-ready') == 'true' for n in nodes))
    key = get('secret', NS + '-provider-auth', NS)
    require(json.loads(base64.b64decode(key['data']['provider-public-keys.json'], validate=True)))
    requested = []
    for item in items:
        item['metadata']['annotations'] = {**(item['metadata'].get('annotations') or {}), ANNOTATION: STAMP}
        if item['kind'] == 'Namespace':
            item['metadata'].setdefault('labels', {})['release.heteronetwork.io/channel'] = 'dev'
        actual = get(item['kind'], item['metadata']['name'], item['metadata'].get('namespace'))
        if actual:
            require(actual['metadata'].get('annotations', {}).get(ANNOTATION) == STAMP
                    and not actual['metadata'].get('deletionTimestamp') and contains(actual, item)
                    and any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
        elif item['kind'] == 'Deployment':
            requested.append(capacity.pod_requests(item['spec']['template']['spec']))
    pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
    for node in nodes:
        allocated = [capacity.pod_requests(p['spec']) for p in pods
                     if p['spec'].get('nodeName') == node['metadata']['name']
                     and p['status'].get('phase') not in ('Succeeded', 'Failed')]
        require(all(capacity.quantity(node['status']['allocatable'][key]) - sum(p[key] for p in allocated)
                    >= sum(p[key] for p in requested) for key in ('cpu', 'memory')))
    command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
    for item in items:
        # Namespaced dry-runs require the namespace to have actually been created.
        namespace = item['metadata'].get('namespace')
        if namespace == WORKLOADS and not get('namespace', WORKLOADS) and not args.apply:
            continue
        helper.run([*command, '--dry-run=server'], json.dumps(item).encode())
        if args.apply:
            helper.guard()
            helper.run(command, json.dumps(item).encode())
            require(contains(get(item['kind'], item['metadata']['name'], namespace), item))
            if item['kind'] == 'CustomResourceDefinition':
                helper.run(['wait', 'crd/' + item['metadata']['name'], '--for=condition=Established', '--timeout=60s'])
            elif item['kind'] == 'Deployment':
                helper.run(['rollout', 'status', 'deployment/' + item['metadata']['name'], '-n', NS, '--timeout=100s'])
    print(json.dumps({'applied': args.apply, 'resources': len(items), 'tenant_workload_verified': False,
                      'dry_run_complete': args.apply or bool(get('namespace', WORKLOADS))}), flush=True)


if __name__ == '__main__':
    main()
