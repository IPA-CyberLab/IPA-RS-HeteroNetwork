#!/usr/bin/env python3
"""Initial DEV Flow runtime, with the migration completed before deployments."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capacity

NS = 'heterocloud-flow-dev'
STAMP = '57adfb9d4f123e77c486fd46a2fc9f83b7cb537f56d119ea796ee0afe3f671a3'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'
MANAGER = 'hetero-dev-runtime'
COMPONENTS = ('api', 'matchmaker', 'signaling', 'livekit', 'coturn')
FLOW = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow:0.1.21-dev.6@sha256:e768fe4d5846e1c7a4e86199a97684aa87dfd75a7ea431550a8e1dcb2470721b'
IMAGES = {**{name: FLOW for name in ('api', 'matchmaker', 'signaling', 'migrate')},
          'livekit': 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit:0.1.21-dev.6@sha256:02920c1d1d5dc4957105692fa236c11abba8a7825e3bf3153e3cbddd69ea949b',
          'coturn': 'docker.io/coturn/coturn:4.16.0@sha256:01fc8655e7c262fa4ccfb8dca74ff80fb372b0ee021e80370a4d3e3dd01a951e'}
EXPECTED = {('ServiceAccount', NS), ('Job', NS + '-migrate'),
            *(('Deployment', NS + '-' + c) for c in COMPONENTS),
            *(('PodDisruptionBudget', NS + '-' + c) for c in COMPONENTS),
            *(('NetworkPolicy', NS + '-' + c) for c in ('default-deny', 'control-plane', 'media-plane')),
            *(('Service', NS + '-' + c) for c in ('api', 'turn', 'coturn-metrics', 'livekit', 'livekit-signal', 'livekit-rtc', 'signaling'))}


def require(value):
    if not value:
        raise ValueError('DEV Flow admission rejected')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def annotate(item):
    annotations = item['metadata'].get('annotations')
    require(annotations is None or isinstance(annotations, dict))
    item['metadata']['annotations'] = {**(annotations or {}), ANNOTATION: STAMP}


def select(document):
    require(document.get('kind') == 'List')
    items = [d for d in document['items'] if (d['kind'], d['metadata']['name']) in EXPECTED]
    require(len(items) == len(EXPECTED) and {(d['kind'], d['metadata']['name']) for d in items} == EXPECTED)
    for item in items:
        require(item['metadata'].get('namespace') == NS)
        if item['kind'] in ('Deployment', 'Job'):
            component = item['metadata']['name'].removeprefix(NS + '-')
            pod = item['spec']['template']['spec']
            require(len(pod['containers']) == 1 and pod['containers'][0]['image'] == IMAGES[component]
                    and not pod.get('initContainers') and pod.get('automountServiceAccountToken') is False
                    and bool(pod.get('hostNetwork')) == (component == 'coturn'))
            if item['kind'] == 'Deployment':
                require(item['spec']['replicas'] == 3)
            else:
                require(pod['containers'][0]['command'] == ['/usr/local/bin/flow-api', 'migrate'])
    return sorted(items, key=lambda d: {'Job': 1, 'Deployment': 2}.get(d['kind'], 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    helper = load('identity_apply', path)
    helper.guard()
    raw_manifest = helper.trusted_file(args.bundle / 'manifest.json', 1048576)
    require(hashlib.sha256(raw_manifest).hexdigest() == STAMP)
    manifest = json.loads(raw_manifest)
    filename = NS + '.json'
    raw = helper.trusted_file(args.bundle / filename, 2097152)
    require(hashlib.sha256(raw).hexdigest() == manifest['files'][filename])
    items = select(json.loads(raw))
    garage_path = Path(__file__).with_name('apply-garage.py')
    require(hashlib.sha256(helper.trusted_file(garage_path, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    contains = load('garage_apply', garage_path).contains

    def get(kind, name=None, namespace=NS):
        cmd = ['get', kind] + ([name] if name else []) + (['-n', namespace] if namespace else [])
        data = helper.run([*cmd, '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(data) if data.strip() else None

    require(get('namespace', NS, None)['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    require(get('cluster.postgresql.cnpg.io', 'dev-postgres')['status']['readyInstances'] == 3)
    require(get('statefulset', NS + '-redis-node')['status']['readyReplicas'] == 3)
    requested = []
    for item in items:
        if item['kind'] not in ('Deployment', 'Job'):
            continue
        pod = item['spec']['template']['spec']
        for container in pod['containers']:
            for env in container.get('env', []):
                ref = env.get('valueFrom', {}).get('secretKeyRef')
                if ref:
                    require(base64.b64decode(get('secret', ref['name'])['data'][ref['key']], validate=True))
        for volume in pod.get('volumes', []):
            ref = volume.get('secret')
            if ref:
                data = get('secret', ref['secretName'])['data']
                for key in ref.get('items', []):
                    require(base64.b64decode(data[key['key']], validate=True))
        if not get(item['kind'], item['metadata']['name']):
            requested.append(capacity.pod_requests(pod))
    pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
    for node in get('nodes', namespace=None)['items']:
        allocated = [capacity.pod_requests(p['spec']) for p in pods
                     if p['spec'].get('nodeName') == node['metadata']['name']
                     and p['status'].get('phase') not in ('Succeeded', 'Failed')]
        require(all(capacity.quantity(node['status']['allocatable'][k]) - sum(p[k] for p in allocated)
                    >= sum(p[k] for p in requested) for k in ('cpu', 'memory')))
    for item in items:
        annotate(item)
        actual = get(item['kind'], item['metadata']['name'])
        if actual:
            require(actual['metadata'].get('annotations', {}).get(ANNOTATION) == STAMP
                    and contains(actual, item) and not actual['metadata'].get('deletionTimestamp')
                    and any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
    command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
    for item in items:
        helper.run([*command, '--dry-run=server'], data=json.dumps(item).encode())
    print(json.dumps({'admitted': True, 'resources': len(items), 'apply': args.apply}), flush=True)
    if args.apply:
        for item in items:
            helper.guard()
            if item['kind'] != 'Job' or not get('job', item['metadata']['name']):
                helper.run(command, data=json.dumps(item).encode())
            require(contains(get(item['kind'], item['metadata']['name']), item))
            if item['kind'] == 'Job':
                helper.run(['wait', '-n', NS, '--for=condition=complete', 'job/' + item['metadata']['name'], '--timeout=90s'])
        print(json.dumps({'applied': True, 'migration_completed': True, 'ready_verified': False}), flush=True)


if __name__ == '__main__':
    main()
