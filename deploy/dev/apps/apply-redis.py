#!/usr/bin/env python3
"""Guarded initial DEV Redis deployment from selected, verified chart output."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capacity
import storage_plan

NS = 'heterocloud-flow-dev'
PREFIX = 'heterocloud-flow-dev-redis'
MANAGER = 'hetero-dev-runtime'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'
EXPECTED = {('NetworkPolicy', PREFIX), ('PodDisruptionBudget', PREFIX + '-node'),
            ('ServiceAccount', PREFIX), ('StatefulSet', PREFIX + '-node'),
            ('Service', PREFIX), ('Service', PREFIX + '-headless'),
            *(('ConfigMap', PREFIX + '-' + suffix) for suffix in ('configuration', 'health', 'scripts'))}
IMAGES = {'redis': 'docker.io/bitnami/redis@sha256:ffa455a3ad00bccc24dfde113ef55329dde687da242e9feb6ccd2b30eb93e8f3',
          'sentinel': 'docker.io/bitnami/redis-sentinel@sha256:97433fd14ea945c164ac514c162e2d2a017e9044fdc7ec46abf12a92f4660770'}


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(
            (actual.get(k) in (None, {}, []) if v in (None, {}, []) else k in actual and contains(actual[k], v))
            for k, v in desired.items())
    if isinstance(desired, list):
        return isinstance(actual, list) and len(actual) == len(desired) and all(
            contains(a, b) for a, b in zip(actual, desired))
    return actual == desired


def select(document):
    if document.get('kind') != 'List':
        raise ValueError('Expected rendered resource list')
    items = [d for d in document['items'] if d['metadata'].get('labels', {}).get('app.kubernetes.io/name') == 'redis']
    if len(items) != len(EXPECTED) or {(d['kind'], d['metadata']['name']) for d in items} != EXPECTED:
        raise ValueError('Unexpected Redis resource inventory')
    for item in items:
        if item['metadata'].get('namespace') != NS or item['metadata']['labels'].get('app.kubernetes.io/instance') != 'heterocloud-flow-dev':
            raise ValueError('Foreign Redis namespace or release')
    sts = next(d for d in items if d['kind'] == 'StatefulSet')
    pod = sts['spec']['template']['spec']
    if sts['spec']['replicas'] != 3 or len(pod['containers']) != 2 or {c['name']: c['image'] for c in pod['containers']} != IMAGES:
        raise ValueError('Unexpected Redis replicas/images')
    if pod.get('hostNetwork') or pod.get('initContainers') or not pod['affinity']['podAntiAffinity'].get('requiredDuringSchedulingIgnoredDuringExecution'):
        raise ValueError('Unexpected Redis placement')
    claim = sts['spec']['volumeClaimTemplates']
    if len(claim) != 1 or claim[0]['metadata']['name'] != 'redis-data' or claim[0]['spec']['storageClassName'] != 'dev-app-local' or claim[0]['spec']['resources']['requests']['storage'] != '8Gi':
        raise ValueError('Redis must use reserved app storage')
    return sorted(items, key=lambda d: d['kind'] == 'StatefulSet'), pod


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    raw_manifest = helper.trusted_file(args.bundle / 'manifest.json', 1024 * 1024)
    manifest = json.loads(raw_manifest)
    helper.require(manifest['schema_version'] == 1 and manifest['channel'] == 'dev'
                   and manifest['cluster_uid'] == storage_plan.CLUSTER_UID
                   and manifest['production_cluster_uid'] == '6d773ea3-e3a7-4bc2-a6fa-d5b53279d524'
                   and manifest['components']['flow']['commit'] == '7e2b8e2db16387faff4087341c51efeac66802de')
    filename = 'heterocloud-flow-dev.json'
    raw = helper.trusted_file(args.bundle / filename, 2 * 1024 * 1024)
    helper.require(hashlib.sha256(raw).hexdigest() == manifest['files'][filename])
    items, pod = select(json.loads(raw))
    stamp = hashlib.sha256(raw_manifest).hexdigest()

    def get(kind, name=None, namespace=None):
        command = ['get', kind] + ([name] if name else []) + (['-n', namespace] if namespace else [])
        data = helper.run([*command, '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(data) if data.strip() else None

    namespace = get('namespace', NS)
    helper.require(namespace['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    secret = get('secret', 'heterocloud-flow-dev-secrets', NS)
    helper.require(len(base64.b64decode(secret['data']['redis-password'], validate=True)) >= 32)
    for desired in storage_plan.manifest()['items'][1:]:
        if desired['metadata']['name'].startswith('dev-app-flow-redis-'):
            actual = get('persistentvolume', desired['metadata']['name'])
            helper.require(contains(actual, desired) and actual['status']['phase'] in ('Available', 'Bound')
                           and not actual['metadata'].get('deletionTimestamp'))
    existing = get('statefulset', PREFIX + '-node', NS)
    if not existing:
        nodes = get('nodes')['items']
        pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
        needed = capacity.pod_requests(pod)
        for node in nodes:
            allocated = [capacity.pod_requests(p['spec']) for p in pods
                         if p['spec'].get('nodeName') == node['metadata']['name']
                         and p['status'].get('phase') not in ('Succeeded', 'Failed')]
            helper.require(all(capacity.quantity(node['status']['allocatable'][k])
                               - sum(p[k] for p in allocated) >= needed[k] for k in needed))
    for item in items:
        item['metadata'].setdefault('annotations', {})[ANNOTATION] = stamp
        actual = get(item['kind'], item['metadata']['name'], NS)
        if actual:
            helper.require(actual['metadata'].get('annotations', {}).get(ANNOTATION) == stamp
                           and contains(actual, item) and not actual['metadata'].get('deletionTimestamp')
                           and any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
    command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
    for item in items:
        helper.run([*command, '--dry-run=server'], data=json.dumps(item).encode())
    print(json.dumps({'admitted': True, 'resources': len(items), 'apply': args.apply}), flush=True)
    if args.apply:
        for item in items:
            helper.guard()
            helper.run(command, data=json.dumps(item).encode())
            helper.require(contains(get(item['kind'], item['metadata']['name'], NS), item))
        print(json.dumps({'applied': True, 'resources': len(items), 'ready_verified': False}), flush=True)


if __name__ == '__main__':
    main()
