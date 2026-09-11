#!/usr/bin/env python3
"""Deploy only the selected DEV Garage storage and layout, never application APIs."""
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

NS = 'heterocloud-syouyu-dev'
STAMP = '57adfb9d4f123e77c486fd46a2fc9f83b7cb537f56d119ea796ee0afe3f671a3'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'
MANAGER = 'hetero-dev-runtime'
IMAGE = 'docker.io/dxflrs/garage@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690'
JOB = NS + '-layout-e97f53f5'
CLUSTER_SCOPED = {'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding'}
EXPECTED = {
    ('CustomResourceDefinition', 'garagenodes.deuxfleurs.fr'),
    *(('NetworkPolicy', NS + '-' + suffix) for suffix in ('default-deny', 'dns', 'garage', 'layout-bootstrap')),
    ('PodDisruptionBudget', NS + '-garage'),
    ('ServiceAccount', NS), ('ServiceAccount', NS + '-garage'),
    ('ConfigMap', NS + '-garage-config'),
    ('ClusterRole', NS + '-garage-discovery'),
    ('ClusterRoleBinding', NS + '-garage-discovery'),
    *(('Service', NS + '-' + suffix) for suffix in ('garage-headless', 's3', 'garage-admin', 'garage-admin-bootstrap', 'garage-metrics')),
    ('StatefulSet', NS + '-garage'), ('Job', JOB),
}


def require(value):
    if not value:
        raise ValueError('DEV Garage admission rejected')


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
    require(document.get('kind') == 'List')
    items = [d for d in document['items'] if (d['kind'], d['metadata']['name']) in EXPECTED]
    require(len(items) == len(EXPECTED) and {(d['kind'], d['metadata']['name']) for d in items} == EXPECTED)
    for item in items:
        require(item['metadata'].get('namespace') == (None if item['kind'] in CLUSTER_SCOPED else NS))
    sts = next(d for d in items if d['kind'] == 'StatefulSet')
    pod = sts['spec']['template']['spec']
    require(sts['spec']['replicas'] == 3 and len(pod['containers']) == 1
            and pod['containers'][0]['image'] == IMAGE and not pod.get('hostNetwork')
            and not pod.get('initContainers')
            and pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'])
    claims = sts['spec']['volumeClaimTemplates']
    require(len(claims) == 2 and {c['metadata']['name']: c['spec']['resources']['requests']['storage']
                               for c in claims} == {'meta': '2Gi', 'data': '10Gi'}
            and all(c['spec']['storageClassName'] == 'dev-app-local' for c in claims))
    # Keep the chart policy scoped to Syouyu pods; the namespace already has PostgreSQL.
    for item in items:
        if item['kind'] == 'NetworkPolicy':
            require(item['spec']['podSelector']['matchLabels']['app.kubernetes.io/instance'] == NS)
    rank = {'CustomResourceDefinition': 0, 'StatefulSet': 2, 'Job': 3}
    return sorted(items, key=lambda d: rank.get(d['kind'], 1)), pod


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    raw_manifest = helper.trusted_file(args.bundle / 'manifest.json', 1024 * 1024)
    require(hashlib.sha256(raw_manifest).hexdigest() == STAMP)
    manifest = json.loads(raw_manifest)
    require(manifest['cluster_uid'] == storage_plan.CLUSTER_UID and manifest['channel'] == 'dev'
            and manifest['production_cluster_uid'] == '6d773ea3-e3a7-4bc2-a6fa-d5b53279d524')
    filename = NS + '.json'
    raw = helper.trusted_file(args.bundle / filename, 2 * 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == manifest['files'][filename])
    items, pod = select(json.loads(raw))

    def get(kind, name=None, namespace=None):
        cmd = ['get', kind] + ([name] if name else []) + (['-n', namespace] if namespace else [])
        raw = helper.run([*cmd, '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    require(get('namespace', NS)['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    require(get('cluster.postgresql.cnpg.io', 'dev-postgres', NS)['status']['readyInstances'] == 3)
    secret = get('secret', NS + '-secrets', NS)
    for key in ('garage-rpc-secret', 'garage-admin-token', 'garage-metrics-token'):
        require(len(base64.b64decode(secret['data'][key], validate=True)) >= 32)
    for desired in storage_plan.manifest()['items'][1:]:
        if desired['metadata']['name'].startswith('dev-app-garage-'):
            actual = get('persistentvolume', desired['metadata']['name'])
            require(contains(actual, desired) and actual['status']['phase'] in ('Available', 'Bound')
                    and not actual['metadata'].get('deletionTimestamp'))
    if not get('statefulset', NS + '-garage', NS):
        nodes = get('nodes')['items']
        pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
        job_pod = next(d for d in items if d['kind'] == 'Job')['spec']['template']['spec']
        needed = capacity.pod_requests(pod)
        job_needed = capacity.pod_requests(job_pod)
        for node in nodes:
            allocated = [capacity.pod_requests(p['spec']) for p in pods
                         if p['spec'].get('nodeName') == node['metadata']['name']
                         and p['status'].get('phase') not in ('Succeeded', 'Failed')]
            require(all(capacity.quantity(node['status']['allocatable'][k]) - sum(p[k] for p in allocated)
                        >= needed[k] + job_needed[k] for k in needed))
    for item in items:
        item['metadata'].setdefault('annotations', {})[ANNOTATION] = STAMP
        namespace = None if item['kind'] in CLUSTER_SCOPED else NS
        actual = get(item['kind'], item['metadata']['name'], namespace)
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
            namespace = None if item['kind'] in CLUSTER_SCOPED else NS
            # An existing Job is never reapplied: API-generated selector fields are immutable.
            if item['kind'] != 'Job' or not get('job', JOB, NS):
                helper.run(command, data=json.dumps(item).encode())
            require(contains(get(item['kind'], item['metadata']['name'], namespace), item))
            if item['kind'] == 'CustomResourceDefinition':
                helper.run(['wait', '--for=condition=Established', 'crd/garagenodes.deuxfleurs.fr', '--timeout=60s'])
        print(json.dumps({'applied': True, 'resources': len(items), 'ready_verified': False}), flush=True)


if __name__ == '__main__':
    main()
