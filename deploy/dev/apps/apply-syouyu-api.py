#!/usr/bin/env python3
"""Guarded initial Syouyu API phase of the immutable revision15 DEV bundle."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit

sys.dont_write_bytecode = True
import capacity

NS = 'heterocloud-syouyu-dev'
NAME = NS + '-api'
STAMP = '57adfb9d4f123e77c486fd46a2fc9f83b7cb537f56d119ea796ee0afe3f671a3'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'
MANAGER = 'hetero-dev-runtime'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-syouyu:0.1.7-dev.2@sha256:2021bc7161146b212e41ec51ae5f1e127d11cfa03ad03d588e05de2335a0d1d6'
EXPECTED = {(kind, NAME) for kind in ('NetworkPolicy', 'Service', 'Deployment')}


def require(value):
    if not value:
        raise ValueError('DEV Syouyu API admission rejected')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def select(document):
    require(document.get('kind') == 'List')
    items = [d for d in document['items'] if (d['kind'], d['metadata']['name']) in EXPECTED]
    require(len(items) == 3 and {(d['kind'], d['metadata']['name']) for d in items} == EXPECTED)
    for item in items:
        require(item['metadata'].get('namespace') == NS)
    deployment = next(d for d in items if d['kind'] == 'Deployment')
    pod = deployment['spec']['template']['spec']
    require(deployment['spec']['replicas'] == 3 and len(pod['containers']) == 1
            and pod['containers'][0]['image'] == IMAGE and not pod.get('hostNetwork')
            and not pod.get('initContainers') and pod.get('automountServiceAccountToken') is False)
    policy = next(d for d in items if d['kind'] == 'NetworkPolicy')
    require(policy['spec']['podSelector'].get('matchLabels', {}).get('app.kubernetes.io/instance') == NS)
    return sorted(items, key=lambda d: d['kind'] == 'Deployment'), pod


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    helper = load('identity_apply', path)
    helper.guard()
    raw_manifest = helper.trusted_file(args.bundle / 'manifest.json', 1024 * 1024)
    require(hashlib.sha256(raw_manifest).hexdigest() == STAMP)
    manifest = json.loads(raw_manifest)
    filename = NS + '.json'
    raw = helper.trusted_file(args.bundle / filename, 2 * 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == manifest['files'][filename])
    items, pod = select(json.loads(raw))
    garage_path = Path(__file__).with_name('apply-garage.py')
    require(hashlib.sha256(helper.trusted_file(garage_path, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    garage = load('garage_apply', garage_path)

    def get(kind, name=None, namespace=NS):
        cmd = ['get', kind] + ([name] if name else []) + (['-n', namespace] if namespace else [])
        raw = helper.run([*cmd, '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    require(get('namespace', NS, None)['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    require(get('cluster.postgresql.cnpg.io', 'dev-postgres')['status']['readyInstances'] == 3)
    require(get('statefulset', NS + '-garage')['status']['readyReplicas'] == 3)
    require(get('serviceaccount', NS)['metadata']['annotations'].get(ANNOTATION) == STAMP)
    for env in pod['containers'][0]['env']:
        reference = env.get('valueFrom', {}).get('secretKeyRef')
        if reference:
            secret = get('secret', reference['name'])
            decoded = base64.b64decode(secret['data'][reference['key']], validate=True)
            require(decoded)
            if env['name'] == 'DATABASE_URL':
                url = urlsplit(decoded.decode())
                require(url.scheme == 'postgresql' and url.hostname == f'dev-postgres-rw.{NS}.svc.cluster.local'
                        and url.path == '/heterocloud_syouyu_dev' and url.username == 'heterocloud_syouyu_dev'
                        and parse_qs(url.query).get('sslmode') == ['verify-full'])
    if not get('deployment', NAME):
        pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
        needed = capacity.pod_requests(pod)
        for node in get('nodes', namespace=None)['items']:
            allocated = [capacity.pod_requests(p['spec']) for p in pods
                         if p['spec'].get('nodeName') == node['metadata']['name']
                         and p['status'].get('phase') not in ('Succeeded', 'Failed')]
            require(all(capacity.quantity(node['status']['allocatable'][k]) - sum(p[k] for p in allocated)
                        >= 2 * needed[k] for k in needed))
    for item in items:
        item['metadata'].setdefault('annotations', {})[ANNOTATION] = STAMP
        actual = get(item['kind'], NAME)
        if actual:
            require(actual['metadata'].get('annotations', {}).get(ANNOTATION) == STAMP
                    and garage.contains(actual, item) and not actual['metadata'].get('deletionTimestamp')
                    and any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
    command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
    for item in items:
        helper.run([*command, '--dry-run=server'], data=json.dumps(item).encode())
    print(json.dumps({'admitted': True, 'resources': 3, 'apply': args.apply}), flush=True)
    if args.apply:
        for item in items:
            helper.guard()
            helper.run(command, data=json.dumps(item).encode())
            require(garage.contains(get(item['kind'], NAME), item))
        print(json.dumps({'applied': True, 'ready_verified': False}), flush=True)


if __name__ == '__main__':
    main()
