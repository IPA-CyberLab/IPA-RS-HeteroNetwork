#!/usr/bin/env python3
"""Apply only the verified revision17 Flash image delta in DEV."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

NS = 'heterocloud-flash-dev'
OLD = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:0.1.30-dev.1@sha256:cd4150194ff1133ec6faf04567110dab14e905cd436744b02a4892ee1809357b'
NEW = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:0.1.30-dev.2@sha256:191c9c68251f7b578490b12fb18797f5f364b1124ae80fd14f457c42eb252cb2'
OLD_STAMP = '3a6fb8239f19638765825c6363d5553beb317ebbf68ce88ed72faf30aa846011'
STAMP = '146d12418c17a225e84168e779db7bf830b0771b86eca9a8762cae7bc64ce5d1'
ANNOTATION = 'heteronetwork.dev/runtime-bundle-sha256'


def require(value):
    if not value:
        raise ValueError('DEV Flash image upgrade rejected')


def pair(before, after):
    expected = copy.deepcopy(before)
    deployments = []
    for obj in expected['items']:
        if obj['kind'] != 'Deployment':
            continue
        require(obj['metadata']['namespace'] == NS)
        containers = obj['spec']['template']['spec']['containers']
        require(len(containers) == 1 and containers[0]['image'] == OLD)
        containers[0]['image'] = NEW
        if obj['metadata']['name'] == NS + '-controller':
            entries = [e for e in containers[0]['env'] if e['name'] == 'FLASH_PERSISTENT_STORAGE_CLASS']
            require(entries == [{'name': 'FLASH_PERSISTENT_STORAGE_CLASS', 'value': 'dev-app-local'}])
            entries[0]['value'] = 'dev-flash-rwx'
        deployments.append(obj)
    require({d['metadata']['name'] for d in deployments} == {NS + '-api', NS + '-controller'}
            and len(deployments) == 2 and expected == after)
    return deployments


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    foundation = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(foundation.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    h = load('identity_apply', foundation)
    h.guard()
    documents = {}
    for name, digest in {'manifest.json': STAMP,
        'before.json': 'f265a7c4ce61bfa560aff3951ca55c5a3892b6052af336aeaeb60b3e1ea62297',
        'heterocloud-flash-dev.json': '99388dcf194b5a53b09b8d1e4976f2757a83c436da0773e2eee6a3aa6d922e40'}.items():
        raw = h.trusted_file(args.bundle / name, 2097152)
        require(hashlib.sha256(raw).hexdigest() == digest)
        documents[name] = json.loads(raw)
    desired = pair(documents['before.json'], documents['heterocloud-flash-dev.json'])
    garage = args.bundle / 'apply-garage.py'
    require(hashlib.sha256(h.trusted_file(garage, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    contains = load('garage', garage).contains

    def get(kind, name=None, namespace=NS):
        return json.loads(h.run(['get', kind, *([name] if name else []), '-n', namespace, '-o', 'json']))

    before_workloads = {p['metadata']['uid'] for p in get('pods', namespace=NS + '-workloads')['items']}
    for item in desired:
        actual = get('deployment', item['metadata']['name'])
        previous = copy.deepcopy(item)
        previous['spec']['template']['spec']['containers'][0]['image'] = OLD
        require(actual['metadata'].get('annotations', {}).get(ANNOTATION) in (OLD_STAMP, STAMP)
                and not actual['metadata'].get('deletionTimestamp')
                and (contains(actual, previous) or contains(actual, item)))
    for item in desired:
        actual = get('deployment', item['metadata']['name'])
        image = actual['spec']['template']['spec']['containers'][0]['image']
        if args.apply and image != NEW:
            h.guard()
            patch = [{'op': 'test', 'path': '/metadata/' + field, 'value': actual['metadata'][field]}
                     for field in ('uid', 'resourceVersion')]
            patch += [{'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': OLD},
                      {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': NEW},
                      {'op': 'add', 'path': '/metadata/annotations/' + ANNOTATION.replace('/', '~1'), 'value': STAMP}]
            h.run(['patch', 'deployment', item['metadata']['name'], '-n', NS, '--type=json', '-p', json.dumps(patch)])
        if args.apply:
            h.run(['rollout', 'status', 'deployment/' + item['metadata']['name'], '-n', NS, '--timeout=100s'])
            result = get('deployment', item['metadata']['name'])
            require(contains(result, item) and result['status']['observedGeneration'] == result['metadata']['generation']
                    and result['status']['availableReplicas'] == item['spec']['replicas']
                    and result['status']['updatedReplicas'] == item['spec']['replicas'])
        print(json.dumps({'deployment': item['metadata']['name'], 'applied': args.apply,
                          'image_changed': args.apply and image != NEW}), flush=True)
    require(before_workloads.issubset({p['metadata']['uid'] for p in get('pods', namespace=NS + '-workloads')['items']}))
    h.guard()
    print(json.dumps({'applied': args.apply, 'image': NEW, 'tenant_pods_preserved': len(before_workloads),
                      'production_changed': False}), flush=True)


if __name__ == '__main__':
    main()
