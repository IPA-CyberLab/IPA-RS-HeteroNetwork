#!/usr/bin/env python3
"""Switch the reviewed DEV Flash controller to verified shared storage."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

NS = 'heterocloud-flash-dev'
NAME = NS + '-controller'
STAMP = '3a6fb8239f19638765825c6363d5553beb317ebbf68ce88ed72faf30aa846011'
STORAGE = 'dev-flash-rwx'


def require(ok):
    if not ok:
        raise ValueError('DEV Flash shared storage migration rejected')


def transition(deployment):
    desired = copy.deepcopy(deployment)
    require(desired['kind'] == 'Deployment' and desired['metadata']['name'] == NAME
            and desired['metadata']['namespace'] == NS and desired['spec']['replicas'] == 2)
    containers = desired['spec']['template']['spec']['containers']
    require(len(containers) == 1 and containers[0]['name'] == 'controller')
    env = containers[0]['env']
    indices = [i for i, e in enumerate(env) if e['name'] == 'FLASH_PERSISTENT_STORAGE_CLASS']
    require(len(indices) == 1)
    index = indices[0]
    require(env[index] == {'name': 'FLASH_PERSISTENT_STORAGE_CLASS', 'value': 'dev-app-local'})
    env[index]['value'] = STORAGE
    return desired, index


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
    raw = h.trusted_file(args.bundle / 'manifest.json', 1048576)
    require(hashlib.sha256(raw).hexdigest() == STAMP)
    filename = NS + '.json'
    expected_hash = json.loads(raw)['files'][filename]
    raw = h.trusted_file(args.bundle / filename, 2097152)
    require(hashlib.sha256(raw).hexdigest() == expected_hash)
    original = next(i for i in json.loads(raw)['items'] if i['kind'] == 'Deployment' and i['metadata']['name'] == NAME)
    desired, index = transition(original)
    garage = args.bundle / 'apply-garage.py'
    require(hashlib.sha256(h.trusted_file(garage, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    contains = load('garage_apply', garage).contains

    def get(kind, name=None, namespace=NS):
        return json.loads(h.run(['get', kind, *([name] if name else []),
                                *(['-n', namespace] if namespace else []), '-o', 'json']))

    sc = get('storageclass', STORAGE, None)
    require(sc['provisioner'] == 'driver.longhorn.io' and sc['parameters']['numberOfReplicas'] == '3'
            and sc['parameters']['migratable'] == 'false' and sc['reclaimPolicy'] == 'Retain')
    nodes = get('nodes.longhorn.io', namespace='longhorn-system')['items']
    require({n['metadata']['name'] for n in nodes} == {'hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3'})
    for node in nodes:
        require(set(node['spec']['disks']) == {'dev-app-filesystem'})
        disk = node['spec']['disks']['dev-app-filesystem']
        require(disk['path'] == '/var/lib/heteronetwork-dev-app-storage/longhorn'
                and disk['storageReserved'] == 43 * 1024**3 and disk['allowScheduling'])
        conditions = {c['type']: c['status'] for c in node['status']['diskStatus']['dev-app-filesystem']['conditions']}
        require(conditions.get('Ready') == 'True' and conditions.get('Schedulable') == 'True')
    actual = get('deployment', NAME)
    require(actual['metadata'].get('annotations', {}).get('heteronetwork.dev/runtime-bundle-sha256') == STAMP
            and not actual['metadata'].get('deletionTimestamp'))
    require(contains(actual, original) or contains(actual, desired))
    before_api = {p['metadata']['uid'] for p in get('pods')['items']
                  if p['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 'api'}
    before_workloads = {p['metadata']['uid'] for p in get('pods', namespace=NS + '-workloads')['items']}
    require(len(before_api) == 3)
    changed = not contains(actual, desired)
    if args.apply and changed:
        tests = [{'op': 'test', 'path': '/metadata/' + field, 'value': actual['metadata'][field]}
                 for field in ('uid', 'resourceVersion')]
        path = '/spec/template/spec/containers/0/env/' + str(index) + '/value'
        tests += [{'op': 'test', 'path': path, 'value': 'dev-app-local'},
                  {'op': 'replace', 'path': path, 'value': STORAGE}]
        h.run(['patch', 'deployment', NAME, '-n', NS, '--type=json', '-p', json.dumps(tests)])
    if args.apply:
        h.run(['rollout', 'status', 'deployment/' + NAME, '-n', NS, '--timeout=100s'])
        result = get('deployment', NAME)
        require(contains(result, desired) and result['status']['observedGeneration'] == result['metadata']['generation']
                and result['status']['availableReplicas'] == 2 and result['status']['updatedReplicas'] == 2)
        require(before_api == {p['metadata']['uid'] for p in get('pods')['items']
                              if p['metadata'].get('labels', {}).get('app.kubernetes.io/component') == 'api'})
        require(before_workloads.issubset({p['metadata']['uid'] for p in get('pods', namespace=NS + '-workloads')['items']}))
        h.guard()
    print(json.dumps({'applied': args.apply, 'controller_changed': changed if args.apply else False,
                      'storage_class': STORAGE, 'api_pods_preserved': len(before_api),
                      'workload_pods_preserved': len(before_workloads), 'tenant_operation_verified': False}), flush=True)


if __name__ == '__main__':
    main()
