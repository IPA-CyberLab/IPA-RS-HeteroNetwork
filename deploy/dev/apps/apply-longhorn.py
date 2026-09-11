#!/usr/bin/env python3
"""Apply the reviewed DEV Longhorn control plane without disk enrollment."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capacity

NS = 'longhorn-system'
STAMP = 'e6a10cc588f2d97c82af3f98bf9981d2e5b43441d5be58fb37fe5950d873d7b2'
MANAGER = 'hetero-dev-longhorn'
ANNOTATION = 'heteronetwork.dev/longhorn-bundle-sha256'
CLUSTER = {'PriorityClass', 'StorageClass', 'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding'}
NAMESPACED = {'NetworkPolicy', 'PodDisruptionBudget', 'ServiceAccount', 'ConfigMap',
              'Role', 'RoleBinding', 'Service', 'DaemonSet', 'Deployment'}


def require(value):
    if not value:
        raise ValueError('DEV Longhorn admission rejected')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized(actual):
    if actual and actual.get('kind') == 'PriorityClass':
        return {'globalDefault': False, **actual}
    return actual


def select(document):
    require(document.get('kind') == 'List' and len(document['items']) == 51)
    items = document['items']
    require(len({(x['kind'], x['metadata']['name']) for x in items}) == len(items))
    for item in items:
        require(item['kind'] in CLUSTER | NAMESPACED
                and item['metadata'].get('namespace') == (None if item['kind'] in CLUSTER else NS)
                and not item['metadata'].get('annotations', {}).get('helm.sh/hook'))
        if item['kind'] == 'StorageClass':
            require(item['metadata']['name'] == 'dev-flash-rwx'
                    and item['provisioner'] == 'driver.longhorn.io'
                    and item['parameters']['numberOfReplicas'] == '3'
                    and item['parameters']['migratable'] == 'false'
                    and item['reclaimPolicy'] == 'Retain'
                    and item['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'] == 'false')
        if item['kind'] == 'Service':
            require(item['spec'].get('type', 'ClusterIP') == 'ClusterIP'
                    and not item['spec'].get('externalIPs'))
    rank = {'CustomResourceDefinition': 0, 'DaemonSet': 2, 'Deployment': 3}
    return sorted(items, key=lambda x: (rank.get(x['kind'], 1), x['metadata']['name']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    helper = load('identity_apply', path)
    helper.guard()
    raw = helper.trusted_file(args.bundle / 'install-objects.json', 4194304)
    require(hashlib.sha256(raw).hexdigest() == STAMP)
    items = select(json.loads(raw))
    garage = Path(__file__).with_name('apply-garage.py')
    require(hashlib.sha256(helper.trusted_file(garage, 32768)).hexdigest() ==
            '36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9')
    contains = load('garage_apply', garage).contains

    def get(kind, name=None, namespace=None):
        raw = helper.run(['get', kind, *([name] if name else []), *(['-n', namespace] if namespace else []),
                         '--ignore-not-found', '--show-managed-fields', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    nodes = get('nodes')['items']
    require(len(nodes) == 3)
    for node in nodes:
        labels = node['metadata'].get('labels', {})
        require(node['status']['capacity']['cpu'] == '12'
                and labels.get('storage.heteronetwork.dev/clients-ready') == 'true'
                and 'node.longhorn.io/create-default-disk' not in labels
                and 'node.longhorn.io/default-disks-config' not in node['metadata'].get('annotations', {}))
    pods = json.loads(helper.run(['get', 'pods', '-A', '-o', 'json']))['items']
    for node in nodes:
        outside = [capacity.pod_requests(p['spec']) for p in pods
                   if p['metadata'].get('namespace') != NS and p['spec'].get('nodeName') == node['metadata']['name']
                   and p['status'].get('phase') not in ('Succeeded', 'Failed')]
        # Reserve headroom for controller-created CSI/instance-manager Pods too.
        for key, reserve in [('cpu', '3'), ('memory', '3Gi')]:
            require(capacity.quantity(node['status']['allocatable'][key]) - sum(x[key] for x in outside)
                    >= capacity.quantity(reserve))
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {
        'release.heteronetwork.io/channel': 'dev', 'pod-security.kubernetes.io/enforce': 'privileged'}}}
    items.insert(0, namespace)
    for item in items:
        item['metadata'].setdefault('annotations', {})[ANNOTATION] = STAMP
        actual = get(item['kind'], item['metadata']['name'], item['metadata'].get('namespace'))
        if actual:
            require(actual['metadata'].get('annotations', {}).get(ANNOTATION) == STAMP
                    and not actual['metadata'].get('deletionTimestamp') and contains(normalized(actual), item)
                    and any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
    command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
    for item in items:
        namespace = item['metadata'].get('namespace')
        if namespace and not get('namespace', namespace) and not args.apply:
            continue
        helper.run([*command, '--dry-run=server'], json.dumps(item).encode())
        if args.apply:
            helper.guard()
            helper.run(command, json.dumps(item).encode())
            if not contains(normalized(get(item['kind'], item['metadata']['name'], namespace)), item):
                raise ValueError('DEV Longhorn readback differs: ' + item['kind'] + '/' + item['metadata']['name'])
            if item['kind'] == 'CustomResourceDefinition':
                helper.run(['wait', 'crd/' + item['metadata']['name'], '--for=condition=Established', '--timeout=60s'])
            print(json.dumps({'applied_kind': item['kind'], 'name': item['metadata']['name']}), flush=True)
    if args.apply:
        for kind, name in [('daemonset', 'longhorn-manager'), ('deployment', 'longhorn-driver-deployer'), ('deployment', 'longhorn-ui')]:
            helper.run(['rollout', 'status', kind + '/' + name, '-n', NS, '--timeout=100s'])
        # Driver readiness precedes creation of the CSI workloads it manages.
        for kind, name in [('deployment', 'csi-' + suffix) for suffix in
                           ('attacher', 'provisioner', 'resizer', 'snapshotter')] + [('daemonset', 'longhorn-csi-plugin')]:
            helper.run(['wait', kind + '/' + name, '-n', NS, '--for=create', '--timeout=100s'])
            helper.run(['rollout', 'status', kind + '/' + name, '-n', NS, '--timeout=100s'])
        storage_nodes = get('nodes.longhorn.io', namespace=NS)['items']
        require({n['metadata']['name'] for n in storage_nodes} == {n['metadata']['name'] for n in nodes}
                and all(not n['spec'].get('disks') for n in storage_nodes))
    print(json.dumps({'applied': args.apply, 'resources': len(items), 'disks_enrolled': False,
                      'tenant_storage_verified': False, 'ha_verified': False}), flush=True)


if __name__ == '__main__':
    main()
