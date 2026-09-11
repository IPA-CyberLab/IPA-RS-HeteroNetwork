#!/usr/bin/env python3
"""Verify DEV Longhorn controllers without creating or enrolling storage."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
NS = 'longhorn-system'
NODES = {f'hetero-dev-{i}' for i in range(1, 4)}
PINS_SHA = '7bc1cc23c0f257b70ebace5ff69388daec260faa71c4d13c0608609b3444e918'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enrolled', action='store_true', help='Require the three explicitly reserved DEV disks')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    raw = helper.trusted_file(Path(__file__).with_name('longhorn-images.json'), 16384)
    helper.require(hashlib.sha256(raw).hexdigest() == PINS_SHA)
    pins = set(json.loads(raw).values())

    def get(kind, name=None):
        return json.loads(helper.run(['get', kind, *([name] if name else []), '-n', NS, '-o', 'json']))

    deployments = get('deployments')['items']
    counts = {'longhorn-driver-deployer': 1, 'longhorn-ui': 2,
              'csi-attacher': 3, 'csi-provisioner': 3, 'csi-resizer': 3, 'csi-snapshotter': 3}
    helper.require({d['metadata']['name'] for d in deployments} == set(counts))
    for d in deployments:
        expected = counts[d['metadata']['name']]
        helper.require(d['spec']['replicas'] == expected
                       and d['status'].get('observedGeneration') == d['metadata']['generation']
                       and all(d['status'].get(field) == expected for field in
                               ('replicas', 'updatedReplicas', 'availableReplicas')))
    daemonsets = get('daemonsets')['items']
    names = {d['metadata']['name'] for d in daemonsets}
    helper.require({'longhorn-manager', 'longhorn-csi-plugin'}.issubset(names))
    for d in daemonsets:
        helper.require(d['status'].get('observedGeneration') == d['metadata']['generation']
                       and all(d['status'].get(field) == 3 for field in
                               ('desiredNumberScheduled', 'updatedNumberScheduled', 'numberReady')))
    nodes = get('nodes.longhorn.io')['items']
    helper.require({n['metadata']['name'] for n in nodes} == NODES)
    for node in nodes:
        disks = node['spec'].get('disks', {})
        if not args.enrolled:
            helper.require(not disks)
            continue
        helper.require(set(disks) == {'dev-app-filesystem'})
        disk = disks['dev-app-filesystem']
        helper.require(disk['path'] == '/var/lib/heteronetwork-dev-app-storage/longhorn'
                       and disk['storageReserved'] == 43 * 1024**3
                       and disk['diskType'] == 'filesystem' and disk['allowScheduling']
                       and not disk['evictionRequested'])
        conditions = {c['type']: c['status'] for c in
                      node['status']['diskStatus']['dev-app-filesystem']['conditions']}
        helper.require(conditions.get('Ready') == 'True' and conditions.get('Schedulable') == 'True')
    if args.enrolled:
        for name, value in [('storage-over-provisioning-percentage', '100'),
                            ('storage-minimal-available-percentage', '25'),
                            ('allow-volume-creation-with-degraded-availability', 'false')]:
            helper.require(get('settings.longhorn.io', name)['value'] == value)
    storage = get('storageclass', 'dev-flash-rwx')
    helper.require(storage['provisioner'] == 'driver.longhorn.io'
                   and storage['parameters']['numberOfReplicas'] == '3'
                   and storage['reclaimPolicy'] == 'Retain')
    pods = [p for p in get('pods')['items'] if p['status'].get('phase') not in ('Succeeded', 'Failed')]
    for pod in pods:
        helper.require(not pod['metadata'].get('deletionTimestamp')
                       and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', [])))
        helper.require(all(c['image'] in pins for c in
                           pod['spec'].get('containers', []) + pod['spec'].get('initContainers', [])))
    managers = [p for p in pods if p['metadata']['labels'].get('app') == 'longhorn-manager']
    helper.require(len(managers) == 3 and {p['spec']['nodeName'] for p in managers} == NODES)
    for pod in managers:
        raw = helper.run(['exec', pod['metadata']['name'], '-n', NS, '-c', 'longhorn-manager', '--',
                          'curl', '--fail', '--silent', '--show-error', '--max-time', '8',
                          'http://longhorn-backend:9500/v1'])
        helper.require(isinstance(json.loads(raw), dict))
    helper.require(not helper.run(['get', 'job', 'longhorn-uninstall', '-n', NS, '--ignore-not-found', '-o', 'name']).strip())
    print(json.dumps({'ready_deployments': counts, 'ready_daemonsets': sorted(names),
                      'ready_pods': len(pods), 'manager_api_checks': 3,
                      'all_pod_images_pinned': True, 'disks_enrolled': args.enrolled,
                      'rwx_verified': False, 'ha_verified': False}), flush=True)


if __name__ == '__main__':
    main()
