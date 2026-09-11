#!/usr/bin/env python3
"""Apply only fresh DEV application namespaces, policies and CNPG clusters."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

import databases
import storage_plan

MANAGER = 'hetero-dev-app-databases'
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=10s']


def run(args, data=None):
    result = subprocess.run(KUBE + args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise ValueError('DEV database Kubernetes operation refused')
    return result.stdout


def get(kind, name=None, namespace=None):
    args = ['get', kind] + ([name] if name else [])
    if namespace:
        args += ['-n', namespace]
    raw = run(args + ['--ignore-not-found', '--show-managed-fields', '-o', 'json'])
    return json.loads(raw) if raw.strip() else None


def require(value):
    if not value:
        raise ValueError('DEV application database prerequisite rejected')


def contains(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and contains(actual[k], v) for k, v in expected.items())
    return actual == expected


def guard():
    require(os.geteuid() == 0 and socket.gethostname() == 'hetero-dev-1')
    require(Path('/etc/machine-id').read_text().strip() == '381d1ae16f555c59b738d8d01dd14c94')
    require(get('namespace', 'kube-system')['metadata']['uid'] == databases.CLUSTER_UID == storage_plan.CLUSTER_UID)
    nodes = get('nodes')['items']
    require(len(nodes) == 3 and {n['metadata']['name'] for n in nodes} ==
            {f'hetero-dev-{i}' for i in range(1, 4)})
    require(all(any(c['type'] == 'Ready' and c['status'] == 'True'
                    for c in n['status']['conditions']) for n in nodes))
    identity = get('cluster.postgresql.cnpg.io', 'dev-identity-postgres', 'hetero-dev-identity')
    require(identity['status'].get('readyInstances') == 3 and identity['spec']['imageName'] == databases.IMAGE)
    volumes = {p['metadata']['name']: p for p in get('persistentvolumes')['items']}
    for desired in storage_plan.manifest()['items'][1:]:
        if desired['spec']['claimRef']['name'].startswith('dev-postgres-'):
            actual = volumes[desired['metadata']['name']]
            require(contains(actual, desired) and not actual['metadata'].get('deletionTimestamp')
                    and actual['status']['phase'] in ('Available', 'Bound'))
            require(any(m.get('manager') == 'hetero-dev-app-storage'
                        for m in actual['metadata'].get('managedFields', [])))


def apply(phase):
    guard()
    objects = databases.resources(phase)
    # Preflight all ownership conflicts before creating any object in this phase.
    for item in objects:
        meta = item['metadata']
        actual = get(item['kind'], meta['name'], meta.get('namespace'))
        if actual:
            require(not actual['metadata'].get('deletionTimestamp') and contains(actual, item))
            require(any(m.get('manager') == MANAGER for m in actual['metadata'].get('managedFields', [])))
    for item in objects:
        raw = json.dumps(item).encode()
        command = ['apply', '--server-side', '--field-manager=' + MANAGER, '-f', '-']
        run(command + ['--dry-run=server'], raw)
        run(command, raw)
        meta = item['metadata']
        require(contains(get(item['kind'], meta['name'], meta.get('namespace')), item))
    return {'phase': phase, 'applied': True, 'readback_verified': True,
            'resources': len(objects), 'database_ready_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['network', *databases.NAMESPACES])
    args = parser.parse_args()
    try:
        print(json.dumps(apply(args.phase)))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'error': 'DEV database apply stopped; preserve existing resources and inspect events'}))
        raise SystemExit(1)
