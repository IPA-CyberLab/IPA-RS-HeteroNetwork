#!/usr/bin/env python3
"""Retire the legacy hard DNS placement rule without dropping all DNS replicas."""
import json
from pathlib import Path
import subprocess
import time
import yaml


COMMAND = ['kubectl', '--request-timeout=12s', '-n', 'kube-system']
APP = ['kubectl', '--request-timeout=12s', '-n', 'argocd']


def get(command, kind, name):
    return json.loads(subprocess.check_output(command + ['get', kind, name, '-o', 'json'], timeout=15))


def patch(command, kind, record, edits):
    identity = record['metadata']['uid']
    for attempt in range(8):
        assert record['metadata']['uid'] == identity
        guards = [{'op': 'test', 'path': '/metadata/' + key, 'value': record['metadata'][key]}
                  for key in ['uid', 'resourceVersion']]
        result = subprocess.run(command + ['patch', kind, record['metadata']['name'], '--type=json', '--patch-file=/dev/stdin'],
                                input=json.dumps(guards + edits), text=True, capture_output=True, timeout=15)
        if not result.returncode:
            return
        time.sleep(0.2 * (attempt + 1))
        record = get(command, kind, record['metadata']['name'])
    raise RuntimeError('guarded DNS migration rejected; protected output withheld')



def main():
    manifest = Path(__file__).resolve().parents[1] / 'deploy/gitops/cluster-dns/coredns.yaml'
    desired = next(d for d in yaml.safe_load_all(manifest.read_text()) if d['kind'] == 'Deployment')
    assert desired['metadata']['name'] == 'coredns' and desired['metadata']['namespace'] == 'kube-system'
    target = desired['spec']['template']['spec']
    assert target['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'] == []
    legacy = [{'labelSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}, 'topologyKey': 'kubernetes.io/hostname'}]
    actual = get(COMMAND, 'deployment', 'coredns')
    pod = actual['spec']['template']['spec']
    assert actual['spec']['replicas'] == 3
    assert actual['spec']['selector']['matchLabels'] == {'k8s-app': 'kube-dns'}
    assert pod['containers'][0]['image'] == target['containers'][0]['image']
    affinity = pod['affinity']['podAntiAffinity']
    assert affinity['preferredDuringSchedulingIgnoredDuringExecution'] == target['affinity']['podAntiAffinity']['preferredDuringSchedulingIgnoredDuringExecution']
    current = affinity.get('requiredDuringSchedulingIgnoredDuringExecution', [])
    assert current in ([], legacy), 'unrecognized placement rule; refusing to replace it'
    if not current and actual.get('status', {}).get('updatedReplicas', 0) >= 3 and actual['status'].get('availableReplicas', 0) >= 3:
        print(json.dumps({'legacy_rule_retired': True, 'changed': False}))
        return
    assert actual.get('status', {}).get('availableReplicas', 0) >= 2
    original_strategy = desired['spec']['strategy']
    app = get(APP, 'application', 'cluster-dns')
    automated = app['spec']['syncPolicy'].get('automated')
    paused = False
    try:
        # Existing Pods retain immutable hard anti-affinity. Temporarily keep at
        # least one DNS replica while replacing the first of two old replicas.
        if automated is not None and automated.get('enabled') is not False:
            patch(APP, 'application', app, [{'op': 'add', 'path': '/spec/syncPolicy/automated/enabled', 'value': False}])
            paused = True
        actual = get(COMMAND, 'deployment', 'coredns')
        edits = []
        if current:
            edits.append({'op': 'replace', 'path': '/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution', 'value': []})
        if actual['status'].get('availableReplicas', 0) == 2:
            edits.append({'op': 'replace', 'path': '/spec/strategy/rollingUpdate/maxUnavailable', 'value': 2})
        if edits:
            patch(COMMAND, 'deployment', actual, edits)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            actual = get(COMMAND, 'deployment', 'coredns')
            status = actual.get('status', {})
            if status.get('updatedReplicas', 0) >= 3 and status.get('availableReplicas', 0) >= 3:
                print(json.dumps({'legacy_rule_retired': True, 'changed': bool(edits), 'available_dns_replicas': 3}))
                return
            if status.get('availableReplicas', 0) < 1:
                raise RuntimeError('DNS minimum availability was lost')
            time.sleep(2)
        raise RuntimeError('DNS migration readiness deadline exceeded')
    finally:
        actual = get(COMMAND, 'deployment', 'coredns')
        if actual['spec']['strategy'].get('rollingUpdate', {}).get('maxUnavailable') != 1:
            patch(COMMAND, 'deployment', actual, [{'op': 'replace', 'path': '/spec/strategy', 'value': original_strategy}])
        if paused:
            current_app = get(APP, 'application', 'cluster-dns')
            assert current_app['metadata']['uid'] == app['metadata']['uid']
            if current_app['spec']['syncPolicy']['automated'].get('enabled') is False:
                restore = {'op': 'replace', 'path': '/spec/syncPolicy/automated/enabled', 'value': automated['enabled']} if 'enabled' in automated else {'op': 'remove', 'path': '/spec/syncPolicy/automated/enabled'}
                patch(APP, 'application', current_app, [restore])


if __name__ == '__main__':
    main()
