#!/usr/bin/env python3
"""Test a Longhorn manager and V1 engine upgrade using only disposable VMs.

This exercises one single-copy degraded fixture, an upgrade while its workload
is running, a rebuild and a healthy-volume live engine upgrade. It is not proof
that production volumes, backups or every upstream rebuild race are safe.
"""
import json
import os
from pathlib import Path
import subprocess
import threading
import urllib.request

import run as fixture
import vms

TARGET_VERSION = '1.12.2'
TARGET_IMAGE = 'docker.io/longhornio/longhorn-engine:v' + TARGET_VERSION
REPORT = {'result': 'failed', 'target_version': TARGET_VERSION, 'samples': []}


def guard():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('HNN_FAULT_E2E') == 'isolated-vms-only'
    assert os.environ.get('KUBECONFIG') == str(fixture.ROOT / 'kubeconfig')
    assert fixture.run(['kubectl', 'config', 'current-context']).strip() == fixture.CONTEXT
    names = {node['metadata']['name'] for node in fixture.get('nodes')['items']}
    assert names == {fixture.CP, fixture.CLUSTER + '-worker', fixture.CLUSTER + '-worker2'}
    inspected = json.loads(fixture.run(['docker', 'inspect', fixture.CP]))[0]
    assert inspected['Config']['Labels']['io.x-k8s.kind.cluster'] == fixture.CLUSTER
    for node in (fixture.CLUSTER + '-worker', fixture.CLUSTER + '-worker2'):
        vms.assert_owned(node)


def patch(kind, name, data):
    fixture.kube('-n', 'longhorn-system', 'patch', kind, name,
                 '--type=merge', '-p', json.dumps(data, separators=(',', ':')))


def volume(name):
    return fixture.get('volumes.longhorn.io', name, 'longhorn-system')


def replica_modes(name):
    engines = fixture.get('engines.longhorn.io', ns='longhorn-system')['items']
    relevant = [engine for engine in engines if engine.get('spec', {}).get('volumeName') == name
                and engine.get('status', {}).get('currentState') == 'running']
    if len(relevant) != 1:
        return []
    return list((relevant[0].get('status', {}).get('replicaModeMap') or {}).values())


def state(name, robustness, rw):
    observed = volume(name)
    modes = replica_modes(name)
    return (observed.get('status', {}).get('state') == 'attached'
            and observed.get('status', {}).get('robustness') == robustness
            and modes.count('RW') == rw and len(modes) == rw)


def endpoint():
    svc = fixture.wait_for('Envoy NodePort', lambda: next((s for s in fixture.get('svc', ns='envoy-gateway-system')['items']
        if s['metadata'].get('labels', {}).get('gateway.envoyproxy.io/owning-gateway-name') == 'fixture'), None), 120)
    port = next(p['nodePort'] for p in svc['spec']['ports'] if p.get('port') == 8080)
    container = json.loads(fixture.run(['docker', 'inspect', fixture.CP]))[0]
    return 'http://' + container['NetworkSettings']['Networks']['kind']['IPAddress'] + ':' + str(port) + '/'


def install_upgrade():
    # Argo applies CRDs when rendering with --include-crds. Helm does not
    # upgrade CRDs itself, so apply the official CRDs before the Helm upgrade.
    rendered = fixture.run(['helm', 'template', 'longhorn', 'longhorn/longhorn', '--version', TARGET_VERSION,
                            '--namespace', 'longhorn-system', '--values', str(fixture.ROOT / 'longhorn.yaml'),
                            '--include-crds'], timeout=90)
    import yaml
    docs = [doc for doc in yaml.safe_load_all(rendered) if doc and doc.get('kind') == 'CustomResourceDefinition']
    assert docs and all(doc.get('metadata', {}).get('name', '').endswith('.longhorn.io') for doc in docs)
    crds = yaml.safe_dump_all(docs)
    command = ['kubectl', '--context', fixture.CONTEXT, '-n', 'longhorn-system',
               'apply', '--server-side', '--force-conflicts', '--field-manager=longhorn-upgrade-e2e', '-f', '-']
    result = subprocess.run(command, input=crds, text=True, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError('isolated CRD update failed: ' + result.stderr[-1200:])
    fixture.run(['helm', 'upgrade', 'longhorn', 'longhorn/longhorn', '--version', TARGET_VERSION,
                 '--namespace', 'longhorn-system', '--values', str(fixture.ROOT / 'longhorn.yaml'),
                 '--kube-context', fixture.CONTEXT, '--wait', '--timeout', '8m'], timeout=540)
    fixture.run(['kubectl', '--context', fixture.CONTEXT, '-n', 'longhorn-system',
                 'rollout', 'status', 'daemonset/longhorn-manager', '--timeout=300s'], timeout=320)
    fixture.wait_for('new default engine image', lambda: fixture.get('settings.longhorn.io',
        'default-engine-image', 'longhorn-system').get('value') == TARGET_IMAGE, 180)
    fixture.wait_for('new engine image deployed', lambda: any(
        item.get('spec', {}).get('image') == TARGET_IMAGE and item.get('status', {}).get('state') == 'deployed'
        for item in fixture.get('engineimages.longhorn.io', ns='longhorn-system')['items']), 300)


def main():
    guard()
    assert (fixture.ROOT / 'longhorn.version').read_text().strip() == '1.12.1'
    url = endpoint()
    fixture.wait_for('initial persistent application', lambda: fixture.probe(url)['data_preserved'], 180)
    with fixture.OPENER.open(url, timeout=3) as response:
        fixture.MARKER = response.read(4096)
    assert len(fixture.MARKER) == len(b'heartbeat-e2e-') + 32
    original = fixture.wait_for('fixture volume', fixture.snapshot, 180)
    name = original['volume']
    assert volume(name)['spec']['dataEngine'] == 'v1'
    fixture.wait_for('two healthy replicas', lambda: state(name, 'healthy', 2), 600)
    # The fixture deliberately leaves one RW copy. Zero disables new rebuilds
    # only in this disposable test, not in the production cluster.
    patch('settings.longhorn.io', 'concurrent-replica-rebuild-per-node-limit', {'value': '0'})
    patch('volumes.longhorn.io', name, {'spec': {'numberOfReplicas': 1}})
    fixture.wait_for('one remaining fixture copy', lambda: state(name, 'healthy', 1), 300)
    patch('volumes.longhorn.io', name, {'spec': {'numberOfReplicas': 2}})
    fixture.wait_for('one-copy degraded fixture', lambda: state(name, 'degraded', 1), 180)
    REPORT['degraded_before_upgrade'] = True

    stop = threading.Event()
    def monitor():
        while not stop.is_set():
            REPORT['samples'].append(fixture.probe(url))
            stop.wait(0.5)
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    try:
        install_upgrade()
        fixture.wait_for('original data after manager upgrade', lambda: fixture.probe(url)['data_preserved'], 300)
        patch('settings.longhorn.io', 'concurrent-replica-rebuild-per-node-limit', {'value': '1'})
        fixture.wait_for('fixture replica rebuild', lambda: state(name, 'healthy', 2), 600)
        REPORT['rebuild_healthy'] = True
        patch('volumes.longhorn.io', name, {'spec': {'image': TARGET_IMAGE}})
        fixture.wait_for('healthy V1 engine upgrade', lambda: state(name, 'healthy', 2) and
                         volume(name).get('status', {}).get('currentImage') == TARGET_IMAGE, 600)
        REPORT['engine_upgraded'] = True
        fixture.wait_for('original data after engine upgrade', lambda: fixture.probe(url)['data_preserved'], 180)
        after = fixture.snapshot()
        assert original['pvc_uid'] == after['pvc_uid'] and name == after['volume']
    finally:
        stop.set()
        thread.join(timeout=5)
    assert REPORT['samples'] and all(sample['data_preserved'] for sample in REPORT['samples'] if sample['status'] == 200)
    REPORT['http_success'] = sum(sample['status'] == 200 for sample in REPORT['samples'])
    REPORT['http_failure'] = sum(sample['status'] != 200 for sample in REPORT['samples'])
    REPORT['result'] = 'passed'
    print(json.dumps({key: value for key, value in REPORT.items() if key != 'samples'}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        REPORT['failure'] = str(error)
        raise
    finally:
        (fixture.ROOT / 'results').mkdir(parents=True, exist_ok=True)
        (fixture.ROOT / 'results' / 'longhorn-upgrade.json').write_text(json.dumps(REPORT, indent=2) + '\n')
