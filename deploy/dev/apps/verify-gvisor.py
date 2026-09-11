#!/usr/bin/env python3
"""Verify each DEV runtime with a real Pod before advertising gVisor readiness."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
NS = 'heterocloud-flash-dev'
UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
MANAGER = 'hetero-dev-gvisor-probe'
LABEL = 'flash.heterocloud.io/gvisor-ready'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit@sha256:6f532540530d5673f4030dc5a29bde5f0d4511261d1b1e2caab28aead3529db0'


def metadata(name, namespace=None):
    value = {'name': name, 'annotations': {'heteronetwork.dev.cluster-uid': UID},
             'labels': {'app.kubernetes.io/managed-by': MANAGER}}
    if namespace:
        value['namespace'] = namespace
    return value


def probe(node):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': metadata('gvisor-probe-' + node, NS),
            'spec': {'nodeName': node, 'runtimeClassName': 'hetero-dev-gvisor-probe',
                     'restartPolicy': 'Never', 'activeDeadlineSeconds': 120, 'automountServiceAccountToken': False,
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532,
                                         'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'probe', 'image': IMAGE,
                         'command': ['sh', '-c', "dmesg | grep -q 'Starting gVisor' && printf 'GVISOR_SMOKE_OK\\n'"],
                         'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'},
                                       'limits': {'cpu': '500m', 'memory': '256Mi'}},
                         'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                             'capabilities': {'drop': ['ALL']}}}]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', choices=[f'hetero-dev-{i}' for i in range(1, 4)], required=True)
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()

    def get(kind, name, namespace=None):
        raw = helper.run(['get', kind, name, *(['-n', namespace] if namespace else []), '--ignore-not-found', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    def owned(obj):
        helper.require(obj['metadata'].get('annotations', {}).get('heteronetwork.dev.cluster-uid') == UID
                       and obj['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == MANAGER
                       and not obj['metadata'].get('deletionTimestamp'))

    def ensure_runtime(name, scheduling=None):
        desired = {'apiVersion': 'node.k8s.io/v1', 'kind': 'RuntimeClass', 'metadata': metadata(name), 'handler': 'runsc'}
        if scheduling:
            desired['scheduling'] = scheduling
        actual = get('runtimeclass', name)
        if actual:
            owned(actual)
            helper.require(actual['handler'] == 'runsc' and actual.get('scheduling') == scheduling)
        else:
            helper.run(['create', '--dry-run=server', '-f', '-'], json.dumps(desired).encode())
            helper.run(['create', '-f', '-'], json.dumps(desired).encode())

    def delete(kind, name, obj, namespace=None):
        owned(obj)
        current = get(kind, name, namespace)
        owned(current)
        helper.require(current['metadata']['uid'] == obj['metadata']['uid'])
        if kind == 'pod':
            helper.require(current['status']['phase'] == 'Succeeded')
        prefix = f'/api/v1/namespaces/{namespace}/pods/' if kind == 'pod' else '/apis/node.k8s.io/v1/runtimeclasses/'
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                   'preconditions': {key: current['metadata'][key] for key in ('uid', 'resourceVersion')}}
        helper.run(['delete', '--raw', prefix + name, '-f', '-'], json.dumps(options).encode())

    helper.require(get('namespace', NS)['metadata']['labels'].get('release.heteronetwork.io/channel') == 'dev')
    ensure_runtime('hetero-dev-gvisor-probe')
    desired = probe(args.node)
    name = desired['metadata']['name']
    actual = get('pod', name, NS)
    if actual:
        owned(actual)
        helper.require(actual['spec']['nodeName'] == args.node and actual['spec']['runtimeClassName'] == 'hetero-dev-gvisor-probe'
                       and actual['spec']['containers'][0]['image'] == IMAGE
                       and actual['spec']['containers'][0]['command'] == desired['spec']['containers'][0]['command'])
    else:
        helper.run(['create', '--dry-run=server', '-f', '-'], json.dumps(desired).encode())
        helper.run(['create', '-f', '-'], json.dumps(desired).encode())
    helper.run(['wait', '-n', NS, 'pod/' + name, '--for=jsonpath={.status.phase}=Succeeded', '--timeout=100s'])
    helper.require(helper.run(['logs', '-n', NS, name]).strip() == b'GVISOR_SMOKE_OK')
    actual = get('pod', name, NS)
    helper.require(actual['status']['phase'] == 'Succeeded')
    node = get('node', args.node)
    labels = node['metadata']['labels']
    helper.require(labels.get(LABEL) in (None, 'true'))
    if labels.get(LABEL) is None:
        patch = [{'op': 'test', 'path': '/metadata/' + key, 'value': node['metadata'][key]} for key in ('uid', 'resourceVersion')]
        patch.append({'op': 'add', 'path': '/metadata/labels/' + LABEL.replace('/', '~1'), 'value': 'true'})
        helper.run(['patch', 'node', args.node, '--type=json', '--patch', json.dumps(patch)])
    ensure_runtime('gvisor', {'nodeSelector': {LABEL: 'true'}})
    delete('pod', name, actual, NS)
    helper.run(['wait', '-n', NS, 'pod/' + name, '--for=delete', '--timeout=30s'])
    delete('runtimeclass', 'hetero-dev-gvisor-probe', get('runtimeclass', 'hetero-dev-gvisor-probe'))
    print(json.dumps({'node': args.node, 'sandbox_execution_verified': True, 'ready_label_set': True,
                      'runtime_class': 'gvisor', 'probe_cleaned_up': True}), flush=True)


if __name__ == '__main__':
    main()
