#!/usr/bin/env python3
"""Exercise one retained 1Gi DEV RWX fixture across three real gVisor Pods."""
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import uuid

NS = 'hetero-dev-rwx-check'
OWNER = 'hetero-dev-rwx-check'
UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit@sha256:6f532540530d5673f4030dc5a29bde5f0d4511261d1b1e2caab28aead3529db0'


def metadata(name, namespace=NS):
    m = {'name': name, 'labels': {'app.kubernetes.io/managed-by': OWNER},
         'annotations': {'heteronetwork.dev.cluster-uid': UID}}
    if namespace:
        m['namespace'] = namespace
    return m


def pod(index):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': metadata('rwx-' + str(index)),
            'spec': {'nodeName': 'hetero-dev-' + str(index), 'runtimeClassName': 'gvisor',
                     'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                     'activeDeadlineSeconds': 900,
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                                         'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'probe', 'image': IMAGE,
                         'command': ['sh', '-ec', "dmesg | grep -q 'Starting gVisor'; exec sleep 850"],
                         'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'},
                                       'limits': {'cpu': '500m', 'memory': '256Mi'}},
                         'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                             'capabilities': {'drop': ['ALL']}},
                         'volumeMounts': [{'name': 'shared', 'mountPath': '/shared'}]}],
                     'volumes': [{'name': 'shared', 'persistentVolumeClaim': {'claimName': 'shared'}}]}}


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    h.guard()

    def get(kind, name, namespace=NS):
        raw = h.run(['get', kind, name, *(['-n', namespace] if namespace else []), '--ignore-not-found', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    def owned(obj):
        h.require(obj and obj['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == OWNER
                  and obj['metadata'].get('annotations', {}).get('heteronetwork.dev.cluster-uid') == UID
                  and not obj['metadata'].get('deletionTimestamp'))

    def ensure(obj, namespace=NS):
        existing = get(obj['kind'], obj['metadata']['name'], namespace)
        if existing:
            owned(existing)
            return existing
        h.run(['create', '--dry-run=server', '-f', '-'], json.dumps(obj).encode())
        return json.loads(h.run(['create', '-f', '-', '-o', 'json'], json.dumps(obj).encode()))

    def start(index):
        desired = pod(index)
        h.require(get('pod', desired['metadata']['name']) is None)
        actual = ensure(desired)
        h.run(['wait', '-n', NS, 'pod/' + actual['metadata']['name'], '--for=condition=Ready', '--timeout=100s'])
        return actual

    def stop(obj):
        current = get('pod', obj['metadata']['name'])
        owned(current)
        h.require(current['metadata']['uid'] == obj['metadata']['uid'])
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                   'preconditions': {k: current['metadata'][k] for k in ('uid', 'resourceVersion')}}
        h.run(['delete', '--raw', '/api/v1/namespaces/' + NS + '/pods/' + obj['metadata']['name'], '-f', '-'],
              json.dumps(options).encode())
        h.run(['wait', '-n', NS, 'pod/' + obj['metadata']['name'], '--for=delete', '--timeout=100s'])

    def execute(index, command):
        return h.run(['exec', '-n', NS, 'rwx-' + str(index), '--', *command])

    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': metadata(NS, None)}
    namespace['metadata']['labels'].update({'release.heteronetwork.io/channel': 'dev',
                                          'pod-security.kubernetes.io/enforce': 'restricted'})
    actual = ensure(namespace, None)
    h.require(all(actual['metadata']['labels'].get(k) == v for k, v in namespace['metadata']['labels'].items()))
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': metadata('deny-all'),
              'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}}
    h.require(ensure(policy)['spec'] == policy['spec'])
    claim = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': metadata('shared'),
             'spec': {'accessModes': ['ReadWriteMany'], 'volumeMode': 'Filesystem',
                      'storageClassName': 'dev-flash-rwx', 'resources': {'requests': {'storage': '1Gi'}}}}
    actual = ensure(claim)
    h.require(all(actual['spec'].get(k) == v for k, v in claim['spec'].items()))
    h.run(['wait', '-n', NS, 'pvc/shared', '--for=jsonpath={.status.phase}=Bound', '--timeout=100s'])
    pods = [start(i) for i in range(1, 4)]
    expected = {i: uuid.uuid4().hex.encode() for i in range(1, 4)}
    for i, content in expected.items():
        execute(i, ['sh', '-ec', 'printf %s "$1" > /shared/writer-"$2"; sync', 'write', content.decode(), str(i)])
    for i in range(1, 4):
        for writer, content in expected.items():
            h.require(execute(i, ['cat', '/shared/writer-' + str(writer)]) == content)
    stop(pods[0])
    replacement = start(1)
    h.require(replacement['metadata']['uid'] != pods[0]['metadata']['uid'])
    pods[0] = replacement
    for writer, content in expected.items():
        h.require(execute(1, ['cat', '/shared/writer-' + str(writer)]) == content)
    pv = get('pv', get('pvc', 'shared')['spec']['volumeName'], None)
    h.require(pv['spec']['csi']['driver'] == 'driver.longhorn.io')
    handle = pv['spec']['csi']['volumeHandle']
    deadline = time.monotonic() + 90
    while True:
        volume = get('volumes.longhorn.io', handle, 'longhorn-system')
        if volume['status'].get('robustness') == 'healthy':
            break
        h.require(time.monotonic() < deadline)
        time.sleep(3)
    replicas = json.loads(h.run(['get', 'replicas.longhorn.io', '-n', 'longhorn-system', '-o', 'json']))['items']
    replicas = [r for r in replicas if r['spec']['volumeName'] == handle]
    h.require(volume['spec']['numberOfReplicas'] == 3 and len(replicas) == 3
              and {r['spec']['nodeID'] for r in replicas} == {'hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3'}
              and all(r['status']['currentState'] == 'running' for r in replicas))
    for obj in pods:
        stop(obj)
    h.guard()
    print(json.dumps({'rwx_cross_node_reads': 9, 'gvisor_nodes': 3, 'replacement_reads': 3,
                      'healthy_replicas': 3, 'pods_cleaned': True, 'fixture_retained_gib': 1,
                      'node_failure_ha_verified': False}), flush=True)


if __name__ == '__main__':
    main()
