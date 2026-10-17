#!/usr/bin/env python3
"""Reproduce and repair an unbounded init-container Pod on the native worker.

Only an isolated, nonce-labelled Deployment/PVC is created. The real helper
image is selected from an observed initializer; no tenant secrets are copied.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import time
from types import SimpleNamespace

from security_inventory import atomic_json, utc_now
from security_runtime_restart import Controller, IMAGE, probe_command, ready
from security_runtime_restart_host import require
from security_runtime_restart_e2e import KindController


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', default='uc-k8sp5')
    parser.add_argument('--kubeconfig', default='/etc/kubernetes/admin.conf')
    parser.add_argument('--kind', action='store_true')
    parser.add_argument('--helper-image')
    args = parser.parse_args()
    require(os.geteuid() == 0 and args.node == ('runtime-restart-e2e-control-plane' if args.kind else 'uc-k8sp5'),
            'only an isolated acceptance worker is allowed')
    policy_path = Path(__file__).resolve().parents[1] / 'deploy/security/policy.json' if args.kind else Path('/opt/heteronetwork/security/policy.json')
    config = json.loads(policy_path.read_text())
    production_namespace = config['restart']['namespace']
    config['restart']['namespace'] = config['restart']['probe_namespace']
    namespace = config['restart']['namespace']
    root = Path('/var/lib/heteronetwork-security/initializer-memory-e2e')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.kind:
        atomic_json(root / 'hosts.json', [{'name': args.node, 'ssh_host': 'unused-in-kind'}])
        atomic_json(root / 'health.json', {'health_probes': []})
    arguments = SimpleNamespace(output=str(root), hosts=str(root / 'hosts.json') if args.kind else '/etc/heteronetwork/security/hosts.json', kubectl='kubectl',
                                kubeconfig=args.kubeconfig, storage_class=None if args.kind else 'longhorn', probe_only=True,
                                restart_key='/etc/heteronetwork/security/restart.key', known_hosts='/etc/heteronetwork/security/known_hosts',
                                health_policy=str(root / 'health.json') if args.kind else '/opt/heteronetwork/security/promotion.json')
    control = (KindController if args.kind else Controller)(arguments, config)
    control.health()
    observed = [] if args.kind else control.kube('get', 'pods', '-n', production_namespace,
                                               '--field-selector=spec.nodeName=' + args.node, '-o', 'json')['items']
    images = [args.helper_image] if args.kind and args.helper_image else [c['image'] for p in observed for c in p['spec'].get('initContainers', []) if c['name'] == 'flash-secret-launcher']
    require(images, 'an observed, cached initializer image is required')
    token = secrets.token_hex(16)
    name = 'initializer-memory-' + token[:12]
    label = {'security.heteronetwork.io/memory-probe': token}
    pvc = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name, 'namespace': namespace, 'labels': label},
           'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '100Mi'}},
                    **({'storageClassName': 'longhorn'} if not args.kind else {})}}
    spec = {'nodeSelector': {'kubernetes.io/hostname': args.node}, 'runtimeClassName': 'gvisor', 'restartPolicy': 'Always',
            'terminationGracePeriodSeconds': 5, 'automountServiceAccountToken': False,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': name}}, {'name': 'temp', 'emptyDir': {}},
                        {'name': 'flash-secret-launcher', 'emptyDir': {'medium': 'Memory'}}],
            'initContainers': [{'name': 'flash-secret-launcher', 'image': images[0], 'imagePullPolicy': 'IfNotPresent',
                                'command': ['/bin/cp', '/usr/local/bin/flash-secret-env-launcher', '/run/flash-helper/launcher'],
                                'resources': {}, 'volumeMounts': [{'name': 'flash-secret-launcher', 'mountPath': '/run/flash-helper'}],
                                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}}],
            'containers': [{'name': 'probe', 'image': IMAGE, 'command': probe_command(token),
                            'resources': {'requests': {'cpu': '10m', 'memory': '64Mi'}, 'limits': {'cpu': '100m', 'memory': '128Mi'}},
                            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                            'readinessProbe': {'httpGet': {'path': '/marker', 'port': 8080}, 'periodSeconds': 1},
                            'volumeMounts': [{'name': 'data', 'mountPath': '/persistent'}, {'name': 'temp', 'mountPath': '/temporary'}]}]}
    deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': namespace, 'labels': label},
                  'spec': {'replicas': 1, 'selector': {'matchLabels': label}, 'template': {'metadata': {'labels': label}, 'spec': spec}}}
    created = []
    try:
        for body in [pvc, deployment]:
            resource = control.kube('create', '-f', '-', '-o', 'json', body=body)
            created.append((resource['kind'].lower(), resource['metadata']['uid']))
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            pods = control.kube('get', 'pods', '-n', namespace, '-l', 'security.heteronetwork.io/memory-probe=' + token, '-o', 'json')['items']
            if len(pods) == 1 and ready(pods[0]):
                pod = pods[0]
                break
            time.sleep(2)
        else:
            raise RuntimeError('unbounded-init memory probe did not become ready')
        before = control.sandbox(control.remote(args.node), pod['metadata']['uid'])
        unbounded = before['memory_max'] is None or before['memory_max'] > 128 * 1024 * 1024
        ids = [s['containerID'] for s in pod['status']['containerStatuses']]
        repaired = control.repair_initializer(pod, control.remote(args.node))
        time.sleep(10)
        current = control.get('pod', pod['metadata']['name'], namespace)
        require(current and current['metadata']['uid'] == pod['metadata']['uid'] and ready(current), 'resource repair recreated or stopped the Pod')
        require([s['containerID'] for s in current['status']['containerStatuses']] == ids, 'resource repair must not restart the application')
        result = control.restart(repaired, control.remote(args.node), probe=True)
        after = control.sandbox(control.remote(result['node']), result['pod_uid'])
        require(after['memory_max'] == 128 * 1024 * 1024, 'sandbox memory did not match the workload budget after restart')
        marker = control.kube('exec', result['pod'], '-n', namespace, '--', 'cat', '/persistent/marker', text=True).strip()
        require(marker == token, 'memory-boundary repair lost persistent data')
        accepted = {'status': 'verified', 'verified_at': utc_now(), 'before_memory_max': before['memory_max'],
                    'unbounded_runtime_reproduced': unbounded,
                    'after_memory_max': after['memory_max'], 'same_pod_uid': result['same_pod_uid'], 'no_extra_restart_during_repair': True,
                    'persistent_data_retained': True, 'restart': result}
        atomic_json(root / 'acceptance.json', accepted)
        print(json.dumps(accepted), flush=True)
    finally:
        for kind, uid in reversed(created):
            current = control.get(kind, name, namespace)
            if (current and current['metadata']['uid'] == uid
                    and current['metadata'].get('labels', {}).get('security.heteronetwork.io/memory-probe') == token):
                control.kube('delete', kind, name, '-n', namespace, '--wait=false', text=True)
                if kind == 'deployment':
                    deadline = time.monotonic() + 60
                    while time.monotonic() < deadline:
                        pods = control.kube('get', 'pods', '-n', namespace, '-l', 'security.heteronetwork.io/memory-probe=' + token, '-o', 'json')['items']
                        if not pods:
                            break
                        time.sleep(2)
                    require(not pods, 'memory-probe cleanup did not finish; its disk was retained')


if __name__ == '__main__':
    main()
