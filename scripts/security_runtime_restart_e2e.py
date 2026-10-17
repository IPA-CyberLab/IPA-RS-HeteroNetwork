#!/usr/bin/env python3
"""Real Kubernetes/containerd restart, disk retention, and rollback acceptance.

Run only against the disposable kind cluster from the matching Actions job.
The production controller/host endpoint execute unchanged; Docker stdin replaces
the transport to a node that has no SSH daemon. Production SSH is tested by the
same native canary on the fleet before enabling its timer.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
from types import SimpleNamespace

from security_inventory import atomic_json, utc_now
from security_runtime_restart import Controller, IMAGE, ready
from security_runtime_restart_host import require


def command(args, body=None):
    result = subprocess.run(args, input=body, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, 'isolated Kubernetes runtime test command failed: ' + args[0] + ': ' + result.stderr[-500:])
    return result.stdout


class KindController(Controller):
    def remote(self, node, action='inspect', **fields):
        challenge = secrets.token_hex(32)
        value = json.loads(command(['docker', 'exec', '-i', node, 'python3',
                                    '/opt/heteronetwork/security/security_runtime_restart_host.py'],
                                   json.dumps({'action': action, 'challenge': challenge, **fields}) + '\n'))
        require(value.get('challenge') == challenge and value.get('status') != 'error', 'real node endpoint rejected the request')
        return value


def install(node, source):
    destination = '/var/lib/heteronetwork-security/runtime-stage'
    command(['docker', 'exec', node, 'mkdir', '-p', destination])
    command(['docker', 'cp', str(source) + '/.', node + ':' + destination])
    code = '''from pathlib import Path
import os,shutil
stage=Path('/var/lib/heteronetwork-security/runtime-stage')
files=[stage/'runsc',stage/'containerd-shim-runsc-v1']+list((stage/'gvisor-bin').rglob('*'))
for source in files:
 if not source.is_file():continue
 relative=source.relative_to(stage)
 assert '..' not in relative.parts
 target=Path('/usr/bin')/relative
 target.parent.mkdir(parents=True,exist_ok=True)
 temporary=target.with_name('.'+target.name+'.test-new')
 shutil.copy2(source,temporary);os.chown(temporary,0,0);temporary.chmod(0o755)
 os.replace(temporary,target)
'''
    command(['docker', 'exec', node, 'python3', '-c', code])


def fixture(controller, node):
    namespace = controller.policy['namespace']
    if not controller.get('namespace', namespace, namespace):
        controller.kube('create', '-f', '-', '-o', 'json', body={'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}})
    token = secrets.token_hex(16)
    name = 'restart-test-' + token[:12]
    controller.kube('create', '-f', '-', '-o', 'json', body={
        'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name, 'namespace': namespace},
        'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '100Mi'}}}})
    controller.kube('create', '-f', '-', '-o', 'json', body={
        'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace},
        'spec': {'nodeSelector': {'kubernetes.io/hostname': node}, 'runtimeClassName': 'gvisor', 'restartPolicy': 'Always',
                 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 5,
                 'securityContext': {'runAsUser': 65532, 'runAsNonRoot': True, 'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
                 'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': name}}, {'name': 'temp', 'emptyDir': {}}],
                 'containers': [{'name': 'app', 'image': IMAGE,
                                 'command': ['/bin/sh', '-ec', 'test -f /persistent/marker || printf %s ' + token + ' > /persistent/marker; '
                                             'dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 > /temporary/boot; '
                                             'exec httpd -f -p 8080 -h /persistent'],
                                 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
                                 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                 'readinessProbe': {'httpGet': {'path': '/marker', 'port': 8080}, 'periodSeconds': 1},
                                 'volumeMounts': [{'name': 'data', 'mountPath': '/persistent'}, {'name': 'temp', 'mountPath': '/temporary'}]}]}})
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        pod = controller.get('pod', name, namespace)
        if ready(pod):
            return pod, token
        time.sleep(2)
    raise RuntimeError('real restart fixture did not become ready')


def disk(controller, pod):
    namespace, name = pod['metadata']['namespace'], pod['metadata']['name']
    marker = controller.kube('exec', name, '-n', namespace, '--', 'cat', '/persistent/marker', text=True).strip()
    boot = controller.kube('exec', name, '-n', namespace, '--', 'cat', '/temporary/boot', text=True).strip()
    return marker, boot


def delete_fixture(controller, pod):
    namespace, name = pod['metadata']['namespace'], pod['metadata']['name']
    controller.kube('delete', 'pod', name, '-n', namespace, '--wait=false', text=True)
    deadline = time.monotonic() + 60
    while controller.get('pod', name, namespace) and time.monotonic() < deadline:
        time.sleep(1)
    require(not controller.get('pod', name, namespace), 'test Pod did not terminate')
    controller.kube('delete', 'pvc', name, '-n', namespace, '--wait=false', text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--bundles', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and args.node == 'runtime-restart-e2e-control-plane', 'only the isolated kind test node is allowed')
    repository = Path(__file__).resolve().parents[1]
    root = Path('/var/lib/heteronetwork-security/restart-e2e')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy = json.loads((repository / 'deploy/security/policy.json').read_text())
    hosts = root / 'hosts.json'
    atomic_json(hosts, [{'name': args.node, 'ssh_host': 'unused-in-kind'}])
    health = root / 'health.json'
    atomic_json(health, {'health_probes': []})
    shared = SimpleNamespace(output=str(root / 'success'), hosts=str(hosts), kubectl='kubectl', kubeconfig=args.kubeconfig,
                             storage_class=None, probe_only=False, health_policy=str(health))
    controller = KindController(shared, policy)
    controller.kube('create', '-f', '-', '-o', 'json', body={'apiVersion': 'node.k8s.io/v1', 'kind': 'RuntimeClass',
                                                          'metadata': {'name': 'gvisor'}, 'handler': 'runsc'})
    source = Path(args.bundles) / 'release-20261005.0'
    target = Path(args.bundles) / 'release-20261012.0'
    install(args.node, source)
    command(['docker', 'exec', args.node, 'systemctl', 'restart', 'containerd'])
    pod, token = fixture(controller, args.node)
    before = controller.remote(args.node)
    original = controller.sandbox(before, pod['metadata']['uid'])
    _, boot = disk(controller, pod)
    command(['docker', 'exec', args.node, 'python3', '/opt/heteronetwork/security/security_runtime_restart_host.py', '--prepare-install'])
    install(args.node, target)
    result = controller.reconcile(args.node)
    marker, boot_after = disk(controller, pod)
    require(result['status'] == 'verified' and len(result['workloads']) == 1, 'real target activation failed')
    require(marker == token and boot_after != boot, 'data did not survive a real application restart')
    active = controller.sandbox(controller.remote(args.node), pod['metadata']['uid'])
    require(active['id'] != original['id'] and active['exe_sha256'] != original['exe_sha256'], 'old and new real Sentry identities did not change')
    require(controller.reconcile(args.node)['status'] == 'current', 'second reconciliation should not restart anything')
    require(controller.sandbox(controller.remote(args.node), pod['metadata']['uid'])['id'] == active['id'], 'reconciliation repeated a restart')
    success = {'status': 'verified', 'persistent_data_retained': True, 'same_pod_uid': True,
               'source_sentry': original['exe_sha256'], 'target_sentry': active['exe_sha256'], 'activation': result}
    delete_fixture(controller, pod)

    # Restore the old *real* runtime for an independent failure/recovery case.
    current = controller.remote(args.node)
    controller.remote(args.node, 'rollback', artifact_sha256=current['artifact']['sha256'])
    pod, token = fixture(controller, args.node)
    marker, boot = disk(controller, pod)
    command(['docker', 'exec', args.node, 'python3', '/opt/heteronetwork/security/security_runtime_restart_host.py', '--prepare-install'])
    install(args.node, target)
    bad_sentry = controller.remote(args.node)['artifact']['sentry_sha256']
    # A real HTTP dependency returns 503 only while this workload runs under
    # the new Sentry. This forces the production controller's post-start health
    # path to restore the previous runtime and restart/recover the same Pod.
    class Health(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                observed = controller.remote(args.node)
                source = controller.sandbox(observed, pod['metadata']['uid'])
                code = 503 if source['exe_sha256'] == bad_sentry else 200
            except Exception:
                code = 503
            self.send_response(code)
            self.end_headers()
        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Health)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    atomic_json(health, {'health_probes': [{'url': 'http://127.0.0.1:' + str(server.server_port), 'deadline_seconds': 10}]})
    shared.output = str(root / 'rollback')
    controller = KindController(shared, policy)
    try:
        try:
            controller.reconcile(args.node)
        except Exception:
            pass
        else:
            raise RuntimeError('real 503 injection was not rejected')
        record = json.loads(next((root / 'rollback').glob('held-*.json')).read_text())
        require(record.get('recovery', {}).get('status') == 'rollback-verified', 'real runtime rollback did not recover the workload')
        marker, boot_after = disk(controller, pod)
        require(marker == token and boot_after != boot, 'rollback did not retain the persistent data')
        controller.health()
        success['injected_503_recovery'] = record
    finally:
        server.shutdown()
        server.server_close()
        delete_fixture(controller, pod)
    success['verified_at'] = utc_now()
    atomic_json(args.output, success)
    print(json.dumps({'status': 'verified', 'persistent_data_retained': True, 'rollback_verified': True,
                      'source_sentry': success['source_sentry'], 'target_sentry': success['target_sentry']}))


if __name__ == '__main__':
    main()
