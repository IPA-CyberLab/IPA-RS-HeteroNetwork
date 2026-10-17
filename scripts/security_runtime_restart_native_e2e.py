#!/usr/bin/env python3
"""Exercise the restricted native SSH/CRI path using only isolated test Pods.

The operator installs the pinned package through the normal IaC playbook when
the protected progress file says awaiting-package. No test restarts a user Pod.
Only the declared bootstrap worker is supported by this operator acceptance.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

from security_inventory import atomic_json, utc_now
from security_runtime_restart import Controller
from security_runtime_restart_e2e import fixture, disk, delete_fixture
from security_runtime_restart_host import require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', default='uc-k8sp5')
    parser.add_argument('--target-version', default='release-20261012.0')
    args = parser.parse_args()
    require(os.geteuid() == 0 and args.node == 'uc-k8sp5', 'only the declared native acceptance worker is allowed')
    root = Path('/var/lib/heteronetwork-security/native-restart-e2e')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    progress = root / 'progress.json'
    policy = json.loads(Path('/opt/heteronetwork/security/policy.json').read_text())
    policy['restart']['namespace'] = policy['restart']['probe_namespace']
    shared = SimpleNamespace(output=str(root / 'success'), hosts='/etc/heteronetwork/security/hosts.json',
                             kubectl='kubectl', kubeconfig='/etc/kubernetes/admin.conf', storage_class='longhorn',
                             probe_only=False, health_policy='/opt/heteronetwork/security/promotion.json',
                             restart_key='/etc/heteronetwork/security/restart.key',
                             known_hosts='/etc/heteronetwork/security/known_hosts')
    controller = Controller(shared, policy)
    controller.health()

    def await_package(phase):
        atomic_json(progress, {'phase': 'awaiting-package', 'case': phase, 'target_version': args.target_version, 'observed_at': utc_now()})
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            node = controller.kube('get', 'node', args.node, '-o', 'json')
            if node['metadata'].get('labels', {}).get('flash.heterocloud.io/gvisor-ready') == 'true':
                try:
                    observed = controller.remote(args.node)
                    if observed['artifact']['version'] == 'runsc version ' + args.target_version:
                        return observed
                except (RuntimeError, ValueError, OSError):
                    pass  # APT may be atomically replacing a bundle member.
            time.sleep(5)
        raise RuntimeError('operator did not install the pinned package before the acceptance deadline')

    source = controller.remote(args.node)
    require(source['artifact']['version'] != 'runsc version ' + args.target_version, 'source and target must be distinct real versions')
    pod, token = fixture(controller, args.node)
    original = controller.sandbox(controller.remote(args.node), pod['metadata']['uid'])
    marker, boot = disk(controller, pod)
    result = {}
    try:
        await_package('upgrade')
        accepted = controller.reconcile(args.node)
        marker, next_boot = disk(controller, pod)
        require(accepted['status'] == 'verified' and len(accepted['workloads']) == 1, 'native version activation was not verified')
        require(marker == token and boot != next_boot, 'native persistent data did not survive a real restart')
        active = controller.sandbox(controller.remote(args.node), pod['metadata']['uid'])
        require(active['id'] != original['id'] and active['exe_sha256'] != original['exe_sha256'], 'native Sentry identity did not change')
        require(controller.reconcile(args.node)['status'] == 'current', 'native reconciliation must not restart an already current Pod')
        require(controller.sandbox(controller.remote(args.node), pod['metadata']['uid'])['id'] == active['id'], 'native restart repeated')
        result['upgrade'] = accepted
    finally:
        delete_fixture(controller, pod)

    observed = controller.remote(args.node)
    controller.remote(args.node, 'rollback', artifact_sha256=observed['artifact']['sha256'])
    require(controller.remote(args.node)['artifact']['sha256'] == source['artifact']['sha256'], 'native old runtime was not restored')
    pod, token = fixture(controller, args.node)
    marker, boot = disk(controller, pod)
    await_package('injected-503')
    target = controller.remote(args.node)['artifact']['sentry_sha256']
    class Health(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                source = controller.sandbox(controller.remote(args.node), pod['metadata']['uid'])
                code = 503 if source['exe_sha256'] == target else 200
            except Exception:
                code = 503
            self.send_response(code)
            self.end_headers()
        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Health)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    health = root / 'health.json'
    atomic_json(health, {'health_probes': [{'url': 'http://127.0.0.1:' + str(server.server_port), 'deadline_seconds': 10}]})
    shared.health_policy = str(health)
    shared.output = str(root / 'rollback')
    controller = Controller(shared, policy)
    try:
        try:
            controller.reconcile(args.node)
        except Exception:
            pass
        else:
            raise RuntimeError('injected real HTTP 503 must fail acceptance')
        record = json.loads(next((root / 'rollback').glob('held-*.json')).read_text())
        require(record.get('recovery', {}).get('status') == 'rollback-verified', 'native workload recovery was not verified')
        marker, next_boot = disk(controller, pod)
        require(marker == token and next_boot != boot, 'native recovery did not preserve the disk marker')
        controller.health()
        result['injected_503_recovery'] = record
    finally:
        server.shutdown()
        server.server_close()
        delete_fixture(controller, pod)
    await_package('final-approved-install')
    shared.health_policy = '/opt/heteronetwork/security/promotion.json'
    shared.output = str(root / 'final')
    shared.probe_only = True
    controller = Controller(shared, policy)
    result['final'] = controller.reconcile(args.node)
    controller.health()
    result.update(status='verified', verified_at=utc_now(), scope='isolated-native-ssh-kubernetes-pods')
    atomic_json(root / 'acceptance.json', result)
    atomic_json(progress, {'phase': 'verified', 'observed_at': utc_now()})
    print(json.dumps({'status': 'verified', 'native_ssh': True, 'version_restart': True, 'persistent_data': True, 'injected_503_recovery': True}))


if __name__ == '__main__':
    main()
