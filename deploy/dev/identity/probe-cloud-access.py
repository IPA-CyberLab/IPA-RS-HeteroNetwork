#!/usr/bin/env python3
"""Short-lived DEV Pods verify Keycloak TLS ingress, not user authentication."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
# Keep the probe on the same reviewed image already running in the DEV database.
IMAGE = 'ghcr.io/cloudnative-pg/postgresql:18.6-standard-trixie@sha256:71eef62330076deb985c8ffb1abeb957d86779c3911a8057c0b97f3c5a30b50b'
NAMESPACE = 'heterocloud-dev'
HOST = 'id.dev.heterocloud.mizuame.app'


def pod(name, node, component):
    attempt = (f'timeout 8 openssl s_client -connect {HOST}:443 -servername {HOST} '
               f'-verify_hostname {HOST} -verify_return_error -CAfile /ca/ca.crt '
               '-brief -no_ign_eof </dev/null >/tmp/tls-result 2>&1; result=$?; ')
    # Newly created Pods may precede the policy controller's selector reconciliation.
    command = (('for attempt in 1 2 3 4 5 6; do ' + attempt +
                '[ "$result" = 0 ] && break; sleep 1; done; ')
               if component != 'worker' else attempt)
    command += 'cat /tmp/tls-result; printf "tls_exit=%s\\n" "$result"; exit "$result"'
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {
        'name': name, 'namespace': NAMESPACE,
        'labels': {'app.kubernetes.io/name': 'heterocloud',
                   'app.kubernetes.io/instance': 'heterocloud-dev',
                   'app.kubernetes.io/component': component,
                   'heteronetwork.dev/probe': name}},
        'spec': {'restartPolicy': 'Never', 'activeDeadlineSeconds': 60,
                 'automountServiceAccountToken': False,
                 'nodeSelector': {'kubernetes.io/hostname': node},
                 'securityContext': {'runAsNonRoot': True, 'runAsUser': 26, 'runAsGroup': 26,
                                     'seccompProfile': {'type': 'RuntimeDefault'}},
                 'containers': [{'name': 'probe', 'image': IMAGE,
                     'command': ['/bin/sh', '-c', command],
                     'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'},
                                   'limits': {'cpu': '100m', 'memory': '64Mi'}},
                     'securityContext': {'allowPrivilegeEscalation': False,
                                         'capabilities': {'drop': ['ALL']}},
                     'volumeMounts': [{'name': 'ca', 'mountPath': '/ca', 'readOnly': True}]}],
                 'volumes': [{'name': 'ca', 'secret': {'secretName': 'heterocloud-dev-identity-ca',
                              'items': [{'key': 'ca.crt', 'path': 'ca.crt'}], 'defaultMode': 0o444}}]}}


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    # Probe labels must not accidentally enter an application's Service endpoints.
    helper.require(not json.loads(helper.run(['get', 'services', '-n', NAMESPACE,
        '-l', 'app.kubernetes.io/instance=heterocloud-dev', '-o', 'json']))['items'])
    for number in range(1, 4):
        for component in ('api', 'worker', 'owner-console'):
            name = 'identity-tls-probe-' + uuid.uuid4().hex[:16]
            desired = pod(name, f'hetero-dev-{number}', component)
            helper.run(['create', '-f', '-'], json.dumps(desired).encode())
            try:
                deadline = time.monotonic() + 90
                while True:
                    current = json.loads(helper.run(['get', 'pod', name, '-n', NAMESPACE, '-o', 'json']))
                    status = current.get('status', {})
                    if status.get('phase') in ('Succeeded', 'Failed'):
                        break
                    helper.require(time.monotonic() < deadline)
                    time.sleep(2)
                states = status.get('containerStatuses', [])
                code = states[0].get('state', {}).get('terminated', {}).get('exitCode') if states else None
                logs = helper.run(['logs', name, '-n', NAMESPACE, '--tail=20']).decode()
                allowed = component != 'worker'
                passed = ((code == 0 and 'Verification: OK' in logs) if allowed else
                          (code == 124 or (code == 1 and 'connect:errno=111' in logs)))
                print(json.dumps({'node': desired['spec']['nodeSelector']['kubernetes.io/hostname'],
                                  'component': component, 'tls_exit': code,
                                  'expected_outcome': 'verified_tls' if allowed else 'connection_denied'}), flush=True)
                if not passed:
                    print(logs, flush=True)
                helper.require(passed)
            finally:
                helper.run(['delete', 'pod', name, '-n', NAMESPACE, '--wait=true', '--timeout=30s'])


if __name__ == '__main__':
    main()
