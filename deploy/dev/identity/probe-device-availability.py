#!/usr/bin/env python3
"""Measure DEV device authorization, optionally restarting its sole DB primary pod."""
import argparse
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import uuid

sys.dont_write_bytecode = True
NS = 'hetero-dev-identity'
HOST = 'id.dev.heterocloud.mizuame.app'
DATABASE = 'dev-identity-postgres'
PG_IMAGE = 'ghcr.io/cloudnative-pg/postgresql:18.6-standard-trixie@sha256:71eef62330076deb985c8ffb1abeb957d86779c3911a8057c0b97f3c5a30b50b'


def ready(pod):
    return not pod['metadata'].get('deletionTimestamp') and any(
        c['type'] == 'Ready' and c['status'] == 'True'
        for c in pod['status'].get('conditions', []))


def request(context, ip):
    connection = http.client.HTTPSConnection(HOST, timeout=3, context=context)
    started = time.monotonic()
    try:
        connection.sock = context.wrap_socket(socket.create_connection((ip, 443), timeout=3), server_hostname=HOST)
        connection.request('POST', '/realms/heterocloud-dev/protocol/openid-connect/auth/device',
                           body='client_id=heteronetwork-dev-web',
                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
        response = connection.getresponse()
        raw = response.read(65537)
        valid = False
        if response.status == 200 and len(raw) <= 65536:
            body = json.loads(raw)
            valid = all(isinstance(body.get(k), str) and body[k]
                        for k in ('device_code', 'user_code', 'verification_uri'))
        return {'ok': bool(valid), 'http_status': response.status,
                'duration_ms': round((time.monotonic() - started) * 1000)}
    except (OSError, ValueError, http.client.HTTPException) as error:
        return {'ok': False, 'error': type(error).__name__,
                'duration_ms': round((time.monotonic() - started) * 1000)}
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restart-primary', action='store_true', help='Explicitly crash-restart one DEV DB pod; never a VM or PVC')
    parser.add_argument('--seconds', type=int, default=180)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 600:
        parser.error('seconds must be between 30 and 600')
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    root = Path('/var/lib/heteronetwork-dev-identity-probes')
    root.mkdir(mode=0o700, exist_ok=True)
    helper.require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == 0
                   and root.stat().st_mode & 0o077 == 0)
    lock = os.open(root / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    record = root / (str(uuid.uuid4()) + '.jsonl')
    with os.fdopen(os.open(record, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as stream:
        def emit(value):
            value = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **value}
            stream.write(json.dumps(value) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
            print(json.dumps(value), flush=True)

        def get(kind, name):
            return json.loads(helper.run(['get', kind, name, '-n', NS, '-o', 'json']))

        def admit():
            helper.guard()
            db = get('clusters.postgresql.cnpg.io', DATABASE)
            helper.require(db['spec']['instances'] == 3 and db['status'].get('readyInstances') == 3)
            deployment = get('deployment', 'dev-keycloak')
            status = deployment['status']
            helper.require(status.get('observedGeneration') == deployment['metadata']['generation']
                           and all(status.get(k) == 3 for k in ('replicas', 'updatedReplicas', 'availableReplicas')))
            env = deployment['spec']['template']['spec']['containers'][0]['env']
            helper.require({'name': 'KC_TRANSACTION_DEFAULT_TIMEOUT', 'value': '30s'} in env)
            return db

        db = admit()
        service = get('service', 'dev-keycloak')
        helper.require(service['spec']['type'] == 'ClusterIP' and service['spec']['ports'][0]['port'] == 443)
        ip = service['spec']['clusterIP']
        helper.require(ip.startswith('172.30.') and ip.count('.') == 3)
        ca = Path('/var/lib/heteronetwork-dev-identity-tls/ca.crt')
        context = ssl.create_default_context(cadata=helper.trusted_file(ca, 65536).decode())
        emit({'phase': 'baseline', 'restart_primary': args.restart_primary, 'record': str(record)})
        for _ in range(5):
            result = request(context, ip)
            emit(result)
            helper.require(result['ok'])
            time.sleep(2)
        old_uid = None
        if args.restart_primary:
            db = admit()
            name = db['status']['currentPrimary']
            helper.require(name in {DATABASE + '-' + str(i) for i in range(1, 4)})
            pod = get('pod', name)
            helper.require(ready(pod) and any(o['uid'] == db['metadata']['uid'] and o.get('controller')
                                           for o in pod['metadata'].get('ownerReferences', []))
                           and any(c['name'] == 'postgres' and c['image'] == PG_IMAGE for c in pod['spec']['containers']))
            old_uid = pod['metadata']['uid']
            options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'gracePeriodSeconds': 0,
                       'preconditions': {'uid': old_uid, 'resourceVersion': pod['metadata']['resourceVersion']}}
            emit({'phase': 'restart-intent', 'pod': name, 'uid': old_uid})
            helper.run(['delete', '--raw', f'/api/v1/namespaces/{NS}/pods/{name}', '-f', '-'],
                       data=json.dumps(options).encode())
            emit({'phase': 'restart-requested'})
        deadline = time.monotonic() + args.seconds
        samples = []
        while time.monotonic() < deadline:
            result = request(context, ip)
            samples.append(result)
            emit(result)
            time.sleep(2)
        final = admit()
        if old_uid:
            helper.require(get('pod', name)['metadata']['uid'] != old_uid)
        failures = sum(not s['ok'] for s in samples)
        emit({'phase': 'complete', 'samples': len(samples), 'failures': failures,
              'max_request_ms': max(s['duration_ms'] for s in samples),
              'db_primary_before': db['status']['currentPrimary'], 'db_primary_after': final['status']['currentPrimary'],
              'full_browser_login_tested': False, 'vm_loss_tested': False})
        helper.require(all(s['ok'] for s in samples[-5:]))


if __name__ == '__main__':
    main()
