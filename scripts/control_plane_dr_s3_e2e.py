#!/usr/bin/env python3
"""Exercise recovery against a new, size-limited real S3 fixture bucket.

The bucket and key are temporary. This verifies HTTPS/S3 and encrypted restore,
not recovery from an independent failure domain. No existing object is read.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

spec = importlib.util.spec_from_file_location('control_plane_dr', Path(__file__).with_name('control_plane_dr.py'))
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restic', required=True)
    parser.add_argument('--kubectl', required=True)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--provider-ops', type=Path, required=True)
    parser.add_argument('--s3-endpoint', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    endpoint = urllib.parse.urlsplit(args.s3_endpoint)
    if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.path not in ('', '/'):
        parser.error('A credential-free HTTPS S3 origin is required')
    if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        parser.error('A credential-free HTTPS S3 origin is required')
    sys.path.insert(0, str(args.provider_ops.resolve()))
    import offsite

    run = uuid.uuid4().hex
    alias = 'hc-dr-probe-' + run[:16]
    command = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '-n', 'heterocloud-syouyu']
    report = {'result': 'incomplete', 'checks': {}, 'cleanup': {},
              'scope': 'real_https_s3_fixture_same_failure_domain'}
    stage = 'admin_access'
    forwards = []
    bucket = None
    key = None
    admin_token = None
    admin_url = None
    store = None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), offsite.NoRedirect())

    def admin(operation, body=None, **query):
        suffix = '?' + urllib.parse.urlencode(query) if query else ''
        data = json.dumps(body).encode() if body is not None else (b'' if operation.startswith('Delete') else None)
        request = urllib.request.Request(admin_url + '/v2/' + operation + suffix, data=data,
            headers={'Authorization': 'Bearer ' + admin_token, 'Content-Type': 'application/json'})
        with opener.open(request, timeout=20) as response:
            result = response.read(2 * 1024 * 1024)
            return json.loads(result) if result else None

    def tunnel(remote):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(command + ['port-forward', 'pod/heterocloud-syouyu-garage-0',
                                   '--address=127.0.0.1', f'{port}:{remote}'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        forwards.append(process)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    return f'http://127.0.0.1:{port}'
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError('fixture_tunnel_failed')
                time.sleep(.1)
        raise RuntimeError('fixture_tunnel_timeout')

    try:
        result = subprocess.run(command + ['get', 'secret', 'heterocloud-syouyu-secrets', '-o', 'json'],
                                capture_output=True, text=True, timeout=30, check=True)
        admin_token = base64.b64decode(json.loads(result.stdout)['data']['garage-admin-token']).decode()
        admin_url = tunnel(3903)
        cleanup_endpoint = tunnel(3900)
        aliases = {name for item in admin('ListBuckets') for name in item.get('globalAliases', [])}
        if alias in aliases:
            raise RuntimeError('fixture_name_already_exists')
        stage = 'create_isolated_fixture'
        key = admin('CreateKey', {'name': alias, 'expiration': None, 'neverExpires': True})
        bucket = admin('CreateBucket', {'globalAlias': alias})
        admin('UpdateBucket', {'quotas': {'maxSize': 128 * 1024**2, 'maxObjects': 1000}}, id=bucket['id'])
        admin('AllowBucketKey', {'bucketId': bucket['id'], 'accessKeyId': key['accessKeyId'],
                                'permissions': {'read': True, 'write': True, 'owner': False}})
        # Cleanup uses the same scoped key; its values never enter argv or reports.
        store = offsite.S3({'endpoint': cleanup_endpoint, 'bucket': alias, 'region': 'heteronet-global',
                            'access_key': key['accessKeyId'], 'secret_key': key['secretAccessKey'],
                            'private_source': True})
        with tempfile.TemporaryDirectory(prefix='hc-dr-s3-e2e-') as private:
            root = Path(private)
            password = root / 'password'
            password.write_text(secrets.token_urlsafe(32) + '\n')
            password.chmod(0o600)
            source = root / 'source'
            marker = secrets.token_hex(32)
            source.write_text('#!/bin/sh\nprintf %s ' + marker + '\n')
            source.chmod(0o700)
            config_file = root / 'config.json'
            config_file.write_text(json.dumps({'repository': 's3:' + args.s3_endpoint.rstrip('/') + '/' + alias + '/recovery',
                'password_file': str(password), 'sources': [{'name': 'postgres', 'executable': str(source)}],
                'max_component_bytes': 1024 * 1024, 'max_total_bytes': 1024 * 1024, 'timeout_seconds': 180}))
            config_file.chmod(0o600)
            config = dr.read_config(config_file)
            os.environ['AWS_ACCESS_KEY_ID'] = key['accessKeyId']
            os.environ['AWS_SECRET_ACCESS_KEY'] = key['secretAccessKey']
            os.environ['AWS_DEFAULT_REGION'] = 'heteronet-global'
            stage = 'https_s3_backup'
            dr.invoke([args.restic, 'init', '--quiet'], dr.restic_env(config), 180)
            created = dr.backup(config, args.restic)
            dr.verify(config, args.restic, created['snapshot'])
            report['checks']['signed_https_s3_backup_readback'] = True
            stage = 'restore'
            target = root / 'restore'
            target.mkdir(mode=0o700)
            dr.restore(config, args.restic, created['snapshot'], target)
            if (target / 'postgres').read_text() != marker:
                raise RuntimeError('restore_content_mismatch')
            report['checks']['restored_original_contents'] = True
        report['result'] = 'passed'
    except Exception as error:
        report.update(result='failed', failure_stage=stage, failure_type=type(error).__name__)
    finally:
        clean = True
        if bucket:
            try:
                current = admin('GetBucketInfo', id=bucket['id'])
                if current.get('globalAliases') != [alias]:
                    raise RuntimeError('fixture_cleanup_identity_mismatch')
                if store is not None:
                    for item in list(store.listing()):
                        store.request('DELETE', item['key'])
                admin('DeleteBucket', id=bucket['id'])
            except Exception:
                clean = False
        if key:
            try:
                admin('DeleteKey', id=key['accessKeyId'])
            except Exception:
                clean = False
        for forward in forwards:
            forward.terminate()
            try:
                forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forward.kill()
                forward.wait(timeout=10)
        report['cleanup']['fixture_bucket_and_key_removed'] = clean
        if not clean:
            report['result'] = 'failed'
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output, indent=2)
        print(json.dumps(report), flush=True)
    return 0 if report['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
