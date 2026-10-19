#!/usr/bin/env python3
"""Provision a private, bucket-scoped CSI backup store without exporting secrets.

Run on the bootstrap node as root via the flash-backups Ansible playbook.
All credentials stay in memory and are sent to kubectl via stdin, never argv.
Re-running validates existing configuration and reuses its access key.
"""
import argparse
import base64
import json
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_target(current, target, secret):
    require(current.get('backupTargetURL', '') in ('', target),
            'default backup target already points elsewhere; refusing to replace it')
    require(current.get('credentialSecret', '') in ('', secret),
            'default backup target uses another credential; refusing to replace it')


def validate_key(key, bucket):
    require(not key.get('expired'), 'backup store key has expired')
    require(not key.get('permissions', {}).get('createBucket'), 'backup key has global bucket creation permission')
    require(all(b['id'] == bucket for b in key.get('buckets', [])), 'backup key can access unrelated buckets')
    require(bool(key.get('secretAccessKey')), 'backup key secret is unavailable')


class Provisioner:
    def __init__(self, args):
        self.args = args
        self.kube_command = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=20s']
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def kube(self, *args, body=None):
        result = subprocess.run(self.kube_command + list(args), input=json.dumps(body) if body is not None else None,
                                capture_output=True, text=True, timeout=30)
        # Kubectl may include secret objects in its error output. Never forward it.
        require(result.returncode == 0, 'Kubernetes operation failed: ' + args[0])
        return json.loads(result.stdout) if result.stdout.strip() else None

    def api(self, operation, body=None, **query):
        url = self.admin_url + '/v2/' + operation + ('?' + urllib.parse.urlencode(query) if query else '')
        request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                         headers={'Authorization': 'Bearer ' + self.admin_token, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                require(len(raw) <= 2 * 1024 * 1024, 'backup store response too large')
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            raise RuntimeError('Garage administration failed: ' + operation + ' HTTP ' + str(error.code)) from None

    def run(self):
        args = self.args
        target = 's3://' + args.bucket + '@' + args.region + '/'
        current = self.kube('-n', 'longhorn-system', 'get', 'backuptargets.longhorn.io', 'default', '-o', 'json')
        check_target(current['spec'], target, args.secret)
        secret = self.kube('-n', args.namespace, 'get', 'secret', args.admin_secret, '-o', 'json')
        self.admin_token = base64.b64decode(secret['data']['garage-admin-token']).decode()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.admin_url = 'http://127.0.0.1:' + str(port)
        forward = subprocess.Popen(self.kube_command + ['-n', args.namespace, 'port-forward',
                                    'pod/' + args.pod, '--address=127.0.0.1', str(port) + ':3903'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    require(forward.poll() is None, 'private Garage administration tunnel failed')
                    time.sleep(.1)
            else:
                raise RuntimeError('private Garage administration tunnel timed out')
            buckets = self.api('ListBuckets')
            matches = [b for b in buckets if args.bucket in b['globalAliases']]
            require(len(matches) <= 1, 'ambiguous backup bucket')
            bucket = self.api('GetBucketInfo', id=matches[0]['id']) if matches else self.api('CreateBucket', {'globalAlias': args.bucket})
            require(not bucket['websiteAccess'], 'backup bucket has public website access')
            require(bucket['bytes'] <= args.capacity_gib * 1024 ** 3, 'backup bucket already exceeds requested quota')
            # Keep enough space for existing user objects. No lifecycle expiration:
            # Longhorn alone owns incremental block reference counts and deletion.
            self.api('UpdateBucket', {'quotas': {'maxSize': args.capacity_gib * 1024 ** 3, 'maxObjects': 1000000}}, id=bucket['id'])
            matches = [key for key in self.api('ListKeys') if key['name'] == args.key_name]
            require(len(matches) <= 1, 'ambiguous backup key')
            key = self.api('GetKeyInfo', id=matches[0]['id'], showSecretKey='true') if matches else self.api('CreateKey', {'name': args.key_name, 'expiration': None, 'neverExpires': True})
            validate_key(key, bucket['id'])
            require(all(k['accessKeyId'] == key['accessKeyId'] for k in bucket.get('keys', [])),
                    'backup bucket has an unrelated access key')
            self.api('AllowBucketKey', {'bucketId': bucket['id'], 'accessKeyId': key['accessKeyId'],
                                      'permissions': {'read': True, 'write': True, 'owner': False}})
            self.api('DenyBucketKey', {'bucketId': bucket['id'], 'accessKeyId': key['accessKeyId'],
                                     'permissions': {'read': False, 'write': False, 'owner': True}})
            key = self.api('GetKeyInfo', id=key['accessKeyId'], showSecretKey='true')
            validate_key(key, bucket['id'])
            require(len(key['buckets']) == 1 and key['buckets'][0]['permissions'] == {'read': True, 'write': True, 'owner': False},
                    'backup key is not limited to read/write on its private bucket')
            data = {'AWS_ACCESS_KEY_ID': key['accessKeyId'], 'AWS_SECRET_ACCESS_KEY': key['secretAccessKey'],
                    'AWS_ENDPOINTS': args.endpoint, 'VIRTUAL_HOSTED_STYLE': 'false'}
            self.kube('apply', '--server-side', '--field-manager=heteronetwork-flash-backups', '-f', '-', '-o', 'json', body={
                'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': args.secret, 'namespace': 'longhorn-system',
                    'labels': {'app.kubernetes.io/managed-by': 'heteronetwork-iac', 'app.kubernetes.io/part-of': 'flash-backups'}},
                'type': 'Opaque', 'data': {name: base64.b64encode(value.encode()).decode() for name, value in data.items()}})
            # Recheck immediately before writing; resourceVersion prevents races.
            current = self.kube('-n', 'longhorn-system', 'get', 'backuptargets.longhorn.io', 'default', '-o', 'json')
            check_target(current['spec'], target, args.secret)
            self.kube('-n', 'longhorn-system', 'patch', 'backuptargets.longhorn.io', 'default', '--type=merge', '--patch-file=/dev/stdin', '-o', 'json',
                      body={'metadata': {'resourceVersion': current['metadata']['resourceVersion']},
                            'spec': {'backupTargetURL': target, 'credentialSecret': args.secret, 'pollInterval': '1m0s'}})
            print(json.dumps({'bucket': args.bucket, 'private': True, 'key_scope': 'one-bucket-read-write',
                              'backup_target': 'default', 'capacity_gib': args.capacity_gib}))
        finally:
            forward.terminate()
            forward.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl', default='/usr/bin/kubectl')
    parser.add_argument('--kubeconfig', default='/etc/kubernetes/admin.conf')
    parser.add_argument('--namespace', default='heterocloud-syouyu')
    parser.add_argument('--pod', default='heterocloud-syouyu-garage-0')
    parser.add_argument('--admin-secret', default='heterocloud-syouyu-secrets')
    parser.add_argument('--bucket', default='heterocloud-flash-backups')
    parser.add_argument('--key-name', default='heterocloud-flash-backup-store')
    parser.add_argument('--secret', default='flash-backup-store')
    parser.add_argument('--region', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--capacity-gib', type=int, default=40)
    args = parser.parse_args()
    require(0 < args.capacity_gib <= 4096, 'invalid backup store capacity')
    require(urllib.parse.urlsplit(args.endpoint).scheme in ('http', 'https'), 'S3 endpoint must be HTTP(S)')
    try:
        Provisioner(args).run()
    except Exception as error:
        # No secret-bearing request/response bodies or tracebacks in operator logs.
        raise SystemExit(str(error)) from None


if __name__ == '__main__':
    main()
