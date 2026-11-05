#!/usr/bin/env python3
"""Exercise two isolated Longhorn S3 targets and restore from each.

All buckets, keys, namespaces and PVs have a fresh random identity. No existing
volume or bucket is read or changed; credentials remain in memory or Kubernetes
Secrets passed over stdin, and are removed with the fixture.
"""
import argparse
import base64
import importlib.util
import json
import os
import secrets
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('flash_backup_storage_e2e.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
offsite = None  # Loaded from the configured provider checkout in main().


class TwoTargets(module.Probe):
    def __init__(self, args):
        super().__init__(args)
        self.prefix = 'flash-target-e2e-' + self.nonce[:10]
        self.bucket_names = [self.prefix + '-a', self.prefix + '-b']
        self.target_names = [self.prefix + '-a', self.prefix + '-b']
        self.classes = [self.prefix + '-a', self.prefix + '-b']
        self.keys = []
        self.buckets = []
        self.stores = []
        self.tunnels = []
        self.targets = []
        self.created_classes = []
        self.fixture_owners = {}
        self.snapshots = []
        self.stage = 'preflight'
        self.report = {'test': 'two-real-longhorn-s3-targets', 'run': self.nonce,
                       'namespace': self.namespace, 'result': 'incomplete', 'checks': {}, 'cleanup': {}}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), offsite.NoRedirect())

    def admin(self, operation, body=None, **query):
        suffix = '?' + urllib.parse.urlencode(query) if query else ''
        data = json.dumps(body).encode() if body is not None else (b'' if operation.startswith('Delete') else None)
        request = urllib.request.Request(self.admin_url + '/v2/' + operation + suffix, data=data,
            headers={'Authorization': 'Bearer ' + self.admin_token, 'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=20) as response:
            data = response.read(2 * 1024 ** 2)
            return json.loads(data) if data else None

    def tunnel(self, port):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            local = sock.getsockname()[1]
        command = self.command + ['-n', 'heterocloud-syouyu', 'port-forward',
            'pod/heterocloud-syouyu-garage-0', '--address=127.0.0.1', f'{local}:{port}']
        p = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.tunnels.append(p)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', local), timeout=.2):
                    return 'http://127.0.0.1:' + str(local)
            except OSError:
                if p.poll() is not None:
                    raise RuntimeError('fixture port-forward failed')
                time.sleep(.1)
        raise RuntimeError('fixture port-forward timed out')

    def claim_with_target(self, name, index, snapshot=None):
        obj = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
               'metadata': {'name': name, 'namespace': self.namespace},
               'spec': {'storageClassName': self.classes[index], 'accessModes': ['ReadWriteMany'],
                        'resources': {'requests': {'storage': '1Gi'}}}}
        if snapshot:
            obj['spec']['dataSource'] = {'apiGroup': 'snapshot.storage.k8s.io',
                                         'kind': 'VolumeSnapshot', 'name': snapshot}
        self.apply(obj)
        pvc = self.wait('wait for fixture disk ' + name,
            lambda: p if (p := self.get('pvc', name)) and p.get('status', {}).get('phase') == 'Bound' else None, 600)
        self.claims[name] = {'uid': pvc['metadata']['uid'], 'pv': pvc['spec']['volumeName']}
        return pvc

    def snapshot(self, name):
        self.snapshots.append(name)
        self.apply({'apiVersion': 'snapshot.storage.k8s.io/v1', 'kind': 'VolumeSnapshot',
                    'metadata': {'name': name, 'namespace': self.namespace},
                    'spec': {'volumeSnapshotClassName': self.args.snapshot_class,
                             'source': {'persistentVolumeClaimName': 'source'}}})
        snapshot = self.wait('wait for fixture backup ' + name,
            lambda: s if (s := self.get('volumesnapshot', name)) and s.get('status', {}).get('readyToUse') else None, 900)
        content = self.get('volumesnapshotcontent', snapshot['status']['boundVolumeSnapshotContentName'])
        if not content.get('status', {}).get('snapshotHandle', '').startswith('bak://'):
            raise RuntimeError('fixture did not create a durable backup')

    def storage_setup(self):
        secret = self.get('secret', 'heterocloud-syouyu-secrets', 'heterocloud-syouyu')
        self.admin_token = base64.b64decode(secret['data']['garage-admin-token']).decode()
        source = self.get('secret', 'flash-backup-export-source', 'heterocloud-flash')
        source_config = json.loads(base64.b64decode(source['data']['config.json']))
        self.source_endpoint = source_config['endpoint']
        self.region = source_config['region']
        self.admin_url = self.tunnel(3903)
        self.s3_url = self.tunnel(3900)
        aliases = {alias for bucket in self.admin('ListBuckets') for alias in bucket.get('globalAliases', [])}
        if any(bucket in aliases for bucket in self.bucket_names):
            raise RuntimeError('fixture bucket already exists')
        for index, bucket_name in enumerate(self.bucket_names):
            key = self.admin('CreateKey', {'name': self.prefix + '-' + str(index),
                                           'expiration': None, 'neverExpires': True})
            self.keys.append(key)
            bucket = self.admin('CreateBucket', {'globalAlias': bucket_name})
            self.buckets.append(bucket)
            self.admin('UpdateBucket', {'quotas': {'maxSize': 128 * 1024 ** 2, 'maxObjects': 10000}}, id=bucket['id'])
            self.admin('AllowBucketKey', {'bucketId': bucket['id'], 'accessKeyId': key['accessKeyId'],
                       'permissions': {'read': True, 'write': True, 'owner': False}})
            self.stores.append(offsite.S3({'endpoint': self.s3_url, 'bucket': bucket_name,
                'region': self.region, 'access_key': key['accessKeyId'],
                'secret_key': key['secretAccessKey'], 'private_source': True}))
            name = self.target_names[index]
            labels = {'heterocloud.io/backup-probe': self.nonce}
            self.targets.append(name)
            self.apply({'apiVersion': 'v1', 'kind': 'Secret',
                        'metadata': {'name': name, 'namespace': 'longhorn-system', 'labels': labels},
                        'type': 'Opaque', 'stringData': {'AWS_ACCESS_KEY_ID': key['accessKeyId'],
                        'AWS_SECRET_ACCESS_KEY': key['secretAccessKey'],
                        'AWS_ENDPOINTS': self.source_endpoint, 'VIRTUAL_HOSTED_STYLE': 'false'}})
            self.apply({'apiVersion': 'longhorn.io/v1beta2', 'kind': 'BackupTarget',
                        'metadata': {'name': name, 'namespace': 'longhorn-system', 'labels': labels},
                        'spec': {'backupTargetURL': 's3://' + bucket_name + '@' + self.region + '/',
                                 'credentialSecret': name, 'pollInterval': '10s'}})
            self.wait('wait for fixture target ' + str(index),
                lambda: t if (t := self.get('backuptargets.longhorn.io', name, 'longhorn-system'))
                             and t.get('status', {}).get('available') else None, 180)
            sc = {'apiVersion': 'storage.k8s.io/v1', 'kind': 'StorageClass',
                  'metadata': {'name': self.classes[index], 'labels': labels},
                  'provisioner': 'driver.longhorn.io', 'reclaimPolicy': 'Delete',
                  'volumeBindingMode': 'Immediate', 'allowVolumeExpansion': True,
                  'parameters': {'numberOfReplicas': '2', 'staleReplicaTimeout': '30',
                                 'fsType': 'ext4', 'backupTargetName': name}}
            self.created_classes.append(self.classes[index])
            self.apply(sc)

    def verify_restored(self, name, index, snapshot, marker):
        claim = self.claim_with_target(name, index, snapshot)
        pv = self.get('pv', claim['spec']['volumeName'])
        volume_name = pv['spec']['csi']['volumeHandle']
        self.wait('wait for fixture restore ' + name, lambda:
            v if (v := self.get('volumes.longhorn.io', volume_name, 'longhorn-system'))
                 and v.get('status', {}).get('restoreInitiated') is True
                 and v.get('status', {}).get('restoreRequired') is False else None, 900)
        self.pod(name, name)
        if self.exec(name, 'cat /data/marker') != marker:
            raise RuntimeError('fixture restore marker mismatch')

    def configure_external_proxy(self):
        origin = urllib.parse.urlsplit(self.args.public_endpoint)
        if origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or origin.path not in ('', '/') or origin.query or origin.fragment:
            raise RuntimeError('fixture external endpoint must be an HTTPS origin')
        if not self.args.proxy_image or '@sha256:' not in self.args.proxy_image:
            raise RuntimeError('fixture proxy image must be pinned by digest')
        proxy_spec = importlib.util.spec_from_file_location('flash_proxy_fixture', self.args.flash_ops / 's3_egress_proxy.py')
        proxy = importlib.util.module_from_spec(proxy_spec)
        proxy_spec.loader.exec_module(proxy)
        key = secrets.token_bytes(32)
        identity = uuid.uuid4().hex + '.' + uuid.uuid4().hex
        host = origin.hostname.lower().rstrip('.')
        port = origin.port or 443
        credential = proxy.token_for(key, identity, host, port)
        proxy_url = 'http://' + identity + ':' + credential + '@external-proxy.' + self.namespace + '.svc.cluster.local:8088'
        source = (self.args.flash_ops / 's3_egress_proxy.py').read_text()
        wrapper = '''import s3_egress_proxy as p\nkey=open('/var/run/proxy/key','rb').read()\ndef connect(address, port):\n print('fixture proxy connected', flush=True)\n return p.system_connector(address, port)\nwith p.Server(('0.0.0.0',8088),key,connector=connect) as server:\n server.serve_forever()\n'''
        self.apply({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'external-proxy','namespace':self.namespace},
                    'data':{'s3_egress_proxy.py':source,'run.py':wrapper}})
        self.apply({'apiVersion':'v1','kind':'Secret','type':'Opaque','metadata':{'name':'external-proxy-key','namespace':self.namespace},
                    'data':{'key':base64.b64encode(key).decode()}})
        self.apply({'apiVersion':'v1','kind':'Pod','metadata':{'name':'external-proxy','namespace':self.namespace,'labels':{'app':'external-proxy'}},
                    'spec':{'automountServiceAccountToken':False,'restartPolicy':'Never',
                      'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'fsGroup':65532},
                      'containers':[{'name':'proxy','image':self.args.proxy_image,'command':['python3','-u','-B','/opt/proxy/run.py'],
                        'ports':[{'containerPort':8088}], 'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'250m','memory':'128Mi'}},
                        'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                        'volumeMounts':[{'name':'scripts','mountPath':'/opt/proxy','readOnly':True},{'name':'key','mountPath':'/var/run/proxy','readOnly':True}]}],
                      'volumes':[{'name':'scripts','configMap':{'name':'external-proxy'}},{'name':'key','secret':{'secretName':'external-proxy-key','defaultMode':288}}]}})
        self.apply({'apiVersion':'v1','kind':'Service','metadata':{'name':'external-proxy','namespace':self.namespace},
                    'spec':{'selector':{'app':'external-proxy'},'ports':[{'port':8088,'targetPort':8088}]}})
        self.wait('wait for isolated S3 proxy', lambda: p if (p := self.get('pod','external-proxy')) and
                  any(c['type']=='Ready' and c['status']=='True' for c in p.get('status',{}).get('conditions',[])) else None, 300)
        if self.args.test_provider_registration:
            organization = uuid.uuid4()
            destination = uuid.uuid4()
            name = 'hc-backup-' + destination.hex
            verification_class = 'hc-verify-' + destination.hex
            self.fixture_owners[name] = (str(organization), str(destination))
            self.fixture_owners[verification_class] = (str(organization), str(destination))
            self.targets.append(name)
            self.created_classes.extend([name, verification_class])
            fixture = {'organization_id':str(organization),'id':str(destination),'proxy_key':list(key),
                'proxy_origin':'http://external-proxy.'+self.namespace+'.svc.cluster.local:8088',
                'destination':{'endpoint':self.args.public_endpoint,'bucket':self.bucket_names[0],
                    'region':self.region,'prefix':'isolated-probe','virtual_hosted':False,
                    'access_key':self.keys[0]['accessKeyId'],'secret_key':self.keys[0]['secretAccessKey']}}
            provider_repo = self.args.flash_ops.resolve().parent
            with tempfile.NamedTemporaryFile(mode='w', prefix='flash-backup-destination-fixture-', delete=True) as file:
                os.chmod(file.name, 0o600)
                json.dump(fixture,file)
                file.flush()
                environment=os.environ.copy()
                environment['KUBECONFIG']=self.args.kubeconfig
                environment['FLASH_BACKUP_DESTINATION_E2E_FIXTURE']=file.name
                result=subprocess.run([self.args.cargo,'test','--offline','--locked','--test','backup_destination_real',
                    'registers_a_real_synthetic_destination'],cwd=provider_repo,env=environment,
                    capture_output=True,text=True,timeout=360)
            if result.returncode:
                diagnostic = (result.stdout + '\n' + result.stderr)[-3000:]
                for value in (self.keys[0]['accessKeyId'], self.keys[0]['secretAccessKey'], credential, proxy_url):
                    diagnostic = diagnostic.replace(value, '[redacted]')
                print('provider acceptance diagnostic:', diagnostic, flush=True)
                self.report['checks']['provider_fixture_resources']={
                    'secret_created':bool(self.get('secret',name,'longhorn-system')),
                    'target_created':bool(self.get('backuptargets.longhorn.io',name,'longhorn-system')),
                    'restore_class_created':bool(self.get('storageclass',name)),
                    'verify_class_created':bool(self.get('storageclass',verification_class))}
                raise RuntimeError('provider could not register the isolated destination')
            self.wait('wait for registered HTTPS S3 target',lambda: t if (t := self.get('backuptargets.longhorn.io',name,'longhorn-system'))
                      and t.get('status',{}).get('available') else None,180)
            self.target_names[0]=name
            self.classes[0]=name
            self.report['checks']['provider_registered_scoped_s3_destination']=True
            return
        name = self.target_names[0]
        existing = self.get('secret',name,'longhorn-system')
        if not existing or existing['metadata'].get('labels',{}).get('heterocloud.io/backup-probe') != self.nonce:
            raise RuntimeError('fixture storage credential identity changed')
        self.kube('-n','longhorn-system','patch','secret',name,'--type=merge','--patch-file=/dev/stdin',body={
            'metadata':{'resourceVersion':existing['metadata']['resourceVersion']},'stringData':{
                'AWS_ENDPOINTS':self.args.public_endpoint,'HTTPS_PROXY':proxy_url,'HTTP_PROXY':proxy_url,'NO_PROXY':''}})

    def execute(self):
        self.apply({'apiVersion': 'v1', 'kind': 'Namespace',
                    'metadata': {'name': self.namespace, 'labels': {'heterocloud.io/backup-probe': self.nonce}}})
        self.stage = 'targets'
        self.storage_setup()
        if self.args.public_endpoint:
            # Exercise TLS and signed S3 operations using only the first
            # random, bucket-scoped fixture credential, never production data.
            self.stage = 'public-s3'
            public = offsite.S3({'endpoint': self.args.public_endpoint, 'bucket': self.bucket_names[0],
                'region': self.region, 'access_key': self.keys[0]['accessKeyId'],
                'secret_key': self.keys[0]['secretAccessKey']})
            public.request('PUT', 'synthetic-probe', b'fixture')
            if public.request('GET', 'synthetic-probe') != b'fixture':
                raise RuntimeError('public S3 fixture contents mismatch')
            public.request('DELETE', 'synthetic-probe')
            self.report['checks']['public_s3_fixture_write_read_delete'] = True
            if self.args.test_external_proxy:
                self.stage = 'external-s3-proxy'
                self.configure_external_proxy()
        self.stage = 'source'
        pvc = self.claim_with_target('source', 0)
        self.pod('source', 'source')
        self.exec('source', 'printf first > /data/marker; sync')
        self.stage = 'backup-a'
        self.snapshot('backup-a')
        if self.args.test_external_proxy:
            logs = self.kube('-n',self.namespace,'logs','external-proxy')
            if 'fixture proxy connected' not in logs:
                raise RuntimeError('Longhorn did not use the fixture proxy')
            self.report['checks']['longhorn_backup_used_https_connect_proxy'] = True
        if not list(self.stores[0].listing()):
            raise RuntimeError('first target is empty')
        if list(self.stores[1].listing()):
            raise RuntimeError('other target received first backup')
        self.report['checks']['first_backup_only_in_first_bucket'] = True
        pv = self.get('pv', pvc['spec']['volumeName'])
        volume = pv['spec']['csi']['volumeHandle']
        current = self.get('volumes.longhorn.io', volume, 'longhorn-system')
        patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                 {'op': 'test', 'path': '/spec/backupTargetName', 'value': self.target_names[0]},
                 {'op': 'replace', 'path': '/spec/backupTargetName', 'value': self.target_names[1]}]
        self.kube('-n', 'longhorn-system', 'patch', 'volumes.longhorn.io', volume,
                  '--type=json', '--patch-file=/dev/stdin', body=patch)
        self.exec('source', 'printf second > /data/marker; sync')
        self.stage = 'backup-b'
        self.snapshot('backup-b')
        if not list(self.stores[1].listing()):
            raise RuntimeError('second target is empty')
        self.report['checks']['second_backup_in_second_bucket'] = True
        self.stage = 'restore-a-after-target-switch'
        self.verify_restored('restore-a', 0, 'backup-a', 'first')
        self.report['checks']['first_target_restores_after_target_switch'] = True
        self.stage = 'restore-b'
        self.verify_restored('restore-b', 1, 'backup-b', 'second')
        self.report['checks']['second_target_restores'] = True
        self.stage = 'cross-bucket-isolation'
        wrong = offsite.S3({'endpoint': self.s3_url, 'bucket': self.bucket_names[1], 'region': self.region,
            'access_key': self.keys[0]['accessKeyId'], 'secret_key': self.keys[0]['secretAccessKey'], 'private_source': True})
        try:
            list(wrong.listing())
        except RuntimeError as error:
            if '403' not in str(error): raise
        else:
            raise RuntimeError('cross-bucket access was allowed')
        self.report['checks']['one_bucket_credential_cannot_read_other_bucket'] = True
        self.report['result'] = 'passed'

    def cleanup(self):
        errors = []
        def owned(obj, name):
            labels = obj.get('metadata', {}).get('labels', {})
            expected = self.fixture_owners.get(name)
            return labels.get('heterocloud.io/backup-probe') == self.nonce or (expected is not None and
                labels.get('flash.heterocloud.io/organization') == expected[0] and
                labels.get('flash.heterocloud.io/backup-destination') == expected[1])
        def attempt(label, function):
            try:
                function()
                return True
            except Exception:
                errors.append(label)
                return False

        def remove_namespace():
            namespace = self.get('namespace', self.namespace)
            if namespace and namespace['metadata'].get('labels', {}).get('heterocloud.io/backup-probe') == self.nonce:
                for name in self.snapshots:
                    self.kube('-n', self.namespace, 'delete', 'volumesnapshot', name, '--ignore-not-found=true', '--wait=false')
                for name in self.snapshots:
                    self.wait('remove fixture backup ' + name, lambda: self.get('volumesnapshot', name) is None, 300)
                for name in ['source', 'restore-a', 'restore-b']:
                    self.kube('-n', self.namespace, 'delete', 'pod', name, '--ignore-not-found=true', '--wait=false')
                self.wait('remove fixture pods', lambda: not any(self.get('pod', name) for name in ['source', 'restore-a', 'restore-b']), 300)
                for name in list(self.claims): self.delete_claim(name)
                self.kube('delete', 'namespace', self.namespace, '--wait=false')
                self.wait('remove fixture namespace', lambda: self.get('namespace', self.namespace) is None, 180)
            elif namespace:
                raise RuntimeError('fixture namespace identity changed')

        namespace_removed = attempt('namespace', remove_namespace)
        def remove_classes():
            for name in self.created_classes:
                obj = self.get('storageclass', name)
                if obj and owned(obj,name):
                    self.kube('delete', 'storageclass', name, '--wait=false')
                elif obj: raise RuntimeError('fixture class identity changed')
        classes_removed = attempt('classes', remove_classes)
        def remove_targets():
            for name in self.targets:
                obj = self.get('backuptargets.longhorn.io', name, 'longhorn-system')
                if obj and owned(obj,name):
                    self.kube('-n', 'longhorn-system', 'delete', 'backuptargets.longhorn.io', name, '--wait=false')
                    self.wait('remove fixture target', lambda: self.get('backuptargets.longhorn.io', name, 'longhorn-system') is None, 180)
                elif obj: raise RuntimeError('fixture target identity changed')
                secret = self.get('secret', name, 'longhorn-system')
                if secret and owned(secret,name):
                    self.kube('-n', 'longhorn-system', 'delete', 'secret', name, '--wait=false')
                elif secret: raise RuntimeError('fixture secret identity changed')
        targets_removed = namespace_removed and attempt('targets', remove_targets)
        def remove_buckets():
            for index, bucket in enumerate(self.buckets):
                current = self.admin('GetBucketInfo', id=bucket['id'])
                if current.get('globalAliases') != [self.bucket_names[index]]:
                    raise RuntimeError('fixture bucket identity changed')
                if index < len(self.stores):
                    store = self.stores[index]
                    for obj in list(store.listing()): store.request('DELETE', obj['key'])
                self.admin('DeleteBucket', id=bucket['id'])
        buckets_removed = targets_removed and attempt('buckets', remove_buckets)
        def remove_keys():
            for key in self.keys: self.admin('DeleteKey', id=key['accessKeyId'])
        keys_removed = buckets_removed and attempt('keys', remove_keys)
        for tunnel in self.tunnels:
            tunnel.terminate()
            try: tunnel.wait(timeout=10)
            except subprocess.TimeoutExpired: tunnel.kill()
        clean = namespace_removed and classes_removed and targets_removed and buckets_removed and keys_removed
        self.report['cleanup']['all_fixture_resources_removed'] = clean
        if not clean:
            self.report['cleanup']['failed_stages'] = errors
            self.report['result'] = 'failed'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--kubectl', default='kubectl')
    parser.add_argument('--snapshot-class', default='flash-disk-backup')
    parser.add_argument('--image', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--public-endpoint', help='Optional HTTPS S3 endpoint for signed synthetic-object checks')
    parser.add_argument('--test-external-proxy', action='store_true', help='Use an isolated CONNECT proxy for the first public S3 backup')
    parser.add_argument('--test-provider-registration', action='store_true', help='Register the first target through the actual Flash provider implementation')
    parser.add_argument('--proxy-image', help='Python-capable image pinned by digest for the isolated proxy')
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--flash-ops', type=Path, default=Path(__file__).resolve().parents[2] / 'IPA-RS-HeteroCloud-Flash' / 'ops')
    args = parser.parse_args()
    if args.test_external_proxy and not args.public_endpoint:
        parser.error('--test-external-proxy requires --public-endpoint')
    if args.test_provider_registration and not args.test_external_proxy:
        parser.error('--test-provider-registration requires --test-external-proxy')
    global offsite
    sys.path.insert(0, str(args.flash_ops.resolve()))
    spec = importlib.util.spec_from_file_location('flash_offsite_e2e', args.flash_ops / 'offsite.py')
    offsite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(offsite)
    probe = TwoTargets(args)
    try:
        probe.execute()
    except (Exception, KeyboardInterrupt) as error:
        probe.report.update(result='failed', failure_stage=probe.stage, failure_type=type(error).__name__)
    finally:
        probe.cleanup()
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f: json.dump(probe.report, f, indent=2)
        print(json.dumps(probe.report), flush=True)
    return 0 if probe.report['result'] == 'passed' else 1


if __name__ == '__main__': raise SystemExit(main())
