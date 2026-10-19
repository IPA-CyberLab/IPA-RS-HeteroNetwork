#!/usr/bin/env python3
"""Verify real CSI backup durability after deleting an isolated source volume.

Never mounts or changes an existing volume. Only the uniquely labelled test
namespace and PVs with its recorded claim UIDs can be cleaned up. Uses gVisor
on worker nodes; no user data, tokens or bucket credentials are read.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid


class Probe:
    def __init__(self, args):
        self.args = args
        self.nonce = uuid.uuid4().hex
        self.namespace = 'flash-backup-storage-e2e-' + self.nonce[:8]
        self.command = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=15s']
        self.claims = {}
        self.report = {'schema_version': 1, 'namespace': self.namespace, 'test': 'real-csi-s3-backup-restore'}

    def kube(self, *args, body=None, optional=False):
        result = subprocess.run(self.command + list(args), input=json.dumps(body) if body is not None else None,
                                text=True, capture_output=True, timeout=45)
        if result.returncode:
            if optional and '(NotFound)' in result.stderr:
                return None
            raise RuntimeError('probe Kubernetes operation failed: ' + ' '.join(args[:3]) + ' ' + result.stderr[-1000:])
        return result.stdout

    def get(self, kind, name, namespace=None):
        raw = self.kube('-n', namespace or self.namespace, 'get', kind, name, '-o', 'json', optional=True)
        return json.loads(raw) if raw else None

    def apply(self, value):
        self.kube('create', '-f', '-', body=value)

    def wait(self, description, condition, timeout=600):
        print(description, flush=True)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = condition()
            if value:
                return value
            time.sleep(2)
        raise RuntimeError('timed out: ' + description)

    def claim(self, name, restore=False):
        value = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name, 'namespace': self.namespace},
                 'spec': {'storageClassName': self.args.storage_class, 'accessModes': ['ReadWriteMany'],
                          'resources': {'requests': {'storage': '1Gi'}}}}
        if restore:
            value['spec']['dataSource'] = {'apiGroup': 'snapshot.storage.k8s.io', 'kind': 'VolumeSnapshot', 'name': 'backup'}
        self.apply(value)
        pvc = self.wait('wait for ' + name + ' disk', lambda: (p if (p := self.get('pvc', name)) and p.get('status', {}).get('phase') == 'Bound' else None))
        self.claims[name] = {'uid': pvc['metadata']['uid'], 'pv': pvc['spec']['volumeName']}
        return pvc

    def pod(self, name, claim):
        self.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': self.namespace},
                    'spec': {'runtimeClassName': 'gvisor', 'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                             'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [
                                 {'matchExpressions': [{'key': 'heteronetwork.io/control-plane-only', 'operator': 'NotIn', 'values': ['true']}]}]}}},
                             'containers': [{'name': 'probe', 'image': self.args.image, 'command': ['/bin/sh', '-c', 'sleep infinity'],
                                             'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '250m', 'memory': '128Mi'}},
                                             'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                                             'volumeMounts': [{'name': 'data', 'mountPath': '/data'}]}],
                             'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': claim}}]}})
        return self.wait('wait for ' + name + ' gVisor Pod', lambda: (p if (p := self.get('pod', name)) and any(c['type'] == 'Ready' and c['status'] == 'True' for c in p.get('status', {}).get('conditions', [])) else None))

    def exec(self, pod, command):
        return self.kube('-n', self.namespace, 'exec', pod, '--', '/bin/sh', '-ec', command).strip()

    def delete_claim(self, name):
        saved = self.claims.get(name)
        if not saved:
            return
        pv = self.get('pv', saved['pv'])
        if pv:
            ref = pv['spec']['claimRef']
            if ref['uid'] != saved['uid'] or ref['namespace'] != self.namespace:
                raise RuntimeError('refusing to clean up a volume with another claim identity')
            self.kube('patch', 'pv', saved['pv'], '--type=merge', '--patch-file=/dev/stdin', body={'metadata': {'resourceVersion': pv['metadata']['resourceVersion']}, 'spec': {'persistentVolumeReclaimPolicy': 'Delete'}})
        self.kube('-n', self.namespace, 'delete', 'pvc', name, '--wait=false', '--ignore-not-found=true')
        self.wait('delete isolated ' + name + ' volume', lambda: self.get('pv', saved['pv']) is None)

    def run(self):
        target = self.get('backuptargets.longhorn.io', 'default', 'longhorn-system')
        if not target or not target.get('status', {}).get('available'):
            raise RuntimeError('default backup store must be available')
        self.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': self.namespace, 'labels': {'heterocloud.io/backup-probe': self.nonce}}})
        try:
            self.claim('source')
            pod = self.pod('source', 'source')
            source_hash = self.exec('source', "printf '%s' " + self.nonce + " > /data/marker; dd if=/dev/urandom of=/data/payload bs=1048576 count=2 2>/dev/null; sync; sha256sum /data/payload").split()[0]
            self.apply({'apiVersion': 'snapshot.storage.k8s.io/v1', 'kind': 'VolumeSnapshot', 'metadata': {'name': 'backup', 'namespace': self.namespace},
                        'spec': {'volumeSnapshotClassName': self.args.snapshot_class, 'source': {'persistentVolumeClaimName': 'source'}}})
            snapshot = self.wait('upload durable backup', lambda: (s if (s := self.get('volumesnapshot', 'backup')) and s.get('status', {}).get('readyToUse') else None), 1800)
            content = json.loads(self.kube('get', 'volumesnapshotcontent', snapshot['status']['boundVolumeSnapshotContentName'], '-o', 'json'))
            if not content.get('status', {}).get('snapshotHandle', '').startswith('bak://'):
                raise RuntimeError('CSI produced a local snapshot rather than a durable backup')
            self.exec('source', 'printf later-state > /data/marker; printf corrupted > /data/payload; sync')
            self.report['source_changed_after_backup'] = self.exec('source', 'cat /data/marker') == 'later-state'
            self.kube('-n', self.namespace, 'delete', 'pod', 'source', '--wait=false')
            self.wait('remove source Pod', lambda: self.get('pod', 'source') is None)
            self.delete_claim('source')
            self.report['source_volume_deleted_before_restore'] = True
            self.claim('restored', restore=True)
            pv = self.get('pv', self.claims['restored']['pv'])
            volume_name = pv['spec']['csi']['volumeHandle']
            def copied():
                volume = self.get('volumes.longhorn.io', volume_name, 'longhorn-system')
                status = volume.get('status', {}) if volume else {}
                return status.get('restoreInitiated') is True and status.get('restoreRequired') is False
            self.wait('finish copying restored disk before any user Pod exists', copied)
            self.report['stopped_restore_copy_complete'] = True
            self.kube('-n', self.namespace, 'delete', 'volumesnapshot', 'backup', '--wait=false')
            self.wait('delete backup before first restored workload mount', lambda: self.get('volumesnapshot', 'backup') is None)
            self.report['backup_deleted_before_first_restore_mount'] = True
            restored_pod = self.pod('restored', 'restored')
            assert self.exec('restored', 'cat /data/marker') == self.nonce
            assert self.exec('restored', 'sha256sum /data/payload').split()[0] == source_hash
            assert self.claims['source']['uid'] != self.claims['restored']['uid']
            self.report.update({'restored_original_marker_and_sha256': True, 'new_disk_identity': True,
                                'source_node': pod['spec']['nodeName'], 'restored_node': restored_pod['spec']['nodeName']})
            self.kube('-n', self.namespace, 'delete', 'volumesnapshot', 'backup', '--wait=false', '--ignore-not-found=true')
            self.wait('delete backup metadata and remote backup', lambda: self.get('volumesnapshot', 'backup') is None)
            # A completed restored volume must remain usable after deleting its backup.
            assert self.exec('restored', 'cat /data/marker') == self.nonce
            self.report['restored_disk_survives_backup_deletion'] = True
        finally:
            namespace = self.get('namespace', self.namespace)
            if namespace and namespace['metadata'].get('labels', {}).get('heterocloud.io/backup-probe') == self.nonce:
                self.kube('-n', self.namespace, 'delete', 'volumesnapshot', 'backup', '--ignore-not-found=true', '--wait=false')
                self.wait('remove probe snapshot', lambda: self.get('volumesnapshot', 'backup') is None)
                for name in ['source', 'restored']:
                    self.kube('-n', self.namespace, 'delete', 'pod', name, '--ignore-not-found=true', '--wait=false')
                self.wait('remove probe Pods', lambda: not any(self.get('pod', name) for name in ['source', 'restored']))
                for name in self.claims:
                    self.delete_claim(name)
                self.kube('delete', 'namespace', self.namespace, '--wait=false')
                self.wait('remove probe namespace', lambda: self.get('namespace', self.namespace) is None)
                self.report['cleanup_complete'] = True
            Path(self.args.report).write_text(json.dumps(self.report, indent=2) + '\n')
        print(json.dumps(self.report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl', default='kubectl')
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--storage-class', default='longhorn-static')
    parser.add_argument('--snapshot-class', default='flash-disk-backup')
    parser.add_argument('--image', required=True)
    parser.add_argument('--report', required=True)
    Probe(parser.parse_args()).run()
