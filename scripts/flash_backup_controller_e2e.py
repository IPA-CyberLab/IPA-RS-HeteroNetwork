#!/usr/bin/env python3
"""Verify the deployed Flash backup controller using only uniquely labelled fixtures.

Creates a small synthetic source disk, application pod, backup and restore in
the Flash workload namespace. Existing claims, backups and services are never
changed. Cleanup verifies labels and volume claim identities before deletion.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

LABEL = 'heterocloud.io/backup-probe'
NAMESPACE = 'heterocloud-flash-workloads'


class Probe:
    def __init__(self, args):
        self.args = args
        self.nonce = uuid.uuid4().hex
        self.backup_id = uuid.uuid4()
        self.backup = 'flash-backup-' + self.backup_id.hex
        self.source = 'backup-probe-' + self.nonce[:16] + '-source'
        self.restored = 'backup-probe-' + self.nonce[:16] + '-restored'
        self.command = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=15s']
        self.identities = {}
        self.report = {'test': 'deployed-flash-backup-controller', 'run': self.nonce,
                       'result': 'incomplete', 'checks': {}, 'cleanup': {}}
        self.stage = 'preflight'

    def call(self, *args, body=None):
        result = subprocess.run(self.command + list(args), input=json.dumps(body) if body is not None else None,
                                text=True, capture_output=True, timeout=40)
        if result.returncode:
            detail = result.stderr.strip().replace('\n', ' ')[-400:]
            raise RuntimeError('Kubernetes operation failed: ' + ' '.join(args[:3]) + ' ' + detail)
        return result.stdout

    def get(self, kind, name, namespace=NAMESPACE):
        text = self.call('-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'json')
        return json.loads(text) if text.strip() else None

    def create(self, value):
        result = json.loads(self.call('create', '-f', '-', '-o', 'json', body=value))
        self.identities[(value['kind'], value['metadata']['name'])] = result['metadata']['uid']
        return result

    def wait(self, label, fn, timeout=600):
        print(label, flush=True)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = fn()
            if value:
                return value
            time.sleep(2)
        raise TimeoutError(label)

    def metadata(self, name):
        return {'name': name, 'namespace': NAMESPACE, 'labels': {LABEL: self.nonce}}

    def claim(self, name, snapshot=None):
        spec = {'storageClassName':'longhorn-static', 'accessModes':['ReadWriteOnce'],
                'resources':{'requests':{'storage':'1Gi'}}}
        if snapshot:
            spec['dataSource']={'apiGroup':'snapshot.storage.k8s.io','kind':'VolumeSnapshot','name':snapshot}
        self.create({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':self.metadata(name),'spec':spec})
        return self.wait('wait for isolated disk '+name, lambda: p if (p:=self.get('pvc',name)) and
                         p.get('status',{}).get('phase')=='Bound' else None)

    def pod(self, name, claim):
        self.create({'apiVersion':'v1','kind':'Pod','metadata':self.metadata(name),'spec':{
            'runtimeClassName':'gvisor','restartPolicy':'Never','automountServiceAccountToken':False,
            'securityContext':{'runAsUser':0,'runAsGroup':0,'runAsNonRoot':False,'seccompProfile':{'type':'RuntimeDefault'}},
            'affinity':{'nodeAffinity':{'requiredDuringSchedulingIgnoredDuringExecution':{'nodeSelectorTerms':[
                {'matchExpressions':[{'key':'heteronetwork.io/control-plane-only','operator':'NotIn','values':['true']}]}]}}},
            'containers':[{'name':'probe','image':self.args.image,'command':['/bin/sh','-c','sleep infinity'],
                'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'250m','memory':'128Mi'}},
                'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},
                'volumeMounts':[{'name':'data','mountPath':'/data'}]}],
            'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':claim}}]}})
        return self.wait('wait for isolated workload '+name, lambda: p if (p:=self.get('pod',name)) and
                         any(c['type']=='Ready' and c['status']=='True' for c in p.get('status',{}).get('conditions',[])) else None)

    def exec(self, pod, command):
        return self.call('-n',NAMESPACE,'exec',pod,'--','/bin/sh','-ec',command).strip()

    def execute(self):
        if '@sha256:' not in self.args.image:
            raise RuntimeError('fixture image must be digest-pinned')
        for kind, name in [('pvc',self.source),('pvc',self.restored),('pod',self.source),('pod',self.restored),('flashbackup',self.backup)]:
            if self.get(kind,name):
                raise RuntimeError('fixture name already exists')
        target=self.get('backuptargets.longhorn.io','default','longhorn-system')
        if not target or not target.get('status',{}).get('available'):
            raise RuntimeError('default Syouyu backup target is unavailable')
        self.stage='source'
        source=self.claim(self.source)
        self.pod(self.source,self.source)
        self.exec(self.source,"printf '%s' "+self.nonce+" > /data/marker; sync")
        self.stage='backup'
        self.create({'apiVersion':'flash.heterocloud.io/v1alpha1','kind':'FlashBackup',
            'metadata':dict(self.metadata(self.backup),finalizers=['flash.heterocloud.io/backup-protection']),
            'spec':{'id':str(self.backup_id),'name':'isolated-probe','organization_id':str(uuid.uuid4()),
                'project_id':str(uuid.uuid4()),'service_instance_id':str(uuid.uuid4()),'source_pvc':self.source,
                'source_pvc_uid':source['metadata']['uid'],'volume_size_bytes':1024**3,'snapshot_class':'flash-disk-backup'}})
        backup=self.wait('wait for deployed controller backup',lambda: b if (b:=self.get('flashbackup',self.backup)) and
                         b.get('status',{}).get('phase')=='ready' else None,900)
        snapshot=self.get('volumesnapshot',self.backup)
        if not snapshot or not snapshot.get('status',{}).get('readyToUse'):
            raise RuntimeError('ready backup has no ready CSI snapshot')
        content=self.get('volumesnapshotcontent',snapshot['status']['boundVolumeSnapshotContentName'])
        if not content.get('status',{}).get('snapshotHandle','').startswith('bak://'):
            raise RuntimeError('snapshot is not a durable storage backup')
        self.report['checks']['deployed_controller_created_syouyu_backup']=True
        pv=self.get('pv',source['spec']['volumeName'])
        handle=pv['spec']['csi']['volumeHandle']
        def reset():
            volume=self.get('volumes.longhorn.io',handle,'longhorn-system')
            return volume and volume.get('spec',{}).get('backupTargetName')=='default' and \
                not volume.get('metadata',{}).get('annotations',{}).get('flash.heterocloud.io/backup-destination-lock')
        self.wait('wait for source target lock release',reset)
        self.report['checks']['source_target_lock_released']=True
        self.stage='restore'
        restored=self.claim(self.restored,self.backup)
        pv=self.get('pv',restored['spec']['volumeName'])
        handle=pv['spec']['csi']['volumeHandle']
        self.wait('wait for isolated restore',lambda: v if (v:=self.get('volumes.longhorn.io',handle,'longhorn-system')) and
                  v.get('status',{}).get('restoreInitiated') is True and v.get('status',{}).get('restoreRequired') is False else None,900)
        self.pod(self.restored,self.restored)
        if self.exec(self.restored,'cat /data/marker')!=self.nonce:
            raise RuntimeError('restored fixture contents do not match')
        self.report['checks']['deployed_backup_restores_original_contents']=True
        self.report['result']='passed'

    def owned(self, kind, name):
        value=self.get(kind,name)
        if value is None:
            return None
        if value['metadata'].get('labels',{}).get(LABEL)!=self.nonce:
            raise RuntimeError('fixture label mismatch')
        recorded=self.identities.get(({'pvc':'PersistentVolumeClaim','pod':'Pod','flashbackup':'FlashBackup'}[kind],name))
        if recorded and value['metadata'].get('uid')!=recorded:
            raise RuntimeError('fixture UID changed')
        return value

    def cleanup(self):
        errors=[]
        def attempt(label, fn):
            try:
                fn()
                return True
            except Exception:
                errors.append(label)
                return False
        def delete_pod(name):
            if self.owned('pod',name):
                self.call('-n',NAMESPACE,'delete','pod',name,'--wait=false')
                self.wait('remove isolated workload '+name,lambda:self.get('pod',name) is None,300)
        pods_removed=[attempt('pod',lambda name=name:delete_pod(name)) for name in (self.source,self.restored)]
        def delete_backup():
            if self.owned('flashbackup',self.backup):
                self.call('-n',NAMESPACE,'delete','flashbackup',self.backup,'--wait=false')
                self.wait('remove isolated backup',lambda:self.get('flashbackup',self.backup) is None,600)
            self.wait('remove isolated snapshot',lambda:self.get('volumesnapshot',self.backup) is None,300)
        backup_removed=attempt('backup',delete_backup)
        def delete_claim(name):
            claim=self.owned('pvc',name)
            if not claim: return
            volume=claim.get('spec',{}).get('volumeName')
            if volume:
                pv=self.get('pv',volume)
                if pv:
                    ref=pv.get('spec',{}).get('claimRef',{})
                    if ref.get('uid')!=claim['metadata']['uid'] or ref.get('name')!=name or ref.get('namespace')!=NAMESPACE:
                        raise RuntimeError('fixture volume ownership changed')
                    self.call('patch','pv',volume,'--type=merge','--patch-file=/dev/stdin',body={
                        'metadata':{'resourceVersion':pv['metadata']['resourceVersion']},'spec':{'persistentVolumeReclaimPolicy':'Delete'}})
            self.call('-n',NAMESPACE,'delete','pvc',name,'--wait=false')
            self.wait('remove isolated claim '+name,lambda:self.get('pvc',name) is None,300)
            if volume: self.wait('remove isolated volume '+name,lambda:self.get('pv',volume) is None,600)
        if backup_removed and all(pods_removed):
            for name in (self.source,self.restored): attempt('claim',lambda name=name:delete_claim(name))
        else:
            errors.append('claims retained until dependent fixtures are removed')
        self.report['cleanup']['all_fixture_resources_removed']=not errors
        if errors:
            self.report['cleanup']['failed_stages']=errors
            self.report['result']='failed'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl',default='kubectl')
    parser.add_argument('--kubeconfig',required=True)
    parser.add_argument('--image',required=True)
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    probe=Probe(args)
    try: probe.execute()
    except (Exception,KeyboardInterrupt) as error:
        probe.report.update(result='failed',failure_stage=probe.stage,failure_type=type(error).__name__,
                            failure_reason=str(error)[:300])
    finally:
        probe.cleanup()
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as file: json.dump(probe.report,file,indent=2)
        print(json.dumps(probe.report),flush=True)
    return 0 if probe.report['result']=='passed' else 1


if __name__=='__main__': raise SystemExit(main())
