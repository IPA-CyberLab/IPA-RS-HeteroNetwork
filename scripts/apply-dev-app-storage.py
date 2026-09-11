#!/usr/bin/env python3
"""Host-only application PV apply after independent checks of all three DEV mounts."""
import argparse
import importlib.util
import json
from pathlib import Path


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
expansion = load(ROOT / 'scripts/expand-dev-storage.py', 'expansion')
plan = load(ROOT / 'deploy/dev/apps/storage_plan.py', 'storage_plan')
dev = expansion.dev
MANAGER = 'hetero-dev-app-storage'
BUNDLE = '/opt/heteronetwork-dev-app-activation-32497083'
HASHES = {
    'activate-storage.py': '4f0a9a8600508043d74f899e8ab2ce3c08302d8bd9459c29f81ede02ecd83b3a',
    'prepare-storage.py': 'a349cce218e84713e8967f96c3a9fee740b5441cf79819c9e0f1eb8e5ba80afe',
    'storage_plan.py': '0c480132417610c29db2f9e50b4a64367407727b040b74e3d4c76cef42ee111d',
}


def verification_code():
    return f"""import hashlib,json,subprocess,stat
from pathlib import Path
root=Path({BUNDLE!r})
for path in [*reversed(root.parents),root]:
 s=path.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
for filename,expected in {HASHES!r}.items():
 p=root/filename;s=p.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022
 assert hashlib.sha256(p.read_bytes()).hexdigest()==expected
r=subprocess.check_output(['python3',str(root/'activate-storage.py'),'verify'],timeout=35)
print(r.decode())
"""


def apply_code(manifest, write):
    # Source contains no credentials; kubectl alone reads the guest's admin.conf.
    return f"""import json,subprocess
k=['/usr/bin/kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=5s']
def run(args,data=None):
 r=subprocess.run(k+args,input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8)
 assert r.returncode==0
 return r.stdout
assert json.loads(run(['get','namespace','kube-system','-o','json']))['metadata']['uid']=={plan.CLUSTER_UID!r}
document=json.loads({json.dumps(manifest)!r})
def contains(actual,expected):
 if isinstance(expected,dict):return isinstance(actual,dict) and all(key in actual and contains(actual[key],v) for key,v in expected.items())
 return actual==expected
for desired in document['items']:
 raw=run(['get',desired['kind'],desired['metadata']['name'],'--ignore-not-found','--show-managed-fields','-o','json'])
 if raw.strip():
  actual=json.loads(raw)
  assert not actual['metadata'].get('deletionTimestamp')
  assert any(m['manager']=={MANAGER!r} for m in actual['metadata'].get('managedFields',[]))
  assert contains(actual,desired)
raw=json.dumps(document).encode()
args=['apply','--server-side','--field-manager={MANAGER}','-f','-']
run(args+['--dry-run=server'],raw)
if {write!r}:
 run(args,raw)
 observed=json.loads(run(['get','persistentvolumes','-o','json']))['items']
 observed.append(json.loads(run(['get','storageclass','dev-app-local','-o','json'])))
 by_name={{(item['kind'],item['metadata']['name']):item for item in observed}}
 for item in document['items']:
  assert contains(by_name[(item['kind'],item['metadata']['name'])],item)
print(json.dumps({{'cluster_uid':{plan.CLUSTER_UID!r},'applied':{write!r},'readback_verified':{write!r},'volume_count':18,'pvc_binding_verified':False}}))
"""


def execute(write):
    p = dev.profile()
    with dev.locked_journal(p) as journal:
        expansion.prerequisites(p, journal.value)
        expansion.inventory(p, journal.value)
        dev.require(set(expansion.completed_records(p, journal.value)) == set(expansion.GUESTS),
                    'All three app disks must be completed')
        expansion.health.cluster_ready(p, expansion.GUESTS[0])
        reports = []
        for name in expansion.GUESTS:
            report = expansion.health.ssh(p, name, verification_code())
            dev.require(report['host'] == name and report['active_mount_dependency_verified'] is True
                        and report['directory_count'] == 6 and report['directories_created'] is False
                        and report['kubelet_process_unchanged'] is True, 'Guest storage not verified')
            reports.append(report)
        dev.require(len({r['filesystem_uuid'] for r in reports}) == 3, 'Filesystem identities must differ')
        result = expansion.health.ssh(p, expansion.GUESTS[0], apply_code(plan.manifest(), write))
        return {**result, 'verified_guests': [r['host'] for r in reports], 'ha_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['inspect', 'apply'])
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args.mode == 'apply'), indent=2))
    except Exception as error:
        print(json.dumps(dev.failure_report(error)))
        raise SystemExit(1)
