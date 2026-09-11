#!/usr/bin/env python3
"""Resize one owned DEV guest, retaining disks, identity and provisioner journal."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
health = load(Path(__file__).with_name('migrate-dev-cpu.py'), 'resize_health')
dev = health.dev
capacity = load(ROOT / 'deploy/dev/libvirt/capacity_resize.py', 'resize_capacity')


def guest(p, name):
    result = health.ssh(p, name, """import json,os,socket,subprocess
from pathlib import Path
memory=int(next(l.split()[1] for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemTotal:')))
mount=json.loads(subprocess.check_output(['findmnt','-J','-T','/var/lib/heteronetwork-dev-app-storage'],timeout=5))['filesystems'][0]
print(json.dumps({'name':socket.gethostname(),'machine':Path('/etc/machine-id').read_text().strip(),
 'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'cpus':os.cpu_count(),
 'memory_kib':memory,'mount_target':mount['target'],'mount_type':mount['fstype'],
 'kubelet':subprocess.check_output(['systemctl','is-active','kubelet'],timeout=5).decode().strip()}))
""")
    dev.require(result['name'] == name and result['machine'] == dev.identity(p, 'domain', name).replace('-', ''),
                'Guest identity differs')
    dev.require(result['mount_target'] == '/var/lib/heteronetwork-dev-app-storage'
                and result['mount_type'] == 'ext4' and result['kubelet'] == 'active', 'Guest storage/kubelet not ready')
    return result


def cluster(p, observer):
    result = health.ssh(p, observer, """import json,subprocess
k=['/usr/bin/kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=8s']
def get(a):return json.loads(subprocess.check_output(k+a,timeout=10,stderr=subprocess.DEVNULL))
ns=get(['get','namespace','kube-system','-o','json'])
nodes=get(['get','nodes','-o','json'])
db=get(['get','clusters.postgresql.cnpg.io','-A','-o','json'])
identity=get(['get','pods','-n','hetero-dev-identity','-l','app.kubernetes.io/name=keycloak','-o','json'])
deployment=get(['get','deployment','dev-keycloak','-n','hetero-dev-identity','-o','json'])
def ready(p):return not p['metadata'].get('deletionTimestamp') and any(c['type']=='Ready' and c['status']=='True' for c in p['status'].get('conditions',[]))
print(json.dumps({'uid':ns['metadata']['uid'],'nodes':{n['metadata']['name']:ready(n) for n in nodes['items']},
 'databases':{d['metadata']['namespace']+'/'+d['metadata']['name']:d.get('status',{}).get('readyInstances',0) for d in db['items']},
 'keycloak_nodes':sorted(p['spec']['nodeName'] for p in identity['items'] if ready(p)),
 'identity_rollout':deployment['status'].get('observedGeneration')==deployment['metadata']['generation'] and all(deployment['status'].get(k)==3 for k in ('replicas','updatedReplicas','availableReplicas'))}))
""")
    expected = {'hetero-dev-identity/dev-identity-postgres': 3,
                **{ns + '/dev-postgres': 3 for ns in ('heterocloud-dev', 'heterocloud-flow-dev', 'heterocloud-syouyu-dev')}}
    dev.require(result['uid'] == health.CLUSTER_UID and result['nodes'] == {n: True for n in p['vms']}
                and result['databases'] == expected and result['keycloak_nodes'] == sorted(p['vms'])
                and result['identity_rollout'],
                'Three nodes, all four DB clusters and three Keycloak replicas must be ready')
    return result


def admit(p):
    domains = dev.run(['virsh', '-c', p['connection'], 'list', '--all', '--name']).split()
    dev.require(set(domains) == {*p['vms'], 'vercel-research'}, 'Unexpected VM inventory')
    other = dev.resource_xml(p, 'domain', 'vercel-research')
    xml = ET.fromstring(other)
    dev.require(xml.find('memory').attrib == {'unit': 'KiB'}, 'Unknown other VM memory units')
    mem = {line.split(':')[0]: int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
           if line.startswith(('MemTotal:', 'MemAvailable:'))}
    budget = capacity.static_budget(mem['MemTotal'], os.cpu_count(), int(xml.findtext('memory')), int(xml.findtext('vcpu')))
    dev.require(budget['static_totals_fit'] and mem['MemAvailable'] >= (capacity.HOST_RESERVE_MIB + 6144) * 1024,
                'Insufficient current host headroom')
    return other


def resize(name, apply):
    p = dev.profile()
    dev.require(name in p['vms'], 'Unknown DEV guest')
    with dev.locked_journal(p) as journal:
        dev.verify_files(journal.value)
        dev.verify_resources(p, journal.value, allow_running=True)
        dev.verify_guard(journal.value)
        dev.require(all(dev.resource_info(p, 'domain', n)['State'] == 'running' for n in p['vms']), 'DEV guest is down')
        other = admit(p)
        observer = next(n for n in p['vms'] if n != name)
        cluster(p, observer)
        before = guest(p, name)
        original = dev.resource_xml(p, 'domain', name)
        requested = capacity.requested_xml(original, name)
        if dev.definition_hash(requested) == dev.definition_hash(original):
            dev.require(before['cpus'] == 8 and before['memory_kib'] >= 9 * 1024 * 1024, 'Configured capacity is not active')
            return {'guest': name, 'already_active': True, 'restart_performed': False}
        if not apply:
            return {'guest': name, 'admitted': True, 'restart_performed': False}
        journal.intent({'operation': 'dev-capacity-resize', 'guest': name, 'boot_before': before['boot'],
                        'before_sha256': dev.definition_hash(original), 'requested_sha256': dev.definition_hash(requested)})
        filename = 'capacity-' + name + '-' + hashlib.sha256(requested.encode()).hexdigest()[:16] + '.xml'
        dev.exclusive(journal.fd, filename, requested)
        dev.record_file(journal, dev.STATE / filename)
        journal.save()
        dev.run(['virsh', '-c', p['connection'], 'define', str(dev.STATE / filename), '--validate'])
        actual = dev.resource_xml(p, 'domain', name)
        dev.require(dev.definition_hash(actual) == dev.definition_hash(requested), 'Definition readback differs')
        journal.value['resources']['domain:' + name]['definition_sha256'] = dev.definition_hash(actual)
        journal.save()
        dev.verify_guard(journal.value)
        print(json.dumps({'guest': name, 'phase': 'requesting-graceful-poweroff'}), flush=True)
        poweroff = health.ssh(p, name, "import json,socket,subprocess; "
                             "from pathlib import Path; "
                             f"assert socket.gethostname()=={name!r} and Path('/etc/machine-id').read_text().strip()=={before['machine']!r}; "
                             f"assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()=={before['boot']!r}; "
                             "subprocess.run(['systemctl','poweroff','--no-block'],check=True,timeout=10); "
                             "print(json.dumps({'requested':True}))")
        dev.require(poweroff == {'requested': True}, 'Guest did not acknowledge graceful poweroff')
        deadline = time.monotonic() + 180
        while dev.resource_info(p, 'domain', name)['State'] != 'shut off':
            dev.require(time.monotonic() < deadline, 'Graceful shutdown timed out; no forced stop')
            time.sleep(2)
        dev.verify_resources(p, journal.value, allow_running=True)
        dev.verify_guard(journal.value)
        admit(p)
        print(json.dumps({'guest': name, 'phase': 'starting-expanded-guest'}), flush=True)
        dev.run(['virsh', '-c', p['connection'], 'start', dev.identity(p, 'domain', name)])
        actual = dev.resource_xml(p, 'domain', name)
        dev.require(dev.definition_hash(actual) == dev.definition_hash(requested), 'Restart altered definition')
        deadline = time.monotonic() + 600
        print(json.dumps({'guest': name, 'phase': 'waiting-for-cluster-recovery'}), flush=True)
        while True:
            try:
                after = guest(p, name)
                dev.require(after['boot'] != before['boot'] and after['cpus'] == 8
                            and after['memory_kib'] >= 9 * 1024 * 1024, 'New boot/capacity not observed')
                cluster(p, observer)
                break
            except (ValueError, OSError, subprocess.SubprocessError):
                dev.require(time.monotonic() < deadline, 'Recovery deadline expired; pending journal retained')
                time.sleep(5)
        dev.verify_resources(p, journal.value, allow_running=True)
        dev.verify_guard(journal.value)
        dev.require(dev.resource_xml(p, 'domain', 'vercel-research') == other, 'Unrelated domain changed')
        journal.value.setdefault('capacity_resizes', {})[name] = {
            'completed': True, 'boot_before': before['boot'], 'boot_after': after['boot'],
            'vcpu': 8, 'memory_mib': 10240}
        journal.done()
        return {'guest': name, 'restart_performed': True, 'vcpu': after['cpus'],
                'memory_kib': after['memory_kib'], 'four_databases_and_identity_ready': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', choices=capacity.GUESTS, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print(json.dumps(resize(args.guest, args.apply)))
