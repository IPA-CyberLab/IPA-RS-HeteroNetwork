#!/usr/bin/env python3
"""Migrate one owned DEV guest from qemu64 to host-model, with a cold restart."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

sys_path = Path(__file__).with_name('provision-dev-libvirt.py')
spec = importlib.util.spec_from_file_location('dev_provisioner', sys_path)
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)
CLUSTER_UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
FLAGS = {'cx16', 'lahf_lm', 'popcnt', 'pni', 'ssse3', 'sse4_1', 'sse4_2'}


def without_cpu(text):
    root = ET.fromstring(text)
    for cpu in root.findall('cpu'):
        root.remove(cpu)
    return ET.canonicalize(ET.tostring(root, encoding='unicode'), strip_text=True)


def change_cpu(text, name, expected_uuid):
    root = ET.fromstring(text)
    dev.require(root.tag == 'domain' and root.get('type') == 'kvm' and
                root.findtext('name') == name and root.findtext('uuid') == expected_uuid,
                'DEV domain identity differs')
    cpus = root.findall('cpu')
    dev.require(len(cpus) == 1, 'Expected one observed CPU definition')
    cpu = cpus[0]
    if cpu.get('mode') == 'host-model' and cpu.get('check') == 'full':
        return text
    dev.require(cpu.attrib == {'mode': 'custom', 'match': 'exact', 'check': 'none'} and
                len(cpu) == 1 and cpu[0].tag == 'model' and cpu[0].text == 'qemu64' and
                cpu[0].attrib == {'fallback': 'forbid'}, 'Unreviewed CPU configuration')
    index = list(root).index(cpu)
    root.remove(cpu)
    root.insert(index, ET.Element('cpu', {'mode': 'host-model', 'check': 'full'}))
    result = ET.tostring(root, encoding='unicode')
    dev.require(without_cpu(result) == without_cpu(text), 'Non-CPU definition changed')
    return result


def ssh(p, name, code):
    address = p['addresses'][p['vms'].index(name)]
    args = ['ssh', '-F', '/dev/null', '-i', str(dev.STATE / 'admin_ed25519'),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=5', '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-o', 'UserKnownHostsFile=' + str(dev.STATE / 'known_hosts'),
            'devadmin@' + address, 'sudo -n python3 -c ' + shlex.quote(code)]
    return json.loads(dev.run(args, timeout=45))


def guest_state(p, name):
    result = ssh(p, name, """import json,socket
from pathlib import Path
flags=next(x for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('flags')).split(':',1)[1].split()
print(json.dumps({'name':socket.gethostname(),'machine':Path('/etc/machine-id').read_text().strip(),
 'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'flags':flags}))
""")
    dev.require(result['name'] == name and result['machine'] == dev.identity(p, 'domain', name).replace('-', ''),
                'Guest machine identity differs')
    return result


def cluster_ready(p, observer):
    result = ssh(p, observer, """import json,subprocess
k=['/usr/bin/kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=10s']
def get(args):return json.loads(subprocess.check_output(k+args,timeout=15,stderr=subprocess.DEVNULL))
ns=get(['get','namespace','kube-system','-o','json'])
nodes=get(['get','nodes','-o','json'])
db=get(['get','cluster.postgresql.cnpg.io','dev-identity-postgres','-n','hetero-dev-identity','-o','json'])
print(json.dumps({'uid':ns['metadata']['uid'],'nodes':{n['metadata']['name']:any(c['type']=='Ready' and c['status']=='True' for c in n['status']['conditions']) for n in nodes['items']},'database_ready':db['status'].get('readyInstances')}))
""")
    dev.require(result['uid'] == CLUSTER_UID and result['nodes'] == {name: True for name in p['vms']}
                and result['database_ready'] == 3, 'All three DEV nodes and database instances must be ready')


def migrate(name):
    p = dev.profile()
    dev.require(name in p['vms'], 'Unknown DEV guest')
    host_flags = set(next(x for x in Path('/proc/cpuinfo').read_text().splitlines()
                          if x.startswith('flags')).split(':', 1)[1].split())
    dev.require(FLAGS <= host_flags, 'Host lacks required v2 flags')
    with dev.locked_journal(p) as journal:
        dev.verify_files(journal.value)
        dev.verify_resources(p, journal.value, allow_running=True)
        dev.verify_guard(journal.value)
        dev.require(all(dev.resource_info(p, 'domain', n)['State'] == 'running' for n in p['vms']),
                    'All guests must be running before a new migration')
        observer = next(n for n in p['vms'] if n != name)
        cluster_ready(p, observer)
        before = guest_state(p, name)
        original = dev.resource_xml(p, 'domain', name)
        requested = change_cpu(original, name, dev.identity(p, 'domain', name))
        record = journal.value.get('cpu_migrations', {}).get(name)
        if requested == original and FLAGS <= set(before['flags']) and record and record.get('completed'):
            return {'guest': name, 'already_verified': True, 'restart_performed': False}
        if requested != original:
            journal.intent({'operation': 'dev-cpu-host-model', 'guest': name,
                            'before_sha256': dev.definition_hash(original),
                            'requested_sha256': dev.definition_hash(requested)})
            filename = 'cpu-' + name + '-' + hashlib.sha256(requested.encode()).hexdigest()[:16] + '.xml'
            dev.exclusive(journal.fd, filename, requested)
            dev.record_file(journal, dev.STATE / filename)
            dev.run(['virsh', '-c', p['connection'], 'define', str(dev.STATE / filename), '--validate'])
            actual = dev.resource_xml(p, 'domain', name)
            dev.require(without_cpu(actual) == without_cpu(original) and
                        ET.fromstring(actual).find('cpu').get('mode') == 'host-model', 'CPU readback mismatch')
            journal.value['resources']['domain:' + name]['definition_sha256'] = dev.definition_hash(actual)
            journal.done()
        journal.value.setdefault('cpu_migrations', {})[name] = {'completed': False, 'boot_before': before['boot']}
        journal.save()
        dev.verify_guard(journal.value)
        dev.run(['virsh', '-c', p['connection'], 'shutdown', dev.identity(p, 'domain', name), '--mode', 'acpi'])
        deadline = time.monotonic() + 180
        while dev.resource_info(p, 'domain', name)['State'] != 'shut off':
            dev.require(time.monotonic() < deadline, 'Graceful shutdown timed out; no forced stop performed')
            time.sleep(2)
        dev.verify_resources(p, journal.value, allow_running=True)
        dev.verify_guard(journal.value)
        dev.run(['virsh', '-c', p['connection'], 'start', dev.identity(p, 'domain', name)])
        actual = dev.resource_xml(p, 'domain', name)
        dev.require(without_cpu(actual) == without_cpu(original), 'Non-CPU readback changed after start')
        journal.value['resources']['domain:' + name]['definition_sha256'] = dev.definition_hash(actual)
        journal.save()
        deadline = time.monotonic() + 420
        while True:
            try:
                after = guest_state(p, name)
                dev.require(after['boot'] != before['boot'] and FLAGS <= set(after['flags']),
                            'New boot and CPU flags not observed')
                cluster_ready(p, observer)
                break
            except (ValueError, OSError, subprocess.SubprocessError):
                dev.require(time.monotonic() < deadline, 'Recovery deadline expired; inspect this guest before continuing')
                time.sleep(5)
        dev.verify_resources(p, journal.value, allow_running=True)
        dev.verify_guard(journal.value)
        journal.value['cpu_migrations'][name].update(completed=True, boot_after=after['boot'])
        journal.save()
        return {'guest': name, 'cpu_mode': 'host-model', 'restart_performed': True,
                'guest_v2_flags_verified': True, 'three_nodes_and_database_ready': True,
                'production_modified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', choices=['hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3'], required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(migrate(args.guest)))
    except Exception as error:
        print(json.dumps(dev.failure_report(error)))
        raise SystemExit(1)
