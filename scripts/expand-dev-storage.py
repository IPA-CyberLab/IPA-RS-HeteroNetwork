#!/usr/bin/env python3
"""Host-only DEV app disks. No guest formatting, rollback, adoption or HA claim.

plan is offline/read-only, NOT capacity admission. apply requires local root,
exclusive operator control of libvirt/storage, and explicit bounded SSH health
probes using the existing pinned identities and existing sudo permissions.
Unknown pool entries/controllers deliberately require manual review.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import uuid
import xml.etree.ElementTree as ET


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dev = load('provision-dev-libvirt.py', 'storage_provisioner')
health = load('migrate-dev-cpu.py', 'storage_health')
GIB = 1024 ** 3
GUESTS = ['hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3']
OTHER = 'vercel-research'


def serial(p, name):
    return 'hnapp-' + uuid.UUID(dev.identity(p, 'domain', name)).hex[:12]


def disk_path(p, name):
    return Path(p['pool_path']) / (name + '-apps.qcow2')


def capacity(available, roots, completed):
    """Inputs are actual allocated bytes; completed apps are already on disk."""
    dev.require(type(available) is int and available >= 0 and len(roots) == 4
                and len(completed) <= 3, 'Invalid capacity inventory')
    dev.require(all(type(n) is int and n >= 0 for n in [*roots, *completed]),
                'Invalid allocation measurement')
    growth = sum(max(0, 40 * GIB - n) for n in roots)
    growth += sum(max(0, 64 * GIB - n) for n in completed)
    required = (3 - len(completed)) * 64 * GIB + 128 * GIB + growth + 5 * GIB
    return {'available_bytes': available, 'required_bytes': required,
            'remaining_growth_bytes': growth, 'admitted': available >= required}


def canonical(text):
    return ET.canonicalize(text, strip_text=True)


def domain(text, p, name):
    root = ET.fromstring(text)
    dev.require(root.tag == 'domain' and root.get('type') == 'kvm'
                and root.findtext('name') == name and len(root.findall('devices')) == 1,
                'Unexpected domain XML')
    if name in GUESTS:
        dev.require(root.findtext('uuid') == dev.identity(p, 'domain', name), 'Domain UUID differs')
    return root


def app_disk(root, p, name):
    matches = [d for d in root.findall('devices/disk')
               if d.findtext('serial') == serial(p, name)
               or any(s.get('file') == str(disk_path(p, name)) for s in d.findall('source'))
               or any(t.get('dev') == 'vdb' for t in d.findall('target'))]
    dev.require(len(matches) == 1, 'App disk absent or ambiguous')
    d = matches[0]
    dev.require(d.get('type') == 'file' and d.get('device') == 'disk'
                and len(d.findall('source')) == len(d.findall('target')) == len(d.findall('driver')) == 1
                and len(d.findall('serial')) == 1
                and d.find('source').attrib == {'file': str(disk_path(p, name))}
                and d.find('target').attrib == {'dev': 'vdb', 'bus': 'virtio'}
                and d.find('driver').get('name') == 'qemu' and d.find('driver').get('type') == 'qcow2'
                and d.findtext('serial') == serial(p, name)
                and d.find('readonly') is None and d.find('shareable') is None,
                'Foreign or incorrect app disk mapping')
    dev.require(all(c.tag in {'driver', 'source', 'target', 'serial', 'address', 'alias', 'backingStore'}
                    for c in d) and all(not len(b) and not b.attrib for b in d.findall('backingStore')),
                'Unexpected app disk XML')
    return d


def verify_addition(before, after, p, name):
    root = domain(after, p, name)
    root.find('devices').remove(app_disk(root, p, name))
    dev.require(canonical(ET.tostring(root, encoding='unicode')) == canonical(before),
                'Hotplug changed preexisting XML; manual review required')


def disk_xml(before, p, name):
    root = domain(before, p, name)
    dev.require(not any(d.findtext('serial') == serial(p, name)
                        or any(t.get('dev') == 'vdb' for t in d.findall('target'))
                        or any(s.get('file') == str(disk_path(p, name)) for s in d.findall('source'))
                        for d in root.findall('devices/disk')), 'App disk target already occupied')
    controllers = root.findall('devices/controller')
    keys = [(c.get('type'), c.get('index')) for c in controllers]
    dev.require(len(keys) == len(set(keys)), 'Ambiguous controllers')
    pci = [c for c in controllers if c.get('type') == 'pci']
    addresses = root.findall('devices/*/address')
    used = {(int(a.get('bus', '0'), 0), int(a.get('slot', '0'), 0))
            for a in addresses if a.get('type') == 'pci'}
    candidates = []
    for c in pci:
        if (c.get('model') == 'pcie-root-port' and c.get('index', '').isdigit()
                and all(t.get('hotplug', 'on') == 'on' for t in c.findall('target'))):
            bus = int(c.get('index'))
            if bus and not any(b == bus for b, _ in used):
                candidates.append((bus, 0))
    if len(pci) == 1 and pci[0].get('model') == 'pci-root' and pci[0].get('index') == '0':
        candidates = [(0, s) for s in range(1, 32) if (0, s) not in used]
    dev.require(bool(candidates) and all(c.get('model') in {'pci-root', 'pcie-root', 'pcie-root-port'}
                                        for c in pci), 'No reviewed existing hotplug controller slot')
    bus, slot = candidates[0]
    d = ET.Element('disk', type='file', device='disk')
    ET.SubElement(d, 'driver', name='qemu', type='qcow2')
    ET.SubElement(d, 'source', file=str(disk_path(p, name)))
    ET.SubElement(d, 'target', dev='vdb', bus='virtio')
    ET.SubElement(d, 'serial').text = serial(p, name)
    ET.SubElement(d, 'address', type='pci', domain='0x0000', bus=hex(bus), slot=hex(slot), function='0x0')
    result = ET.tostring(d, encoding='unicode')
    root.find('devices').append(copy.deepcopy(d))
    verify_addition(before, ET.tostring(root, encoding='unicode'), p, name)
    return result


def completed_records(p, value):
    records = value.get('app_storage', {})
    dev.require(set(records) <= set(GUESTS), 'Unknown expansion record')
    for name, r in records.items():
        dev.require(r == {'completed': True, 'path': str(disk_path(p, name)),
                          'serial': serial(p, name), 'size_bytes': 64 * GIB},
                    'Partial or foreign expansion record; no adoption')
        f = value['files'].get(str(disk_path(p, name)), {})
        dev.require(f.get('mutable') is True and f.get('sha256') is None,
                    'Missing mutable app ownership record')
    return records


def virsh(p, *args):
    return dev.run(['virsh', '-c', p['connection'], *args])


def file_info(path, filesystem, seen):
    path = dev.checked_path(path)
    s = path.stat()
    key = (s.st_dev, s.st_ino)
    dev.require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_dev == filesystem
                and key not in seen, 'Storage must be distinct regular files on the same filesystem')
    seen.add(key)
    return s.st_blocks * 512


def image_info(path, size):
    dev.validate_base_header(path)
    info = dev.decode(dev.run(['qemu-img', 'info', '--force-share', '--output=json', str(path)]))
    dev.require(info.get('format') == 'qcow2' and info.get('virtual-size') == size
                and not info.get('backing-filename') and not info.get('snapshots')
                and not info.get('data-file')
                and not info.get('format-specific', {}).get('data', {}).get('data-file'),
                'Unexpected disk size, backing, external data or snapshots')


def verify_ext4(path):
    mount = dev.decode(dev.run(['findmnt', '--json', '--target', str(path), '--output', 'FSTYPE']))
    dev.require(mount == {'filesystems': [{'fstype': 'ext4'}]}, 'Only ext4 admitted')


def preallocate(path):
    """Called only for this operation's exclusively created empty file."""
    verify_ext4(path.parent)
    dev.run(['qemu-img', 'create', '-f', 'qcow2', '-o', 'preallocation=falloc',
             str(path), '64G'], timeout=900)
    image_info(path, 64 * GIB)
    dev.require(path.stat().st_blocks * 512 >= 64 * GIB, 'Full preallocation not verified')


def pool_file(p, value, pool_name, path, filesystem, seen):
    backups = {n + '-seed.iso.before-schema-repair' for n in GUESTS}
    is_dev = pool_name == p['name']
    base = 'ubuntu-base.img' if is_dev else 'ubuntu-24.04-server-cloudimg-amd64.img'
    dev.require(pool_name in {p['name'], OTHER}
                and (path.name == base or (is_dev and path.name in backups)),
                'Unknown pool allocation; manual review required')
    file_info(path, filesystem, seen)
    record = value['files'].get(str(path))
    # DEV bases and seed-repair backups must already belong to the provisioner.
    # The unrelated pool has no ownership journal here; never adopt its files.
    dev.require(not is_dev or record is not None, 'Missing immutable pool file ownership')
    if record is not None:
        dev.require(record.get('mutable') is False and isinstance(record.get('sha256'), str)
                    and record.get('inode') == dev.inode(path), 'Immutable pool file ownership differs')
        dev.require(dev.digest_file(path) == record['sha256'], 'Immutable pool file hash differs')
    if path.name == base:
        dev.validate_base_header(path)
        info = dev.decode(dev.run(['qemu-img', 'info', '--force-share', '--output=json', str(path)]))
        image_info(path, info['virtual-size'])


def inventory(p, value):
    records = completed_records(p, value)
    dev.require(set(virsh(p, 'list', '--all', '--name').split()) == set(GUESTS + [OTHER]),
                'Expected exactly four domains')
    dev.require(set(virsh(p, 'pool-list', '--all', '--name').split()) == {p['name'], OTHER},
                'Unknown or missing pools')
    fs = Path(p['pool_path']).stat().st_dev
    pools = {}
    for name in (p['name'], OTHER):
        root = ET.fromstring(dev.resource_xml(p, 'pool', name))
        dev.require(root.get('type') == 'dir' and root.findtext('name') == name
                    and len(root.findall('target/path')) == 1, 'Unreviewed pool')
        path = dev.checked_path(root.findtext('target/path'))
        fd = dev.root_directory(path)
        os.close(fd)
        dev.require(path.stat().st_dev == fs, 'Pools differ in filesystem')
        verify_ext4(path)
        pools[name] = path
    dev.require(pools[p['name']] == Path(p['pool_path']) and pools[p['name']] != pools[OTHER],
                'Pool path mismatch')
    seen, roots, apps, xmls = set(), [], [], {}
    allowed = {name: set() for name in pools}
    for name in GUESTS + [OTHER]:
        persistent = dev.resource_xml(p, 'domain', name)
        live = virsh(p, 'dumpxml', name)
        xmls[name] = (persistent, live)
        dev.require(not virsh(p, 'snapshot-list', name, '--name').strip(), 'Managed snapshots refused')
        root = domain(persistent, p, name)
        live_root = domain(live, p, name)
        dev.require(root.findtext('uuid') == live_root.findtext('uuid'), 'Live identity differs')
        pool_name = p['name'] if name in GUESTS else OTHER
        disks = root.findall('devices/disk')
        live_disks = live_root.findall('devices/disk')
        def mapping(ds):
            return [(d.get('type'), d.get('device'), d.find('source').get('file'),
                     d.find('target').attrib, d.find('driver').get('type'), d.findtext('serial')) for d in ds]
        dev.require(mapping(disks) == mapping(live_disks), 'Live/persistent disk inventory differs')
        writable = [d for d in disks if d.get('device') == 'disk']
        dev.require(len(writable) == 1 + (name in records), 'Unknown disk allocation')
        for d in disks + live_disks:
            dev.require(d.get('type') == 'file' and d.get('device') in {'disk', 'cdrom'}
                        and all(not len(b) and not b.attrib for b in d.findall('backingStore')),
                        'Unknown disk type or backing XML')
        for d in disks:
            path = dev.checked_path(d.find('source').get('file'))
            dev.require(path.parent == pools[pool_name], 'Disk outside expected pool')
            allocated = file_info(path, fs, seen)
            allowed[pool_name].add(path.name)
            if d.get('device') == 'cdrom':
                dev.require(d.find('readonly') is not None and d.find('driver').get('type') == 'raw'
                            and path.name == name + '-seed.iso', 'Unknown seed media')
            elif d.find('target').get('dev') == 'vda':
                dev.require(path.name == name + '.qcow2' and d.find('driver').get('type') == 'qcow2'
                            and d.find('readonly') is None and d.find('shareable') is None,
                            'Root path or format differs')
                image_info(path, 40 * GIB)
                roots.append(allocated)
            else:
                dev.require(name in records, 'Unowned app disk; no adoption')
                app_disk(root, p, name)
                app_disk(live_root, p, name)
                image_info(path, 64 * GIB)
                dev.require(allocated >= 64 * GIB, 'App preallocation no longer complete')
                apps.append(allocated)
    for name, pool in pools.items():
        for path in pool.iterdir():
            if path.name in allowed[name]:
                continue
            if path.name == 'cloud-init' and name == OTHER:
                fd = dev.root_directory(path)
                os.close(fd)
                dev.require(path.stat().st_dev == fs, 'Cloud-init directory filesystem differs')
                # No credential content reads; reject nested allocations and special files.
                for entry in path.iterdir():
                    dev.require(entry.name in {'user-data', 'meta-data', 'network-config'},
                                'Unknown cloud-init entry')
                    file_info(entry, fs, seen)
                continue
            pool_file(p, value, name, path, fs, seen)
    for name in GUESTS:
        path = disk_path(p, name)
        dev.require(name in records or (not path.exists() and str(path) not in value['files']),
                    'Existing unknown or partial app file; no overwrite')
    s = os.statvfs(p['pool_path'])
    budget = capacity(s.f_bavail * s.f_frsize, roots, apps)
    dev.require(s.f_favail >= 16, 'Insufficient free inodes')
    dev.require(budget['admitted'], 'Insufficient capacity including all remaining commitments')
    return budget, xmls


def prerequisites(p, value):
    expected = {'domain:' + n for n in GUESTS} | {'pool:' + p['name'], 'network:' + p['name']}
    dev.require(value.get('ready') is True and set(value.get('resources', {})) == expected
                and value.get('boot_verified') == GUESTS, 'Complete ready three-guest journal required')
    dev.verify_files(value)
    dev.verify_resources(p, value, allow_running=True)
    dev.verify_guard(value)
    dev.require(all(dev.resource_info(p, 'domain', n).get('State') == 'running' for n in GUESTS),
                'All three DEV guests must remain running')


def apply(p, name):
    with dev.locked_journal(p) as journal:
        prerequisites(p, journal.value)
        health.cluster_ready(p, name)
        boots = {n: health.guest_state(p, n)['boot'] for n in GUESTS}
        budget, xmls = inventory(p, journal.value)
        if name in completed_records(p, journal.value):
            return {'guest': name, 'already_verified': True, 'capacity': budget}
        persistent, live = xmls[name]
        requested = disk_xml(live, p, name)
        # Persistent and live must independently accept precisely this new device.
        candidate = domain(persistent, p, name)
        dev.require(disk_xml(persistent, p, name) == requested,
                    'Live and persistent free controller slots differ')
        candidate.find('devices').append(ET.fromstring(requested))
        verify_addition(persistent, ET.tostring(candidate, encoding='unicode'), p, name)
        path = disk_path(p, name)
        pool = dev.root_directory(p['pool_path'])
        try:
            prerequisites(p, journal.value)
            budget, fresh = inventory(p, journal.value)
            dev.require(fresh == xmls, 'Inventory changed during readiness checks')
            journal.intent({'operation': 'dev-app-storage', 'guest': name, 'path': str(path),
                            'serial': serial(p, name), 'persistent_before': persistent, 'live_before': live})
            dev.exclusive(pool, path.name, b'')
            reserved = dev.inode(path)
            preallocate(path)
            dev.require(dev.inode(path) == reserved, 'Allocated file replaced')
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pool)
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(pool)
            image_info(path, 64 * GIB)
            dev.require(path.stat().st_blocks * 512 >= 64 * GIB, 'Full preallocation not verified')
            dev.record_file(journal, path, mutable=True)
            journal.save()
            filename = name + '-apps-attach.xml'
            dev.exclusive(journal.fd, filename, requested)
            dev.record_file(journal, dev.STATE / filename)
            journal.save()
            dev.verify_guard(journal.value)
            dev.require(dev.resource_xml(p, 'domain', name) == persistent
                        and virsh(p, 'dumpxml', name) == live, 'Domain changed before hotplug')
            virsh(p, 'attach-device', dev.identity(p, 'domain', name), str(dev.STATE / filename),
                  '--live', '--config')
            actual = dev.resource_xml(p, 'domain', name)
            actual_live = virsh(p, 'dumpxml', name)
            verify_addition(persistent, actual, p, name)
            verify_addition(live, actual_live, p, name)
            for n in GUESTS + [OTHER]:
                if n != name:
                    dev.require((dev.resource_xml(p, 'domain', n), virsh(p, 'dumpxml', n)) == xmls[n],
                                'Unrelated domain changed')
            dev.require({n: health.guest_state(p, n)['boot'] for n in GUESTS} == boots,
                        'DEV boot identity changed during hotplug')
            health.cluster_ready(p, name)
            journal.value['resources']['domain:' + name]['definition_sha256'] = dev.definition_hash(actual)
            journal.value.setdefault('app_storage', {})[name] = {
                'completed': True, 'path': str(path), 'serial': serial(p, name), 'size_bytes': 64 * GIB}
            prerequisites(p, journal.value)
            inventory(p, journal.value)
            journal.done()
        finally:
            os.close(pool)
        return {'guest': name, 'path': str(path), 'serial': serial(p, name),
                'live_and_persistent_verified': True, 'reboot_performed': False,
                'guest_formatted': False, 'ha_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'apply'])
    parser.add_argument('--guest', choices=GUESTS)
    parser.add_argument('--probe-readiness', action='store_true', help='Permit bounded pinned SSH read-only health probes')
    args = parser.parse_args()
    p = dev.profile()
    dev.require(p['vms'] == GUESTS and p['disk_gib'] == 40 and p['connection'] == 'qemu:///system',
                'Fixed DEV profile required')
    if args.command == 'plan':
        result = {'read_only': True, 'capacity_verified': False, 'ha_verified': False,
                  'requirements': 'Local root; exclusive storage/libvirt maintenance; ready cluster; existing guard and pinned SSH sudo access',
                  'disks': [{'guest': n, 'uuid': dev.identity(p, 'domain', n), 'path': str(disk_path(p, n)),
                             'serial': serial(p, n), 'size_bytes': 64 * GIB, 'target': 'vdb'}
                            for n in ([args.guest] if args.guest else GUESTS)]}
    else:
        dev.require(args.guest and args.probe_readiness, 'Apply requires --guest and --probe-readiness')
        result = apply(p, args.guest)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps(dev.failure_report(error)))
        raise SystemExit(1)
