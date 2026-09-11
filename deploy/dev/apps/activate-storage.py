#!/usr/bin/env python3
"""Activate an existing DEV mount guard and prepare fixed app directories.

No format, unmount, reboot, service restart or Kubernetes mutation. Run during
an exclusive systemd/storage maintenance window: daemon-reload is manager-wide.
Loaded dependency checks do not substitute for a storage-loss recovery test.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import sys

import storage_plan

spec = importlib.util.spec_from_file_location('mount_preparation', Path(__file__).with_name('prepare-storage.py'))
mount = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mount)
require = mount.require


def properties(unit, *names):
    raw = mount.run('systemctl', 'show', unit, '--property=' + ','.join(names))
    result = dict(line.split('=', 1) for line in raw.splitlines())
    require(set(result) == set(names))
    return result


def process_state():
    state = properties('kubelet.service', 'MainPID', 'InvocationID', 'ActiveState')
    require(state['ActiveState'] == 'active' and state['MainPID'].isdigit()
            and int(state['MainPID']) > 0 and bool(state['InvocationID']))
    return state


def verify_guard(name):
    state = properties('kubelet.service', 'Requires', 'BindsTo', 'After', 'DropInPaths', 'NeedDaemonReload')
    require(all(name in shlex.split(state[key]) for key in ('Requires', 'BindsTo', 'After'))
            and str(mount.DROPIN) in shlex.split(state['DropInPaths'])
            and state['NeedDaemonReload'] == 'no')
    require(properties(name, 'ActiveState')['ActiveState'] == 'active')


def expected_directories(who):
    return [{'name': directory, 'uid': uid, 'gid': gid, 'capacity': capacity}
            for host, _, _, directory, capacity, uid, gid in storage_plan.volumes()
            if host == who['host']]


def directory_record(entry):
    path = mount.MOUNT / entry['name']
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == entry['uid']
            and info.st_gid == entry['gid'] and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_dev == mount.MOUNT.stat().st_dev)
    return {**entry, 'device': info.st_dev, 'inode': info.st_ino}


def directories(who, fs_uuid, create):
    entries = expected_directories(who)
    require(len(entries) == 6 and len({e['name'] for e in entries}) == 6)
    plan_hash = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    intent = {'identity': who, 'fs_uuid': fs_uuid, 'plan_sha256': plan_hash}
    intent_file = mount.STATE / 'app-directories-intent.json'
    complete_file = mount.STATE / 'app-directories-complete.json'
    if mount.exists(intent_file) or mount.exists(complete_file):
        require(mount.exists(intent_file) and mount.exists(complete_file))
        require(json.loads(mount.read_private(intent_file)) == intent)
        require(json.loads(mount.read_private(complete_file)) ==
                {**intent, 'directories': [directory_record(e) for e in entries]})
        return False
    require(create)
    require(all(not mount.exists(mount.MOUNT / e['name']) for e in entries))
    require({p.name for p in mount.MOUNT.iterdir()} <= {'lost+found'})
    available = os.statvfs(mount.MOUNT)
    require(available.f_bavail * available.f_frsize >= 40 * 1024**3
            and available.f_favail >= 10000)
    mount.write_new(intent_file, json.dumps(intent, sort_keys=True) + '\n')
    for entry in entries:
        path = mount.MOUNT / entry['name']
        path.mkdir(mode=0o700)
        os.chown(path, entry['uid'], entry['gid'], follow_symlinks=False)
        mount.sync_dir(path)
    mount.sync_dir(mount.MOUNT)
    record = {**intent, 'directories': [directory_record(e) for e in entries]}
    mount.write_new(complete_file, json.dumps(record, sort_keys=True) + '\n')
    return True


def activate(mode):
    who = mount.identity()
    require(storage_plan.CLUSTER_UID == mount.K8S_UID and storage_plan.MOUNT == str(mount.MOUNT))
    mount.root_path(mount.STATE, directory=True)
    fd = os.open(mount.STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(mount.exists(mount.STATE / 'complete.json'))
        mount.transaction(who)
        fs_uuid = json.loads(mount.read_private(mount.STATE / 'complete.json'))['fs_uuid']
        name, _, _ = mount.unit_files(fs_uuid)
        before = process_state()
        if mode == 'activate':
            mount.run('systemctl', 'daemon-reload')
        verify_guard(name)
        require(process_state() == before)
        mount.verify_mount(mount.inspect(who['serial'], fresh=False), fs_uuid)
        created = directories(who, fs_uuid, create=mode == 'activate')
        mount.verify_mount(mount.inspect(who['serial'], fresh=False), fs_uuid)
        verify_guard(name)
        require(process_state() == before)
        mount.verify_cluster()
        return {'host': who['host'], 'filesystem_uuid': fs_uuid, 'directories_created': created,
                'directory_count': 6, 'active_mount_dependency_verified': True,
                'kubelet_process_unchanged': True, 'quota_enforced': False,
                'storage_loss_tested': False, 'kubernetes_applied': False}
    finally:
        os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['activate', 'verify'])
    args = parser.parse_args()
    try:
        print(json.dumps(activate(args.mode), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, mount.subprocess.SubprocessError):
        print('DEV storage activation stopped; preserve journals and inspect local state', file=sys.stderr)
        raise SystemExit(1)
