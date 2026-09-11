#!/usr/bin/env python3
"""Enroll only this DEV guest's prepared app filesystem, without formatting."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time

PREPARE = Path('/opt/heteronetwork-dev-disk-4bcac59d/prepare.py')
PREPARE_SHA = '4bcac59dbfb3a790d25832f64dc67598d6e942e4ff6f359f87db5b7a5e189b07'
NS = 'longhorn-system'
KEY = 'dev-app-filesystem'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or hashlib.sha256(PREPARE.read_bytes()).hexdigest() != PREPARE_SHA:
        raise ValueError('Unreviewed disk preparer')
    disk = load('disk_prepare', PREPARE)
    require = disk.require
    require(hashlib.sha256(disk.GUARD.read_bytes()).hexdigest() == disk.GUARD_SHA)
    helper = load('gvisor_guard', disk.GUARD)
    helper.trusted(PREPARE, 32768)
    name = helper.guard()
    s = os.statvfs(disk.MOUNT)
    disk.validate_mount(name, json.loads(helper.run(['findmnt', '-J', '-T', str(disk.DIRECTORY),
                        '-o', 'TARGET,SOURCE,UUID,FSTYPE,OPTIONS']))['filesystems'],
                        s.f_blocks * s.f_frsize, s.f_bavail * s.f_frsize)
    require(disk.DIRECTORY.is_dir() and not disk.DIRECTORY.is_symlink()
            and disk.DIRECTORY.stat().st_uid == 0 and disk.DIRECTORY.stat().st_mode & 0o777 == 0o700)
    require(all(disk.state(unit, 'ActiveState') == 'inactive' and disk.state(unit, 'UnitFileState') == 'disabled'
                for unit in ('multipathd.service', 'multipathd.socket')))

    def get(kind, name):
        return json.loads(helper.run([*helper.KUBE, 'get', kind, name, '-n', NS, '-o', 'json']))

    def patch(kind, actual, updates):
        tests = [{'op': 'test', 'path': '/metadata/' + field, 'value': actual['metadata'][field]}
                 for field in ('uid', 'resourceVersion')]
        return helper.run([*helper.KUBE, 'patch', kind, actual['metadata']['name'], '-n', NS,
                           '--type=json', '-p', json.dumps(tests + updates)])

    for key, value in [('storage-over-provisioning-percentage', '100'),
                       ('storage-minimal-available-percentage', '25'),
                       ('create-default-disk-labeled-nodes', 'true')]:
        require(get('settings.longhorn.io', key)['value'] == value)
    setting = get('settings.longhorn.io', 'allow-volume-creation-with-degraded-availability')
    require(setting['value'] in ('true', 'false'))
    desired = {'path': str(disk.DIRECTORY), 'allowScheduling': True,
               'storageReserved': disk.RESERVED, 'tags': [], 'evictionRequested': False,
               'diskType': 'filesystem', 'diskDriver': ''}
    actual = get('nodes.longhorn.io', name)
    disks = actual['spec'].get('disks', {})
    require(not actual['metadata'].get('deletionTimestamp') and actual['spec']['allowScheduling']
            and (disks == {} or disks == {KEY: desired}))
    if args.apply:
        if setting['value'] != 'false':
            patch('settings.longhorn.io', setting, [{'op': 'replace', 'path': '/value', 'value': 'false'}])
        if not disks:
            patch('nodes.longhorn.io', actual, [{'op': 'add', 'path': '/spec/disks', 'value': {KEY: desired}}])
        deadline = time.monotonic() + 180
        while True:
            actual = get('nodes.longhorn.io', name)
            require(actual['spec']['disks'] == {KEY: desired})
            status = actual['status'].get('diskStatus', {}).get(KEY, {})
            conditions = {c['type']: c['status'] for c in status.get('conditions', [])}
            if conditions.get('Ready') == 'True' and conditions.get('Schedulable') == 'True':
                require(status.get('diskUUID') and status['storageMaximum'] == s.f_blocks * s.f_frsize)
                break
            if time.monotonic() >= deadline:
                raise ValueError('Disk did not become ready: ' + json.dumps(status))
            time.sleep(3)
        helper.guard()
    print(json.dumps({'node': name, 'applied': args.apply, 'disk': desired,
                      'disk_ready': args.apply, 'rwx_verified': False, 'ha_verified': False}), flush=True)


if __name__ == '__main__':
    main()
