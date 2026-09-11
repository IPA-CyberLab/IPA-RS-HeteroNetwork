#!/usr/bin/env python3
"""Prepare one existing DEV filesystem for explicit Longhorn enrollment."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

GUARD = Path('/opt/heteronetwork-dev-gvisor-a6cfcb7c/install-gvisor.py')
GUARD_SHA = 'e9b99490b58d8a396667bdf2731b466b49cc88f9133d56754d75b3fe557535c0'
MOUNT = Path('/var/lib/heteronetwork-dev-app-storage')
DISKS = {
    'hetero-dev-1': '17138c6e-6b4d-4751-be77-d543492b0b76',
    'hetero-dev-2': 'e57ca4f8-930c-4c23-9830-951a563fef09',
    'hetero-dev-3': '21469bc7-98b6-420e-9850-67582114c05f',
}
RESERVED = 43 * 1024**3
DIRECTORY = MOUNT / 'longhorn'


def require(value):
    if not value:
        raise ValueError('DEV Longhorn disk prerequisite failed')


def validate_mount(name, mounts, total, available):
    require(name in DISKS and len(mounts) == 1)
    m = mounts[0]
    require(m['target'] == str(MOUNT) and m['uuid'] == DISKS[name]
            and m['source'] == '/dev/vdb' and m['fstype'] == 'ext4'
            and {'rw', 'nodev', 'nosuid'}.issubset(m['options'].split(',')))
    require(60 * 1024**3 <= total <= 64 * 1024**3 and available >= RESERVED + 2 * 1024**3)


def no_multipath(blocks, uuids):
    for b in blocks:
        require(b.get('type') != 'mpath')
        no_multipath(b.get('children', []), [])
    require(all(not u.startswith('mpath-') for u in uuids))


def state(unit, property):
    return subprocess.run(['systemctl', 'show', unit, '-p', property, '--value'],
                          check=True, capture_output=True, text=True, timeout=20).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0 and hashlib.sha256(GUARD.read_bytes()).hexdigest() == GUARD_SHA)
    spec = importlib.util.spec_from_file_location('gvisor_guard', GUARD)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.trusted(GUARD, 32768)
    fd = os.open('/run/lock/heteronetwork-dev-longhorn-disk.lock',
                 os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        name = helper.guard()
        mounts = json.loads(helper.run(['findmnt', '-J', '-T', str(MOUNT),
                             '-o', 'TARGET,SOURCE,UUID,FSTYPE,OPTIONS']))['filesystems']
        s = os.statvfs(MOUNT)
        validate_mount(name, mounts, s.f_blocks * s.f_frsize, s.f_bavail * s.f_frsize)
        # Never disable a service that owns an existing multipath mapping.
        no_multipath(json.loads(helper.run(['lsblk', '-J', '-o', 'NAME,TYPE']))['blockdevices'],
                     [p.read_text().strip() for p in Path('/sys/block').glob('dm-*/dm/uuid')])
        require(state('iscsid', 'ActiveState') == 'active')
        before_pid = state('containerd', 'MainPID')
        before = helper.running()
        if DIRECTORY.exists() or DIRECTORY.is_symlink():
            st = DIRECTORY.lstat()
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700
                    and st.st_dev == MOUNT.stat().st_dev)
        if args.apply:
            # These DEV guests use virtio disks, not multipath storage.
            subprocess.run(['systemctl', 'disable', '--now', 'multipathd.service', 'multipathd.socket'],
                           check=True, timeout=60)
            require(all(state(unit, 'ActiveState') == 'inactive' and state(unit, 'UnitFileState') == 'disabled'
                        for unit in ('multipathd.service', 'multipathd.socket')))
            if not DIRECTORY.exists():
                DIRECTORY.mkdir(mode=0o700)
            require(before_pid == state('containerd', 'MainPID') and before.issubset(helper.running()))
            helper.guard()
        print(json.dumps({'node': name, 'applied': args.apply, 'path': str(DIRECTORY),
                          'filesystem_uuid': DISKS[name], 'storage_reserved_bytes': RESERVED,
                          'filesystem_bytes': s.f_blocks * s.f_frsize,
                          'existing_containers_preserved': len(before) if args.apply else None,
                          'disk_formatted': False, 'disk_enrolled': False,
                          'reservation_is_filesystem_quota': False}), flush=True)
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
