#!/usr/bin/env python3
"""Install NFS/iSCSI client prerequisites on one verified DEV guest only."""
import argparse
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

GUARD = Path('/opt/heteronetwork-dev-gvisor-a6cfcb7c/install-gvisor.py')
GUARD_SHA = 'e9b99490b58d8a396667bdf2731b466b49cc88f9133d56754d75b3fe557535c0'
VERSION = '1:2.6.4-3ubuntu5.1'
MOUNT = '/var/lib/heteronetwork-dev-app-storage'
DISKS = {
    'hetero-dev-1': '17138c6e-6b4d-4751-be77-d543492b0b76',
    'hetero-dev-2': 'e57ca4f8-930c-4c23-9830-951a563fef09',
    'hetero-dev-3': '21469bc7-98b6-420e-9850-67582114c05f',
}
MODULE = Path('/etc/modules-load.d/heterocloud-flash-storage.conf')
CONTENT = b'iscsi_tcp\n'
SOURCES = Path('/etc/apt/sources.list.d/ubuntu.sources')


def source_stanzas(sections):
    require(len(sections) == 2)
    result = []
    for fields, host, suites in zip(sections, ('archive.ubuntu.com', 'security.ubuntu.com'),
                                    ('noble noble-updates noble-backports', 'noble-security')):
        require(set(fields) == {'Types', 'URIs', 'Suites', 'Components', 'Signed-By'}
                and fields['Types'] == 'deb' and fields['Suites'] == suites
                and fields['Components'] == 'main universe restricted multiverse'
                and fields['Signed-By'] == '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
                and fields['URIs'] in (f'http://{host}/ubuntu', f'https://{host}/ubuntu'))
        result.append({**fields, 'URIs': f'https://{host}/ubuntu'})
    return result


def parse_sources(raw):
    from aptsources._deb822 import File
    return [dict(section.tags) for section in File(io.StringIO(raw.decode())) if section.tags]


def https_sources(helper):
    raw = helper.trusted(SOURCES, 32768)
    sections = parse_sources(raw)
    desired = source_stanzas(sections)
    if desired == sections:
        return False
    data = ('\n\n'.join('\n'.join(f'{key}: {fields[key]}' for key in
            ('Types', 'URIs', 'Suites', 'Components', 'Signed-By')) for fields in desired) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.hetero-https-', dir=SOURCES.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        require(helper.trusted(SOURCES, 32768) == raw)
        os.replace(temporary, SOURCES)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def require(value):
    if not value:
        raise ValueError('DEV storage prerequisite check failed')


def installed_version():
    result = subprocess.run(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', 'nfs-common'],
                            capture_output=True, text=True, timeout=20)
    if result.returncode != 0 or not result.stdout.startswith('installed '):
        return None
    return result.stdout.removeprefix('installed ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0 and hashlib.sha256(GUARD.read_bytes()).hexdigest() == GUARD_SHA)
    spec = importlib.util.spec_from_file_location('gvisor_guard', GUARD)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.trusted(GUARD, 32768)
    lock = os.open('/run/lock/heteronetwork-dev-storage-prerequisites.lock',
                   os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        name = helper.guard()
        require(os.cpu_count() == 12)
        mount = json.loads(helper.run(['findmnt', '-J', '-T', MOUNT, '-o', 'TARGET,SOURCE,FSTYPE,UUID']))['filesystems']
        require(len(mount) == 1 and mount[0]['target'] == MOUNT
                and mount[0]['uuid'] == DISKS[name] and mount[0]['fstype'] == 'ext4')
        require(helper.run(['findmnt', '-no', 'PROPAGATION', '/']).strip() == b'shared')
        require(all(shutil.which(tool) for tool in ('iscsiadm', 'cryptsetup', 'dmsetup')))
        helper.run(['modinfo', '-F', 'filename', 'iscsi_tcp'])
        version = installed_version()
        require(version in (None, VERSION))
        if MODULE.exists() or MODULE.is_symlink():
            require(helper.trusted(MODULE, 4096) == CONTENT)
        if not args.apply:
            print(json.dumps({'node': name, 'admitted': True, 'nfs_version': version,
                              'runtime_changed': False}), flush=True)
            return
        before_tasks = helper.running()
        before_pid = helper.run(['systemctl', 'show', 'containerd', '-p', 'MainPID', '--value'])
        sources_changed = https_sources(helper)
        if version is None:
            # Honor an existing package policy; never replace an administrator's file.
            policy = Path('/usr/sbin/policy-rc.d')
            require(not policy.exists() and not policy.is_symlink())
            fd = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
            identity = os.fstat(fd)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(b'#!/bin/sh\nexit 101\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                subprocess.run(['apt-get', '-o', 'Acquire::ForceIPv4=true',
                                '-o', 'Acquire::http::Timeout=20', '-o', 'Acquire::Retries=1',
                                'install', '-y', '--no-remove', '--no-install-recommends',
                                'nfs-common=' + VERSION], check=True, timeout=360,
                               env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'})
            finally:
                actual = policy.lstat()
                require((actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino))
                policy.unlink()
        require(installed_version() == VERSION and shutil.which('mount.nfs'))
        if not MODULE.exists():
            fd = os.open(MODULE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(CONTENT)
                stream.flush()
                os.fsync(stream.fileno())
        subprocess.run(['modprobe', 'iscsi_tcp'], check=True, timeout=20)
        subprocess.run(['systemctl', 'enable', '--now', 'iscsid'], check=True, timeout=40)
        require(helper.run(['systemctl', 'is-active', 'iscsid']).strip() == b'active'
                and helper.run(['systemctl', 'is-enabled', 'iscsid']).strip() == b'enabled')
        require(helper.trusted(MODULE, 4096) == CONTENT and Path('/sys/module/iscsi_tcp').is_dir())
        require(helper.run(['systemctl', 'show', 'containerd', '-p', 'MainPID', '--value']) == before_pid
                and before_tasks.issubset(helper.running()))
        helper.guard()
        node = json.loads(helper.run([*helper.KUBE, 'get', 'node', name, '-o', 'json']))
        label = 'storage.heteronetwork.dev/clients-ready'
        actual = node['metadata'].get('labels', {}).get(label)
        require(actual in (None, 'true'))
        if actual is None:
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': node['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': node['metadata']['resourceVersion']},
                     {'op': 'add', 'path': '/metadata/labels/storage.heteronetwork.dev~1clients-ready', 'value': 'true'}]
            helper.run([*helper.KUBE, 'patch', 'node', name, '--type=json', '-p', json.dumps(patch)])
        print(json.dumps({'node': name, 'nfs_version': VERSION, 'nfs_installed_now': version is None,
                          'iscsi_enabled': True, 'existing_containers_preserved': len(before_tasks),
                          'containerd_restarted': False, 'disks_formatted': False,
                          'ubuntu_sources_changed_to_https': sources_changed,
                          'longhorn_installed': False}), flush=True)
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
