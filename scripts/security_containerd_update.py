#!/usr/bin/env python3
"""Patch the containerd daemon while preserving running shim/task identities.

This is a daemon replacement, not a claimed cross-version Sentry migration.
Already running tasks keep their exact IDs and PIDs. Any failed acceptance
restores the previous binaries and restarts only the daemon, never the shims.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request

from security_inventory import atomic_json, utc_now


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, 'operation failed: ' + args[0])
    return result.stdout


def tasks():
    output = run(['ctr', '--namespace', 'k8s.io', 'tasks', 'list'])
    result = {}
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[2] == 'RUNNING':
            require(re.fullmatch(r'[A-Za-z0-9._-]+', fields[0]) and fields[1].isdigit(), 'invalid task identity')
            result[fields[0]] = int(fields[1])
    return result


def preserved(before, after):
    return all(after.get(identifier) == pid for identifier, pid in before.items())


def trusted(path):
    for item in [path, *path.parents]:
        info = item.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022 == 0, 'untrusted updater path')


def install(args):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64', 'root on amd64 is required')
    policy_path = Path(args.lock).resolve()
    trusted(policy_path)
    lock = json.loads(policy_path.read_text())
    require(re.fullmatch(r'2\.2\.\d+', lock['version']), 'only the declared 2.2 runtime line is allowed')
    require(set(lock['binaries']) == {'containerd', 'containerd-shim-runc-v2', 'ctr'}, 'unexpected archive binary list')
    require(lock['url'] == 'https://github.com/containerd/containerd/releases/download/v' + lock['version'] + '/containerd-' + lock['version'] + '-linux-amd64.tar.gz', 'unexpected upstream artifact')
    require(run(['systemctl', 'show', 'containerd.service', '-p', 'KillMode', '--value']).strip() == 'process', 'containerd restart must preserve child shims')
    pid = int(run(['systemctl', 'show', 'containerd.service', '-p', 'MainPID', '--value']).strip())
    require(pid > 0, 'containerd is not running')
    installed = Path(os.readlink('/proc/' + str(pid) + '/exe').removesuffix(' (deleted)'))
    require(installed in (Path('/usr/bin/containerd'), Path('/usr/local/bin/containerd')), 'unexpected daemon binary path')
    before_version = run([str(installed), '--version']).strip()
    require(re.search(r'\b(?:v)?2\.[12]\.\d+\b', before_version), 'unsupported current runtime version')
    require(not re.search(r'enable_experimental_restore_via_create\s*=\s*true', run([str(installed), 'config', 'dump'])), 'unsafe CRI checkpoint restore is enabled')
    before = tasks()
    require(before, 'no running tasks available for preservation verification')
    root = Path(args.output).parent
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    snapshot = {'node': Path('/etc/hostname').read_text().strip(), 'started_at': utc_now(), 'before_version': before_version, 'before_tasks': before, 'target_version': lock['version']}
    atomic_json(root / 'containerd-before.json', snapshot)
    changed = hashlib.sha256(Path('/proc/' + str(pid) + '/exe').read_bytes()).hexdigest() != lock['binaries']['containerd'] or hashlib.sha256(installed.read_bytes()).hexdigest() != lock['binaries']['containerd']
    if not changed:
        atomic_json(args.output, {**snapshot, 'status': 'verified', 'changed': False, 'running_tasks_preserved': len(before), 'verified_at': utc_now()})
        return
    with tempfile.TemporaryDirectory(prefix='containerd-patch-', dir=root) as temporary:
        stage = Path(temporary)
        archive_path = stage / 'containerd.tar.gz'
        with urllib.request.urlopen(lock['url'], timeout=120) as response:
            archive = response.read(100 * 1024 * 1024)
        require(hashlib.sha256(archive).hexdigest() == lock['archive_sha256'], 'upstream archive checksum mismatch')
        archive_path.write_bytes(archive)
        with tarfile.open(archive_path) as archive:
            for name, expected in lock['binaries'].items():
                member = archive.getmember('bin/' + name)
                require(member.isfile(), 'archive contains unexpected link')
                content = archive.extractfile(member).read()
                require(hashlib.sha256(content).hexdigest() == expected, 'binary checksum mismatch')
                (stage / name).write_bytes(content)
                (stage / name).chmod(0o755)
        destinations = {name: installed.parent / name for name in lock['binaries']}
        backup = stage / 'backup'
        backup.mkdir(mode=0o700)
        for name, destination in destinations.items():
            require(destination.is_file() and not destination.is_symlink(), 'installed runtime binary is missing or a symlink')
            shutil.copy2(destination, backup / name)
        try:
            for name, destination in destinations.items():
                temporary_destination = destination.with_name('.' + destination.name + '.security-new')
                shutil.copy2(stage / name, temporary_destination)
                os.chown(temporary_destination, 0, 0)
                os.replace(temporary_destination, destination)
            run(['systemctl', 'restart', 'containerd.service'], timeout=90)
            deadline = time.monotonic() + 90
            while True:
                try:
                    after = tasks()
                    require(preserved(before, after), 'running task ID/PID changed')
                    require('2.2.' in run([str(installed), '--version']), 'runtime did not start')
                    info = json.loads(run(['crictl', '--runtime-endpoint=unix:///run/containerd/containerd.sock', 'info']))
                    conditions = {c['type']: c['status'] for c in info['status']['conditions']}
                    require(conditions.get('RuntimeReady') is True and conditions.get('NetworkReady') is True, 'CRI readiness failed')
                    break
                except (RuntimeError, ValueError, subprocess.TimeoutExpired):
                    require(time.monotonic() < deadline, 'post-update runtime acceptance timed out')
                    time.sleep(2)
            version = run([str(installed), '--version']).strip()
            require(lock['version'] in version, 'running version does not match the verified artifact')
            running_pid = int(run(['systemctl', 'show', 'containerd.service', '-p', 'MainPID', '--value']).strip())
            require(hashlib.sha256(Path('/proc/' + str(running_pid) + '/exe').read_bytes()).hexdigest() == lock['binaries']['containerd'], 'active daemon differs from the verified artifact')
            atomic_json(args.output, {**snapshot, 'status': 'verified', 'changed': True, 'after_version': version, 'after_tasks': after, 'running_tasks_preserved': len(before), 'verified_at': utc_now(), 'fixed_advisories': lock['fixed_advisories']})
            print(json.dumps({'node': snapshot['node'], 'status': 'verified', 'version': lock['version'], 'running_tasks_preserved': len(before)}))
        except BaseException:
            for name, destination in destinations.items():
                temporary_destination = destination.with_name('.' + destination.name + '.security-rollback')
                shutil.copy2(backup / name, temporary_destination)
                os.replace(temporary_destination, destination)
            run(['systemctl', 'restart', 'containerd.service'], timeout=90)
            atomic_json(args.output, {**snapshot, 'status': 'rolled_back', 'verified_at': utc_now(), 'tasks_preserved_after_rollback': preserved(before, tasks())})
            raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lock', default='/opt/heteronetwork/security/containerd-lock.json')
    p.add_argument('--output', default='/var/lib/heteronetwork-security/containerd-update.json')
    a = p.parse_args()
    fd = os.open('/run/lock/heteronetwork-containerd-security.lock', os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        install(a)
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
