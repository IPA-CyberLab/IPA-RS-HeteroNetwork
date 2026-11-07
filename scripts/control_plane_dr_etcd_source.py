#!/usr/bin/env python3
"""Stream a verified local etcd snapshot without writing plaintext to disk."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import urllib.parse

from control_plane_dr import private_file


def mounts_for(path, text):
    target = str(Path(path).resolve())
    rows = []
    for order, line in enumerate(text.splitlines()):
        fields = line.split()
        if len(fields) < 4:
            continue
        mount = fields[1].replace('\\040', ' ').replace('\\011', '\t').replace('\\134', '\\')
        if target == mount or target.startswith(mount.rstrip('/') + '/'):
            rows.append((len(mount), order, fields[2], set(fields[3].split(','))))
    if not rows:
        raise ValueError('Cannot determine the snapshot temporary filesystem')
    # Multiple mounts may cover the same path. The last entry is the visible
    # one; trusting an obscured noswap mount could expose secrets to swap.
    return max(rows, key=lambda row: (row[0], row[1]))[2:]


def check_tmpfs(path, maximum, *, mounts=None):
    directory = Path(path)
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError('A private absolute temporary directory is required')
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('The snapshot temporary directory must be owner-only')
    mounts = Path('/proc/mounts').read_text() if mounts is None else mounts
    kind, options = mounts_for(directory, mounts)
    if kind != 'tmpfs':
        raise ValueError('etcd snapshots require tmpfs, never a plaintext disk file')
    # /proc/swaps inside a sandbox can omit host swap. Require the property on
    # the mount itself instead of inferring it from the process namespace.
    if 'noswap' not in options:
        raise ValueError('etcd snapshots require a noswap tmpfs')
    free = os.statvfs(directory).f_bavail * os.statvfs(directory).f_frsize
    if free < maximum + 8 * 1024**2:
        raise ValueError('Insufficient private memory for an etcd snapshot')


def read_config(path):
    config = json.loads(private_file(path).read_text())
    allowed = {'etcdctl', 'etcdutl', 'endpoint', 'ca', 'cert', 'key', 'tmp_dir', 'max_snapshot_bytes'}
    if not isinstance(config, dict) or set(config) != allowed:
        raise ValueError('Invalid etcd source configuration')
    for key in ('etcdctl', 'etcdutl'):
        binary = Path(config[key])
        info = binary.stat()
        parent = binary.parent.stat()
        if (not binary.is_absolute() or binary.is_symlink() or not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o022 or parent.st_uid != 0
                or parent.st_mode & 0o022 or not os.access(binary, os.X_OK)):
            raise ValueError('etcd tools must be root-owned and protected')
    endpoint = urllib.parse.urlsplit(config['endpoint'])
    try:
        address = ipaddress.ip_address(endpoint.hostname or '')
    except ValueError:
        raise ValueError('The etcd endpoint must be a loopback IP address') from None
    if (endpoint.scheme != 'https' or not address.is_loopback or endpoint.username or endpoint.password
            or endpoint.path not in ('', '/') or endpoint.query or endpoint.fragment or endpoint.port is None):
        raise ValueError('The etcd endpoint must use loopback HTTPS')
    for key in ('ca', 'cert'):
        file = Path(config[key])
        info = file.stat()
        if not file.is_absolute() or file.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('The etcd certificate must be root-owned and protected')
    private_file(config['key'])
    limit = config['max_snapshot_bytes']
    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= 4 * 1024**3:
        raise ValueError('A bounded etcd snapshot size is required')
    check_tmpfs(config['tmp_dir'], limit)
    return config


class Source:
    def __init__(self, config):
        self.config = config
        self.env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'ETCDCTL_API': '3'}
        self.client = [config['etcdctl'], '--endpoints', config['endpoint'], '--cacert', config['ca'],
                       '--cert', config['cert'], '--key', config['key']]

    def status(self):
        result = subprocess.run(self.client + ['endpoint', 'status', '-w', 'json'], env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=30, check=False)
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise RuntimeError('etcd endpoint health could not be verified')
        try:
            rows = json.loads(result.stdout)
            status = rows[0]['Status']
            header = status['header']
            cluster = header['cluster_id']
            revision = header['revision']
            size = status['dbSize']
            leader = status['leader']
            version = status['version']
            if (len(rows) != 1 or not all(isinstance(x, int) and x > 0 for x in (cluster, revision, size, leader))
                    or size > self.config['max_snapshot_bytes'] or not isinstance(version, str)):
                raise ValueError()
        except (ValueError, TypeError, KeyError, IndexError):
            raise RuntimeError('etcd endpoint status is invalid or exceeds the snapshot budget') from None
        match = re.search(r'\b(\d+)\.(\d+)\.', version)
        if not match:
            raise RuntimeError('etcd server version is invalid')
        major_minor = match.groups()
        for tool in ('etcdctl', 'etcdutl'):
            result = subprocess.run([self.config[tool], 'version'], env=self.env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
            match = re.search(rb'\b(\d+)\.(\d+)\.', result.stdout)
            if result.returncode or not match or tuple(part.decode() for part in match.groups()) != major_minor:
                raise RuntimeError('etcd server and snapshot tools have incompatible versions')
        return cluster, revision

    def backup(self):
        check_tmpfs(self.config['tmp_dir'], self.config['max_snapshot_bytes'])
        before_cluster, before_revision = self.status()
        previous_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix='etcd-', dir=self.config['tmp_dir']) as temporary:
                snapshot = Path(temporary) / 'snapshot.db'
                maximum = self.config['max_snapshot_bytes']
                def file_limit():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
                saved = subprocess.run(self.client + ['snapshot', 'save', str(snapshot)], env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=600, check=False,
                                       preexec_fn=file_limit)
                if saved.returncode or not snapshot.is_file() or not 0 < snapshot.stat().st_size <= maximum:
                    raise RuntimeError('etcd snapshot failed or exceeded its size budget')
                inspected = subprocess.run([self.config['etcdutl'], 'snapshot', 'status', str(snapshot), '-w', 'json'],
                                           env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, timeout=60, check=False)
                if inspected.returncode or len(inspected.stdout) > 1024 * 1024:
                    raise RuntimeError('etcd snapshot metadata could not be verified')
                try:
                    revision = json.loads(inspected.stdout)['revision']
                    if not isinstance(revision, int) or revision < before_revision:
                        raise ValueError()
                except (ValueError, TypeError, KeyError):
                    raise RuntimeError('etcd snapshot revision is invalid') from None
                after_cluster, after_revision = self.status()
                if after_cluster != before_cluster or after_revision < revision:
                    raise RuntimeError('etcd cluster identity or revision changed during backup')
                with snapshot.open('rb') as source:
                    shutil.copyfileobj(source, sys.stdout.buffer, 1024 * 1024)
                sys.stdout.buffer.flush()
        finally:
            os.umask(previous_umask)


def main():
    # Allow TemporaryDirectory to remove an unencrypted snapshot when the
    # enclosing backup times out or is cancelled.
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    Source(read_config(args.config)).backup()


if __name__ == '__main__':
    main()
