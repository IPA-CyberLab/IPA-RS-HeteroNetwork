#!/usr/bin/python3 -I
"""Forced-command, read-only runtime acceptance snapshot. Takes no arguments.

No process arguments, environment, descriptors' contents or remote addresses
are exported. The caller can observe IDs/PIDs, executable hashes and inbound
connection counts, but cannot select a command or a file to read.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


CACHE_ROOT = Path('/var/lib/heteronetwork-security/runtime-observer')


def cached_hashes():
    if not CACHE_ROOT.exists():
        CACHE_ROOT.mkdir(mode=0o700)
    info = CACHE_ROOT.lstat()
    if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError('runtime observer cache is untrusted')
    path = CACHE_ROOT / 'hashes.json'
    if not path.exists():
        return {}
    info = path.lstat()
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 2 * 1024 * 1024:
        raise RuntimeError('runtime observer hash cache is untrusted')
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (ValueError, OSError):
        return {}


def save_hashes(hashes):
    # Each observation retains only currently running executable identities.
    # PID and inode reuse cannot reuse a hash: size, ctime and mtime must also
    # match. Linux denies writes to the executable of a running process.
    temporary = CACHE_ROOT / ('hashes.' + str(os.getpid()) + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(hashes, stream, separators=(',', ':'))
        os.replace(temporary, CACHE_ROOT / 'hashes.json')
    finally:
        temporary.unlink(missing_ok=True)


def tcp_connections(pid, namespaces=None):
    sockets = set()
    try:
        for descriptor in (Path('/proc') / str(pid) / 'fd').iterdir():
            try:
                link = os.readlink(descriptor)
                if link.startswith('socket:['):
                    sockets.add(link[8:-1])
            except OSError:
                pass
        if not sockets:
            return {'status': 'complete', 'inbound_connections': 0}
        # Host-network containers share a large TCP table. Parse it once per
        # network namespace during this observation, then select this PID's
        # sockets. No address or socket content leaves the observer.
        namespaces = namespaces if namespaces is not None else {}
        namespace = (Path('/proc') / str(pid) / 'ns' / 'net').stat().st_ino
        if namespace not in namespaces:
            rows = []
            for table in ['tcp', 'tcp6']:
                for line in (Path('/proc') / str(pid) / 'net' / table).read_text().splitlines()[1:]:
                    fields = line.split()
                    if len(fields) > 9:
                        rows.append((fields[9], int(fields[1].rsplit(':', 1)[1], 16), fields[3]))
            namespaces[namespace] = rows
        rows = [(port, state) for inode, port, state in namespaces[namespace] if inode in sockets]
        listeners = {port for port, state in rows if state == '0A'}
        return {'status': 'complete', 'inbound_connections': sum(state == '01' and port in listeners for port, state in rows)}
    except OSError:
        return {'status': 'unverified'}


def collect(challenge=None):
    ctr = next((p for p in ['/usr/bin/ctr', '/usr/local/bin/ctr'] if Path(p).is_file()), None)
    if not ctr:
        raise RuntimeError('containerd task observer unavailable')
    output = subprocess.check_output([ctr, '--namespace', 'k8s.io', 'tasks', 'list'], text=True, timeout=20)
    tasks, hashes, namespaces = {}, {}, {}
    previous = cached_hashes()
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 3 or fields[2] != 'RUNNING' or not fields[1].isdigit():
            continue
        identifier, pid = fields[0], int(fields[1])
        executable = Path('/proc') / str(pid) / 'exe'
        try:
            info = executable.stat()
            inode = ':'.join(str(v) for v in (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns, info.st_mtime_ns))
            if inode not in hashes:
                cached = previous.get(inode, '')
                if isinstance(cached, str) and re.fullmatch(r'[0-9a-f]{64}', cached):
                    hashes[inode] = cached
                else:
                    digest = hashlib.sha256()
                    with executable.open('rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(chunk)
                    hashes[inode] = digest.hexdigest()
            tasks[identifier] = {'pid': pid, 'exe_sha256': hashes[inode], 'tcp': tcp_connections(pid, namespaces)}
        except OSError:
            tasks[identifier] = {'pid': pid, 'status': 'unverified'}
    save_hashes(hashes)
    return {'schema_version': 1, 'challenge': challenge, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'host': os.uname().nodename, 'tasks': tasks}


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit('root with no arguments required')
    try:
        challenge = sys.stdin.readline(100).strip()
        if challenge and not re.fullmatch(r'[0-9a-f]{64}', challenge):
            raise RuntimeError('invalid observation challenge')
        print(json.dumps(collect(challenge or None), separators=(',', ':')))
    except (RuntimeError, OSError, subprocess.SubprocessError):
        raise SystemExit('runtime snapshot failed')
