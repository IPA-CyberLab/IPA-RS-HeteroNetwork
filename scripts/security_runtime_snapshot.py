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
import subprocess
import sys


def tcp_connections(pid):
    sockets = set()
    try:
        for descriptor in (Path('/proc') / str(pid) / 'fd').iterdir():
            try:
                link = os.readlink(descriptor)
                if link.startswith('socket:['):
                    sockets.add(link[8:-1])
            except OSError:
                pass
        rows = []
        for table in ['tcp', 'tcp6']:
            for line in (Path('/proc') / str(pid) / 'net' / table).read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[9] in sockets:
                    rows.append((int(fields[1].rsplit(':', 1)[1], 16), fields[3]))
        listeners = {port for port, state in rows if state == '0A'}
        return {'status': 'complete', 'inbound_connections': sum(state == '01' and port in listeners for port, state in rows)}
    except OSError:
        return {'status': 'unverified'}


def collect():
    ctr = next((p for p in ['/usr/bin/ctr', '/usr/local/bin/ctr'] if Path(p).is_file()), None)
    if not ctr:
        raise RuntimeError('containerd task observer unavailable')
    output = subprocess.check_output([ctr, '--namespace', 'k8s.io', 'tasks', 'list'], text=True, timeout=20)
    tasks, hashes = {}, {}
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 3 or fields[2] != 'RUNNING' or not fields[1].isdigit():
            continue
        identifier, pid = fields[0], int(fields[1])
        executable = Path('/proc') / str(pid) / 'exe'
        try:
            info = executable.stat()
            inode = (info.st_dev, info.st_ino)
            if inode not in hashes:
                digest = hashlib.sha256()
                with executable.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                hashes[inode] = digest.hexdigest()
            tasks[identifier] = {'pid': pid, 'exe_sha256': hashes[inode], 'tcp': tcp_connections(pid)}
        except OSError:
            tasks[identifier] = {'pid': pid, 'status': 'unverified'}
    return {'schema_version': 1, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'host': os.uname().nodename, 'tasks': tasks}


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit('root with no arguments required')
    try:
        print(json.dumps(collect(), separators=(',', ':')))
    except (RuntimeError, OSError, subprocess.SubprocessError):
        raise SystemExit('runtime snapshot failed')
