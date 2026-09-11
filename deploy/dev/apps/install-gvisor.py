#!/usr/bin/env python3
"""Install the pinned Flash runtime on one identified DEV guest, preserving tasks."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import tomllib

UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
NODES = {
    'hetero-dev-1': ('381d1ae16f555c59b738d8d01dd14c94', '10.251.0.1'),
    'hetero-dev-2': ('acc5151b6b245b63864372933dab97da', '10.251.0.2'),
    'hetero-dev-3': ('165a6e8acc3a56fdbf9bef8c90d6cf4d', '10.251.0.3'),
}
CONFIG = Path('/etc/containerd/config.toml')
DROPIN = Path('/etc/containerd/conf.d/50-heterocloud-flash-runsc.toml')
EXPECTED_DROPIN = 'version = 3\n\n[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc]\n  runtime_type = "io.containerd.runsc.v1"\n'
KUBE = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf']
CRI = ['crictl', '--runtime-endpoint=unix:///run/containerd/containerd.sock']


def require(condition):
    if not condition:
        raise ValueError('DEV gVisor installation prerequisite failed')


def run(command, timeout=40):
    return subprocess.check_output(command, timeout=timeout)


def trusted(path, limit):
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022 == 0)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit)
    return path.read_bytes()


def guard():
    require(os.geteuid() == 0)
    name = Path('/etc/hostname').read_text().strip()
    require(name in NODES and Path('/etc/machine-id').read_text().strip() == NODES[name][0])
    namespace = json.loads(run([*KUBE, 'get', 'namespace', 'kube-system', '-o', 'json']))
    require(namespace['metadata']['uid'] == UID)
    nodes = json.loads(run([*KUBE, 'get', 'nodes', '-o', 'json']))['items']
    require(len(nodes) == 3 and {n['metadata']['name'] for n in nodes} == set(NODES))
    for node in nodes:
        require([a['address'] for a in node['status']['addresses'] if a['type'] == 'InternalIP'] ==
                [NODES[node['metadata']['name']][1]]
                and any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status']['conditions']))
    require(run(['systemctl', 'show', 'containerd', '-p', 'KillMode', '--value']).strip() == b'process')
    require(run(['dpkg', '--print-architecture']).strip() == b'amd64')
    clusters = json.loads(run([*KUBE, 'get', 'clusters.postgresql.cnpg.io', '-A', '-o', 'json']))['items']
    require(len(clusters) == 4 and all(c['status'].get('readyInstances') == 3 for c in clusters))
    return name


def running():
    return {c['id'] for c in json.loads(run([*CRI, 'ps', '-o', 'json']))['containers']}


def main():
    fd = os.open('/run/lock/heteronetwork-dev-gvisor.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        install()
    finally:
        os.close(fd)


def install():
    name = guard()
    root = Path(__file__).resolve().parent
    lock = json.loads(trusted(root / 'gvisor-lock.json', 16384))
    require(lock['schema_version'] == 1 and lock['cluster_uid'] == UID
            and lock['version'] == '20260907.0')
    installer = root / 'install-gvisor.sh'
    require(hashlib.sha256(trusted(installer, 65536)).hexdigest() == lock['installer_sha256'])
    before = trusted(CONFIG, 65536)
    config = tomllib.loads(before.decode())
    require(config['version'] == 3 and config['imports'] == ['/etc/containerd/conf.d/*.toml'])
    runtime = config['plugins']['io.containerd.cri.v1.runtime']['containerd']
    require(runtime['default_runtime_name'] == 'runc'
            and runtime['runtimes']['runc']['options']['SystemdCgroup'] is True)
    if DROPIN.exists():
        require(trusted(DROPIN, 4096).decode() == EXPECTED_DROPIN)
    before_tasks = running()
    require(before_tasks)
    before_pid = run(['systemctl', 'show', 'containerd', '-p', 'MainPID', '--value']).strip()
    subprocess.run(['bash', str(installer)], env={**os.environ, 'GVISOR_VERSION': lock['version'], 'NEEDRESTART_MODE': 'l'},
                   check=True, timeout=900)
    require(trusted(CONFIG, 65536) == before and trusted(DROPIN, 4096).decode() == EXPECTED_DROPIN)
    require(run(['dpkg-query', '-W', '-f=${Version}', 'runsc']).decode() == lock['version'])
    deadline = time.monotonic() + 60
    while True:
        try:
            info = json.loads(run([*CRI, 'info']))
            conditions = {c['type']: c['status'] for c in info['status']['conditions']}
            if conditions.get('RuntimeReady') is True and conditions.get('NetworkReady') is True:
                break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        require(time.monotonic() < deadline)
        time.sleep(2)
    require(before_tasks.issubset(running()))
    guard()
    after_pid = run(['systemctl', 'show', 'containerd', '-p', 'MainPID', '--value']).strip()
    print(json.dumps({'node': name, 'version': lock['version'], 'existing_containers_preserved': len(before_tasks),
                      'containerd_restarted': before_pid != after_pid, 'runtime_smoke_verified': False}), flush=True)


if __name__ == '__main__':
    main()
