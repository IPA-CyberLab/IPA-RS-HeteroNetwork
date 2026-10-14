#!/usr/bin/env python3
"""Root-owned, read-only OS/runtime security inventory for a single host."""
import argparse
import glob
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import tempfile

from security_inventory import atomic_json, command_json, normalize_trivy, utc_now, validate_host_os


BINARIES = {
    'gvisor': ['/usr/bin/runsc', '/usr/local/bin/runsc'],
    'gvisor-shim': ['/usr/bin/containerd-shim-runsc-v1', '/usr/local/bin/containerd-shim-runsc-v1'],
    'containerd': ['/usr/bin/containerd', '/usr/local/bin/containerd'],
    'containerd-shim': ['/usr/bin/containerd-shim-runc-v2', '/usr/local/bin/containerd-shim-runc-v2'],
    'runc': ['/usr/bin/runc', '/usr/local/sbin/runc'],
    'kubelet': ['/usr/bin/kubelet'],
    'kubeadm': ['/usr/bin/kubeadm'],
    'etcd': ['/opt/heteronetwork/postgres-ha/etcd', '/usr/bin/etcd'],
    'postgres': ['/usr/lib/postgresql/17/bin/postgres', '/usr/lib/postgresql/18/bin/postgres'],
    'openssl': ['/usr/bin/openssl'],
    'haproxy': ['/usr/sbin/haproxy'],
    'nvidia-container-runtime': ['/usr/bin/nvidia-container-runtime'],
    'heteronetwork': ['/opt/heteronetwork/bin/ipars'],
    'heteronetwork-daemon': ['/opt/heteronetwork/bin/iparsd'],
    'trivy': ['/opt/heteronetwork/security/trivy'],
}


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def active_runtimes(installed):
    records = {}
    hashes = {}
    for path in glob.glob('/proc/[0-9]*/exe'):
        try:
            executable = os.readlink(path).removesuffix(' (deleted)')
            if Path(executable).name not in ('runsc', 'containerd', 'containerd-shim-runc-v2', 'containerd-shim-runsc-v1', 'kubelet'):
                continue
            # Hash the actual running executable, not just the new file at the
            # same path. Replacing runsc does not patch existing Sentry tasks.
            info = os.stat(path)
            inode = (info.st_dev, info.st_ino)
            if inode not in hashes:
                hashes[inode] = digest(path)
            sha = hashes[inode]
            key = (Path(executable).name, sha)
            record = records.setdefault(key, {'executable': key[0], 'sha256': sha, 'processes': 0, 'matches_installed_binary': sha in installed})
            record['processes'] += 1
        except (OSError, PermissionError):
            continue
    return list(records.values())


def collect(args):
    node = args.node_name or os.environ.get('HETERONETWORK_NODE_NAME') or Path('/etc/hostname').read_text().strip()
    source = 'node:' + node
    binaries = []
    for component, paths in BINARIES.items():
        path = next((p for p in paths if Path(p).is_file()), None)
        if not path:
            continue
        flags = ['version', '-o', 'short'] if component == 'kubeadm' else ['version'] if component == 'openssl' else ['-vv'] if component == 'haproxy' else ['--version']
        try:
            r = subprocess.run([path, *flags], capture_output=True, text=True, timeout=10)
            version = next((line for line in r.stdout.splitlines() if any(c.isdigit() for c in line)), '')[:200] if r.returncode == 0 else ''
            binaries.append({'component': component, 'path': path, 'version': version, 'sha256': digest(path)})
        except (OSError, subprocess.TimeoutExpired):
            binaries.append({'component': component, 'path': path, 'status': 'unknown'})
    gpu = None
    if shutil.which('nvidia-smi'):
        r = subprocess.run(['nvidia-smi', '--query-gpu=name,driver_version', '--format=csv,noheader'], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            gpu = r.stdout.strip().splitlines()
    if args.metadata_only:
        metadata = {p.lstrip('/'): Path(p).read_text() for p in ['/etc/os-release', '/etc/lsb-release', '/etc/debian_version', '/var/lib/dpkg/status'] if Path(p).is_file()}
        package_rows = subprocess.run(['dpkg-query', '--show', '--showformat=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'], capture_output=True, text=True, timeout=15)
        if package_rows.returncode:
            raise RuntimeError('installed package enumeration failed')
        family = 'ubuntu' if 'ID=ubuntu' in metadata.get('etc/os-release', '') else 'debian'
        packages = []
        for line in package_rows.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) == 3 and fields[2].startswith('ii'):
                packages.append({'name': fields[0], 'version': fields[1], 'ecosystem': family, 'source': source, 'purl': '', 'licenses': []})
        if not packages:
            raise RuntimeError('installed package enumeration was empty')
        binaries_packages = [{'name': b['component'], 'version': b.get('version') or 'unknown (' + b.get('sha256', '')[:12] + ')', 'ecosystem': 'native', 'source': source, 'purl': '', 'licenses': []} for b in binaries]
        binaries_packages.append({'name': 'linux-running-kernel', 'version': platform.release(), 'ecosystem': 'native', 'source': source, 'purl': '', 'licenses': []})
        patch_path = Path(args.output).parent / 'containerd-update.json'
        patch = json.loads(patch_path.read_text()) if patch_path.exists() else {}
        result = {'schema_version': 2, 'node': node, 'observed_at': utc_now(), 'status': 'complete', 'vulnerability_matching': 'central', 'package_metadata': metadata, 'kernel': platform.release(), 'binaries': binaries, 'active_runtimes': active_runtimes({b['sha256'] for b in binaries if 'sha256' in b}), 'gpu_driver': gpu, 'packages': packages + binaries_packages, 'findings': [], 'containerd_patch': {key: patch[key] for key in ['status', 'target_version', 'running_tasks_preserved', 'verified_at', 'fixed_advisories'] if key in patch}}
        atomic_json(args.output, result)
        account = pwd.getpwnam(args.inventory_user)
        os.chown(args.output, 0, account.pw_gid)
        os.chmod(args.output, 0o640)
        print(json.dumps({'node': node, 'metadata_collected': True, 'packages': len(packages), 'matching': 'central'}))
        return
    cmd = [args.trivy, '--cache-dir', args.cache, '--timeout', '10m', 'rootfs', '--scanners', 'vuln', '--format', 'json', '--list-all-pkgs', '--no-progress']
    try:
        # Scan package metadata and explicitly installed runtimes, not VM disks,
        # databases, Pod filesystems, secrets, logs or archived release trees.
        # This also bounds the I/O/memory cost on dedicated master machines.
        with tempfile.TemporaryDirectory(prefix='scan-', dir=Path(args.output).parent) as temporary:
            stage = Path(temporary)
            for source_path in ['/etc/os-release', '/etc/lsb-release', '/etc/debian_version', '/var/lib/dpkg/status']:
                if not Path(source_path).is_file():
                    continue
                target = stage / source_path.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, target)
            for binary in binaries:
                if binary.get('status') == 'unknown':
                    continue
                target = stage / binary['path'].lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(binary['path'], target)
                except OSError:
                    shutil.copyfile(binary['path'], target)
            report = command_json(cmd + [str(stage)], timeout=660)
        packages, findings = normalize_trivy(report, source)
        validate_host_os(report, packages)
        packages += [{'name': b['component'], 'version': b.get('version') or 'unknown (' + b.get('sha256', '')[:12] + ')', 'ecosystem': 'native', 'source': source, 'purl': '', 'licenses': []} for b in binaries]
        packages.append({'name': 'linux-running-kernel', 'version': platform.release(), 'ecosystem': 'native', 'source': source, 'purl': '', 'licenses': []})
        status, error = 'complete', None
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
        error = str(e) if isinstance(e, RuntimeError) else type(e).__name__
        status, packages, findings = 'error', [], []
    runtime_patch = None
    patch_path = Path(args.output).parent / 'containerd-update.json'
    if patch_path.is_file():
        patch = json.loads(patch_path.read_text())
        runtime_patch = {key: patch[key] for key in ['status', 'target_version', 'running_tasks_preserved', 'verified_at', 'fixed_advisories'] if key in patch}
    result = {'containerd_patch': runtime_patch, 'schema_version': 1, 'node': node, 'observed_at': utc_now(), 'status': status, 'error': error, 'kernel': platform.release(), 'binaries': binaries, 'active_runtimes': active_runtimes({b['sha256'] for b in binaries if 'sha256' in b}), 'gpu_driver': gpu, 'packages': packages, 'findings': findings}
    atomic_json(args.output, result)
    # The designated SSH inventory user can read package/version data. No
    # secrets, process arguments, Pod environment or checkpoints are exported.
    account = pwd.getpwnam(args.inventory_user)
    os.chown(args.output, 0, account.pw_gid)
    os.chmod(args.output, 0o640)
    print(json.dumps({'node': node, 'status': status, 'packages': len(packages), 'findings': len(findings)}))
    if status != 'complete':
        raise SystemExit(1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trivy', default='/opt/heteronetwork/security/trivy')
    p.add_argument('--cache', default='/var/cache/heteronetwork-security')
    p.add_argument('--output', default='/var/lib/heteronetwork-security/host-report.json')
    p.add_argument('--inventory-user', default='mizuame')
    p.add_argument('--metadata-only', action='store_true')
    p.add_argument('--node-name')
    collect(p.parse_args())


if __name__ == '__main__':
    main()
