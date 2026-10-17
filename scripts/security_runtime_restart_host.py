#!/usr/bin/env python3
"""Argument-free, forced-SSH endpoint for bounded Flash sandbox activation.

Only the declared namespaces and runsc handler are eligible. Requests bind the
Pod UID, sandbox ID, old executable hash, and installed artifact fingerprint.
No command, environment, image, volume path, or executable path comes from SSH.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

from security_inventory import atomic_json, utc_now
from security_update_gate import fingerprint


ROOT = Path('/var/lib/heteronetwork-security/runtime-restart-host')
POLICY = Path('/opt/heteronetwork/security/policy.json')
ENDPOINT = 'unix:///run/containerd/containerd.sock'
BINARIES = [Path('/usr/bin/runsc'), Path('/usr/bin/containerd-shim-runsc-v1')]
BUNDLE = Path('/usr/bin/gvisor-bin')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def trusted(path):
    path = Path(path)
    for item in [path, *path.parents]:
        info = item.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode)
                and info.st_mode & 0o022 == 0, 'untrusted runtime restart path')
    return path


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(args, timeout=20):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, 'runtime operation failed: ' + args[0])
    return result.stdout


def cri(*args, timeout=20):
    return run(['crictl', '--runtime-endpoint=' + ENDPOINT, '--timeout=60s', *args], timeout)


def artifact():
    paths = BINARIES + sorted(p for p in BUNDLE.rglob('*')
                              if p.is_file() and not p.name.startswith('.') and '.dpkg-' not in p.name)
    require(2 < len(paths) <= 100 and BUNDLE.joinpath('gvisor_sentry') in paths,
            'complete gVisor bundle is required')
    files = {}
    for path in paths:
        trusted(path)
        require(path.is_file() and path.stat().st_size < 200 * 1024 * 1024,
                'invalid runtime bundle member')
        files[str(path)] = sha(path)
    version = run(['/usr/bin/runsc', '--version']).splitlines()[0].strip()
    require(re.fullmatch(r'runsc version release-\d{8}\.\d+', version), 'unsupported runtime version')
    value = {'version': version, 'files': files}
    return {**value, 'sha256': fingerprint(value), 'sentry_sha256': files[str(BUNDLE / 'gvisor_sentry')]}


def process(pid):
    # The start time prevents PID reuse from being mistaken for continuity.
    path = Path('/proc') / str(pid)
    stat_text = (path / 'stat').read_text()
    fields = stat_text.rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': fields[19], 'state': fields[0],
            'exe_sha256': sha(path / 'exe')}


def memory_limit(pid):
    root = Path('/sys/fs/cgroup')
    rows = (Path('/proc') / str(pid) / 'cgroup').read_text().splitlines()
    unified = next((r[3:] for r in rows if r.startswith('0::')), None)
    require(unified is not None and '..' not in Path(unified).parts, 'cgroup v2 memory accounting required')
    current = root / unified.lstrip('/')
    limits = []
    while current != root:
        path = current / 'memory.max'
        if path.exists():
            value = path.read_text().strip()
            if value.isdigit():
                limits.append(int(value))
        current = current.parent
    return min(limits) if limits else None


def pod_memory(pid, uid):
    rows = (Path('/proc') / str(pid) / 'cgroup').read_text().splitlines()
    unified = next((r[3:] for r in rows if r.startswith('0::')), None)
    require(unified is not None and '..' not in Path(unified).parts, 'invalid memory accounting path')
    current = Path('/sys/fs/cgroup') / unified.lstrip('/')
    normalized = uid.replace('-', '_')
    while current != Path('/sys/fs/cgroup'):
        if uid in current.name or normalized in current.name:
            values = dict(line.split() for line in (current / 'memory.stat').read_text().splitlines())
            nonreclaimable = sum(int(values.get(k, 0)) for k in ('anon', 'shmem', 'kernel_stack', 'pagetables', 'slab_unreclaimable'))
            return {'current': int((current / 'memory.current').read_text()), 'nonreclaimable': nonreclaimable}
        current = current.parent
    return None


def snapshot(policy):
    result = []
    namespaces = (policy['namespace'], policy['probe_namespace'])
    for item in json.loads(cri('pods', '-o', 'json')).get('items', []) or []:
        meta = item['metadata']
        if meta['namespace'] not in namespaces or item['state'] != 'SANDBOX_READY':
            continue
        detail = json.loads(cri('inspectp', item['id']))
        if detail.get('status', {}).get('runtimeHandler') != policy['runtime_handler']:
            continue
        pid = detail.get('info', {}).get('pid', 0)
        require(isinstance(pid, int) and pid > 0, 'sandbox runtime identity is unavailable')
        try:
            identity = process(pid)
        except FileNotFoundError:
            continue  # The kubelet may already be replacing a terminated sandbox.
        result.append({'id': item['id'], 'metadata': meta, 'memory_max': memory_limit(pid),
                       'pod_memory': pod_memory(pid, meta['uid']), **identity})
    return result


def prepare():
    current = artifact()
    directory = ROOT / 'bundles' / current['sha256']
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path, digest in current['files'].items():
        destination = directory / Path(path).relative_to('/usr/bin')
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(path, destination)
        require(sha(destination) == digest, 'rollback bundle checksum mismatch')
    atomic_json(directory / 'manifest.json', current)
    atomic_json(ROOT / 'rollback.json', current)
    return {'status': 'rollback-staged', 'artifact': current['sha256'], 'version': current['version']}


def backup():
    manifest = ROOT / 'rollback.json'
    if not manifest.exists():
        return None
    value = json.loads(trusted(manifest).read_text())
    require(re.fullmatch(r'[0-9a-f]{64}', value['sha256']), 'invalid rollback identity')
    require(value['sha256'] == fingerprint({k: value[k] for k in ('version', 'files')}), 'rollback identity mismatch')
    for path, digest in value['files'].items():
        require(path in [str(p) for p in BINARIES] or path.startswith(str(BUNDLE) + '/'), 'invalid rollback member')
        relative = Path(path).relative_to('/usr/bin')
        require('..' not in relative.parts, 'invalid rollback member')
        saved = trusted(ROOT / 'bundles' / value['sha256'] / relative)
        require(sha(saved) == digest, 'rollback bundle checksum mismatch')
    return value


def restore(expected):
    current = artifact()
    require(current['sha256'] == expected, 'installed runtime changed before rollback')
    previous = backup()
    require(previous and previous['sha256'] != expected, 'a distinct rollback bundle is unavailable')
    for path in previous['files']:
        saved = ROOT / 'bundles' / previous['sha256'] / Path(path).relative_to('/usr/bin')
        temporary = Path(path).with_name('.' + Path(path).name + '.security-rollback')
        shutil.copy2(saved, temporary)
        os.replace(temporary, path)
    for path in current['files'].keys() - previous['files'].keys():
        require(path.startswith(str(BUNDLE) + '/'), 'unexpected extra top-level runtime file')
        Path(path).unlink()
    require(artifact()['sha256'] == previous['sha256'], 'runtime rollback verification failed')
    return previous


def validate_request(request, current, pods, policy):
    require(request.get('artifact_sha256') == current['sha256'], 'installed runtime changed')
    require(re.fullmatch(r'[0-9a-f]{64}', request.get('sandbox_id', '')), 'invalid sandbox ID')
    matches = [p for p in pods if p['id'] == request['sandbox_id']]
    require(len(matches) == 1, 'sandbox is no longer ready')
    pod = matches[0]
    require(pod['metadata']['namespace'] in (policy['namespace'], policy['probe_namespace']), 'namespace is not approved')
    require(pod['metadata']['uid'] == request.get('pod_uid'), 'Pod UID changed')
    require(pod['exe_sha256'] == request.get('source_sha256'), 'source runtime changed')
    is_probe = pod['metadata']['namespace'] == policy['probe_namespace']
    require(not request.get('probe') or is_probe, 'only a canary may force an already current restart')
    require(is_probe or pod['exe_sha256'] != current['sentry_sha256'], 'runtime is already active')
    return pod


def operate(request, policy):
    action = request.get('action')
    require(action in ('inspect', 'reserve', 'restart', 'rollback'), 'unsupported runtime action')
    current = artifact()
    require(current['version'].removeprefix('runsc version ') in policy['approved_runtime_versions'],
            'installed runtime version is not approved')
    pods = snapshot(policy)
    previous = backup()
    if action == 'inspect':
        response = {'artifact': current, 'sandboxes': pods, 'rollback_sha256': (previous or {}).get('sha256')}
        if request.get('pod_uid') and request.get('artifact_sha256'):
            key = fingerprint({'uid': request['pod_uid'], 'artifact': request['artifact_sha256']})
            path = ROOT / 'attempts' / (key + '.json')
            require(path.exists(), 'restart intent is missing')
            source = json.loads(trusted(path).read_text())['source']
            try:
                active = process(source['pid'])
                response['source_fenced'] = active['start_ticks'] != source['start_ticks'] or active['state'] == 'Z'
            except FileNotFoundError:
                response['source_fenced'] = True
        return response
    require(policy['max_attempts_per_artifact'] == 1, 'only one automatic restart is permitted')
    if action == 'rollback':
        restored = restore(request.get('artifact_sha256'))
        return {'status': 'rollback-restored', 'artifact': restored}
    pod = validate_request(request, current, pods, policy)
    directory = ROOT / 'attempts'
    directory.mkdir(mode=0o700, exist_ok=True)
    identity = fingerprint({'uid': pod['metadata']['uid'], 'artifact': current['sha256']})
    record_path = directory / (identity + '.json')
    require(not record_path.exists(), 'this Pod/artifact already used its restart budget')
    # Write the intent before the mutation: an interrupted SSH session is never
    # retried blindly against the same workload and artifact.
    record = {'status': 'stopping', 'started_at': utc_now(), 'pod_uid': pod['metadata']['uid'],
              'sandbox_id': pod['id'], 'source': {k: pod[k] for k in ('pid', 'start_ticks', 'exe_sha256')},
              'target_artifact': current['sha256'], 'target_sentry_sha256': current['sentry_sha256']}
    atomic_json(record_path, record)
    if action == 'reserve':
        record.update(status='reserved-for-pod-replacement')
        atomic_json(record_path, record)
        return record
    started = time.monotonic()
    # StopPodSandbox has no grace-period parameter. Gracefully stop application
    # containers first, sharing one grace budget, then stop the empty sandbox.
    containers = json.loads(cri('ps', '--pod', pod['id'], '-o', 'json')).get('containers', []) or []
    deadline = started + policy['grace_seconds']
    for container in containers:
        require(re.fullmatch(r'[0-9a-f]{64}', container['id']), 'invalid application container ID')
        remaining = max(0, int(deadline - time.monotonic()))
        cri('stop', '--timeout=' + str(remaining), container['id'], timeout=remaining + 15)
    cri('stopp', pod['id'], timeout=30)
    record.update(status='stopped', stop_seconds=round(time.monotonic() - started, 3), stopped_at=utc_now())
    atomic_json(record_path, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-install', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root is required')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    trusted(ROOT)
    handle = os.open(ROOT / 'operation.lock', os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.prepare_install:
            response = prepare()
        else:
            raw = sys.stdin.readline(8193)
            require(len(raw) <= 8192 and raw.endswith('\n'), 'invalid bounded restart request')
            request = json.loads(raw)
            require(isinstance(request, dict) and re.fullmatch(r'[0-9a-f]{64}', request.get('challenge', '')), 'fresh challenge required')
            config = json.loads(trusted(POLICY).read_text())
            require(config.get('allow_restart_fallback') is True and config.get('require_live_migration') is False,
                    'bounded restart is not authorized')
            policy = config['restart']
            require(1 <= policy['grace_seconds'] <= 60, 'invalid restart grace period')
            response = {**operate(request, policy), 'challenge': request['challenge'], 'observed_at': utc_now()}
        print(json.dumps(response), flush=True)
    finally:
        os.close(handle)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'error', 'reason': str(error)[:200]}), flush=True)
        raise SystemExit(1)
