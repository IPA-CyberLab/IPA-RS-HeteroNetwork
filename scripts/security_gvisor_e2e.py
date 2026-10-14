#!/usr/bin/env python3
"""Exercise real gVisor checkpoint/restore with a continuously connected client.

Runs only an isolated, explicitly named canary. Checkpoints live in a private
noswap tmpfs. No Kubernetes/CRI workload or installed runtime is modified.
Incompatible restores must recover the original state with the source runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

from security_inventory import atomic_json, utc_now


def command(args, timeout=30, checked=True):
    # Detached Sentry processes can inherit stdout. Pipes would wait for EOF
    # from the still-running sandbox instead of for the completed runsc command.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(args, stdout=output, stderr=errors, timeout=timeout)
        output.seek(0)
        errors.seek(0)
        result.stdout = output.read().decode(errors='replace')
        result.stderr = errors.read().decode(errors='replace')
    if checked and result.returncode:
        raise RuntimeError(args[0] + ': ' + result.stderr[-1500:])
    return result


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bundle_identity(runtime):
    parent = Path(runtime).parent
    files = [Path(runtime)] + sorted((parent / 'gvisor-bin').glob('*'))
    return {str(path.relative_to(parent)): digest(path) for path in files if path.is_file()}


def continuity(before, after):
    return (all(before[key] == after[key] for key in ['nonce', 'memory_hash', 'started_ns', 'guest_pid'])
            and after['connections'] == before['connections'] == 1
            and after['sequence'] > before['sequence'])


def run(args):
    if os.geteuid() != 0:
        raise RuntimeError('this isolated network/runtime test requires root')
    for binary in [args.source_runsc, args.target_runsc, args.probe_binary]:
        path = Path(binary)
        info = path.stat()
        if not path.is_file() or path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('probe executables must be trusted root-owned regular files')
    if command(['ip', '-4', 'route', 'show', 'exact', '192.0.2.0/30']).stdout.strip():
        raise RuntimeError('the canary subnet is already in use')
    identifier = uuid.uuid4().hex[:8]
    namespace = 'hnn-sec-' + identifier
    host_link = 'hs' + identifier
    peer_link = 'gs' + identifier
    source_id, target_id, rollback_id = ['sec-' + identifier + '-' + suffix for suffix in ['src', 'dst', 'rollback']]
    source_version = command([args.source_runsc, '--version']).stdout.strip()
    target_version = command([args.target_runsc, '--version']).stdout.strip()
    evidence = {'schema_version': 1, 'verified_at': utc_now(), 'strategy': 'gvisor_checkpoint_restore',
                'scope': 'isolated-canary', 'source_version': source_version, 'target_version': target_version,
                'source_sha256': digest(args.source_runsc), 'target_sha256': digest(args.target_runsc),
                'source_bundle': bundle_identity(args.source_runsc), 'target_bundle': bundle_identity(args.target_runsc),
                'probe_sha256': digest(args.probe_binary), 'restart_fallback': False,
                'cross_version_restore_passed': False, 'rollback_verified': False,
                'state_preserved': False, 'network_connections_preserved': False}
    root = Path(tempfile.mkdtemp(prefix='hetero-gvisor-probe-', dir='/var/lib/heteronetwork-security'))
    snapshot = root / 'snapshot'
    snapshot.mkdir(mode=0o700)
    state = root / 'state'
    state.mkdir(mode=0o700)
    bundle = root / 'bundle'
    bundle.mkdir(mode=0o700)
    rootfs = bundle / 'rootfs'
    rootfs.mkdir(mode=0o700)
    for name in ['proc', 'dev', 'tmp']:
        (rootfs / name).mkdir(mode=0o755)
    shutil.copyfile(args.probe_binary, rootfs / 'probe')
    (rootfs / 'probe').chmod(0o755)
    spec = {'ociVersion': '1.2.0', 'root': {'path': str(rootfs), 'readonly': True},
            'process': {'terminal': False, 'user': {'uid': 0, 'gid': 0},
                        'args': ['/probe'], 'env': ['PATH=/'], 'cwd': '/',
                        'noNewPrivileges': True}, 'hostname': 'security-probe',
            'mounts': [{'destination': '/proc', 'type': 'proc', 'source': 'proc'},
                       {'destination': '/tmp', 'type': 'tmpfs', 'source': 'tmpfs', 'options': ['nosuid', 'nodev', 'size=16m']}],
            'linux': {'namespaces': [{'type': kind} for kind in ['pid', 'ipc', 'uts', 'mount']] +
                                    [{'type': 'network', 'path': '/var/run/netns/' + namespace}],
                      'cgroupsPath': '/hetero-security-' + identifier,
                      'resources': {'memory': {'limit': 256 * 1024 * 1024},
                                    'cpu': {'quota': 100000, 'period': 100000}}}}
    atomic_json(bundle / 'config.json', spec)
    common = ['--root=' + str(state), '--platform=systrap', '--network=sandbox']
    mounted, network = False, False
    client = reader = None
    try:
        command(['mount', '-t', 'tmpfs', '-o', 'size=256M,mode=0700,noswap', 'tmpfs', str(snapshot)])
        mounted = True
        mount = json.loads(command(['findmnt', '--json', '--target', str(snapshot), '-o', 'OPTIONS']).stdout)
        if 'noswap' not in mount['filesystems'][0]['options'].split(','):
            raise RuntimeError('checkpoint memory must never spill into swap')
        command(['ip', 'netns', 'add', namespace])
        network = True
        command(['ip', 'link', 'add', host_link, 'type', 'veth', 'peer', 'name', peer_link])
        command(['ip', 'link', 'set', peer_link, 'netns', namespace])
        command(['ip', 'addr', 'add', '192.0.2.1/30', 'dev', host_link])
        command(['ip', 'link', 'set', host_link, 'up'])
        command(['ip', '-n', namespace, 'addr', 'add', '192.0.2.2/30', 'dev', peer_link])
        command(['ip', '-n', namespace, 'link', 'set', peer_link, 'up'])
        command(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
        command([args.source_runsc, *common, 'run', '--detach', '--bundle=' + str(bundle), source_id])
        deadline = time.monotonic() + 30
        while True:
            try:
                client = socket.create_connection(('192.0.2.2', 6069), timeout=3)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError('probe never became available')
                time.sleep(0.3)
        client.settimeout(30)
        reader = client.makefile('rb')
        def observe():
            client.sendall(b'state\n')
            line = reader.readline(65536)
            if not line:
                raise RuntimeError('established connection was closed')
            return json.loads(line)
        before = observe()
        evidence['before'] = before
        evidence['client_socket'] = list(client.getsockname())
        checkpoint = snapshot / 'checkpoint'
        command([args.source_runsc, *common, 'checkpoint', '--image-path=' + str(checkpoint), source_id], timeout=120)
        command([args.source_runsc, *common, 'delete', '--force', source_id])
        evidence['source_fenced'] = True
        # Sandbox networking consumes the namespace's IP configuration at
        # startup. Recreate that exact interface address before rebinding the
        # restored netstack to its new packet endpoint.
        command(['ip', '-n', namespace, 'addr', 'replace', '192.0.2.2/30', 'dev', peer_link])
        result = command([args.target_runsc, *common, 'restore', '--detach', '--bundle=' + str(bundle), '--image-path=' + str(checkpoint), target_id], timeout=120, checked=False)
        if result.returncode == 0:
            after = observe()
            if not continuity(before, after):
                raise RuntimeError('restore lost in-memory state or reconnected the client')
            evidence.update(status='verified', after=after, cross_version_restore_passed=True,
                            state_preserved=True, network_connections_preserved=True,
                            target_runtime_verified=True, capacity_reserved=True)
        else:
            evidence['target_restore_error'] = result.stderr[-1000:]
            command([args.target_runsc, *common, 'delete', '--force', target_id], checked=False)
            command(['ip', '-n', namespace, 'addr', 'replace', '192.0.2.2/30', 'dev', peer_link])
            command([args.source_runsc, *common, 'restore', '--detach', '--bundle=' + str(bundle), '--image-path=' + str(checkpoint), rollback_id], timeout=120)
            after = observe()
            if not continuity(before, after):
                raise RuntimeError('rollback failed to recover memory and the existing connection')
            evidence.update(status='blocked-incompatible', rollback_after=after, rollback_verified=True,
                            rollback_state_preserved=True, rollback_network_connections_preserved=True)
        atomic_json(args.output, evidence)
        print(json.dumps({key: evidence[key] for key in ['status', 'source_version', 'target_version', 'cross_version_restore_passed', 'rollback_verified', 'network_connections_preserved']}))
        return evidence
    except BaseException as error:
        atomic_json(args.output, {**evidence, 'status': 'error', 'error': str(error)[-1500:]})
        raise
    finally:
        if reader:
            reader.close()
        if client:
            client.close()
        for runtime, container in [(args.source_runsc, source_id), (args.target_runsc, target_id), (args.source_runsc, rollback_id)]:
            command([runtime, *common, 'delete', '--force', container], checked=False)
        if network:
            command(['ip', 'link', 'del', host_link], checked=False)
            command(['ip', 'netns', 'del', namespace], checked=False)
        if mounted:
            command(['umount', str(snapshot)])
        # runsc can retain a private bind-mounted null namespace after a failed
        # create. Release only mounts inside this test's unique private tree.
        mounts = command(['findmnt', '-rn', '-o', 'TARGET']).stdout.splitlines()
        for mount in sorted((m for m in mounts if m.startswith(str(root) + '/')), key=len, reverse=True):
            command(['umount', mount])
        shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ['source-runsc', 'target-runsc', 'probe-binary', 'output']:
        parser.add_argument('--' + field, required=True)
    args = parser.parse_args()
    result = run(args)
    raise SystemExit(0 if result['status'] == 'verified' else 2)


if __name__ == '__main__':
    main()
