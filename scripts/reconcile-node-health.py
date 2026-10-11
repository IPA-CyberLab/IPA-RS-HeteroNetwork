#!/usr/bin/env python3
"""Reconcile only node health timing; never restart kubelet or containerd."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


def replace_manifest(text, seconds):
    pattern = r"(?m)^(\s*- --node-monitor-grace-period=)\d+s(\s*)$"
    result, count = re.subn(pattern, lambda m: m[1] + str(seconds) + 's' + m[2], text)
    if count != 1:
        raise ValueError('Expected exactly one existing node-monitor-grace-period argument')
    return result


def replace_cluster_config(text, seconds):
    pattern = r'(name: ["\x27]?node-monitor-grace-period["\x27]?\n\s*value: )["\x27]?\d+s["\x27]?'
    result, count = re.subn(pattern, lambda m: m[1] + str(seconds) + 's', text)
    if count != 1:
        raise ValueError('Expected exactly one kubeadm node health setting')
    return result


def kube(*arguments, data=None):
    result = subprocess.run(['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                             '--request-timeout=10s', *arguments], input=data,
                            text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError('Kubernetes node health operation failed')
    return result.stdout


def verify(pod, node, seconds):
    if pod.get('spec', {}).get('nodeName') != node:
        raise ValueError('Unexpected controller manager node')
    containers = [c for c in pod['spec']['containers'] if c['name'] == 'kube-controller-manager']
    expected = '--node-monitor-grace-period=' + str(seconds) + 's'
    if len(containers) != 1 or [a for a in containers[0].get('command', []) + containers[0].get('args', [])
                               if a.startswith('--node-monitor-grace-period=')] != [expected]:
        raise ValueError('New controller manager arguments are not observed yet')
    statuses = [c for c in pod.get('status', {}).get('containerStatuses', [])
                if c['name'] == 'kube-controller-manager']
    if len(statuses) != 1 or not statuses[0].get('ready') or 'running' not in statuses[0].get('state', {}):
        raise ValueError('New controller manager is not running and ready')
    if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', [])):
        raise ValueError('Controller manager Pod is not ready')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['manifest', 'cluster-config', 'verify'])
    parser.add_argument('--seconds', type=int, required=True)
    parser.add_argument('--node')
    args = parser.parse_args()
    if not 50 <= args.seconds <= 300:
        raise ValueError('Node monitor grace must be between 50 and 300 seconds')
    if args.operation == 'manifest':
        path = Path('/etc/kubernetes/manifests/kube-controller-manager.yaml')
        mode = path.lstat()
        if not stat.S_ISREG(mode.st_mode) or mode.st_uid != 0:
            raise ValueError('Controller manager manifest must be a root-owned regular file')
        original = path.read_text()
        replacement = replace_manifest(original, args.seconds)
        if original != replacement:
            backup = Path('/etc/heteronetwork/kubernetes/controller-manager-before-node-health.yaml')
            backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'w') as output:
                    output.write(original)
            # Stage outside the watched manifests directory, then replace atomically.
            fd, temp = tempfile.mkstemp(prefix='node-health-', dir='/etc/kubernetes')
            try:
                with os.fdopen(fd, 'w') as output:
                    output.write(replacement)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temp, stat.S_IMODE(mode.st_mode))
                os.replace(temp, path)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
        print(json.dumps({'changed': original != replacement, 'seconds': args.seconds}))
    elif args.operation == 'cluster-config':
        cm = json.loads(kube('-n', 'kube-system', 'get', 'configmap', 'kubeadm-config', '-o', 'json'))
        original = cm['data']['ClusterConfiguration']
        replacement = replace_cluster_config(original, args.seconds)
        if replacement != original:
            patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': cm['metadata']['resourceVersion']},
                     {'op': 'replace', 'path': '/data/ClusterConfiguration', 'value': replacement}]
            kube('-n', 'kube-system', 'patch', 'configmap', 'kubeadm-config', '--type=json', '-p', json.dumps(patch))
        print(json.dumps({'changed': original != replacement, 'seconds': args.seconds}))
    else:
        if not args.node:
            raise ValueError('--node is required for verification')
        pod = json.loads(kube('-n', 'kube-system', 'get', 'pod', 'kube-controller-manager-' + args.node, '-o', 'json'))
        verify(pod, args.node, args.seconds)
        print(json.dumps({'node': args.node, 'seconds': args.seconds, 'ready': True}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
