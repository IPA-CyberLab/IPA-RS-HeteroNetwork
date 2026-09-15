#!/usr/bin/env python3
"""Accept provisioned hosts only after fresh live browser and role E2E passes."""
import argparse
import contextlib
import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'deploy/terraform/master-only'
STATUS = 'heteronetwork.io/onboarding-status'
TAINT = 'heteronetwork.io/onboarding'


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, check=True, **kwargs)


def kubectl(*args):
    return run(['kubectl', '--request-timeout=15s', *args], timeout=30)


def mark(name, state, revision='', checked_at=''):
    patch = {'metadata': {'annotations': {STATUS: state,
        'heteronetwork.io/onboarding-e2e-revision': revision or None,
        'heteronetwork.io/onboarding-e2e-checked-at': checked_at or None}}}
    kubectl('patch', 'node', name, '--type=merge', '-p', json.dumps(patch))


def quarantine(name):
    kubectl('taint', 'node', name, TAINT + '=pending:NoSchedule', '--overwrite')


@contextlib.contextmanager
def operator_proxy(work):
    inventory = json.loads((work / 'inventory.json').read_text())['all']
    bootstrap = inventory['children']['bootstrap']['hosts']['uc-k8sp5']['ansible_host']
    key = inventory['vars']['ansible_ssh_private_key_file']
    with socket.socket() as free:
        free.bind(('127.0.0.1', 0))
        port = free.getsockname()[1]
    with (work / 'onboarding-ssh.log').open('w') as log:
        os.chmod(log.name, 0o600)
        process = subprocess.Popen(['ssh', '-N', '-i', key,
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'),
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=10',
            '-D', '127.0.0.1:' + str(port), 'mizuame@' + bootstrap],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Operator SSH proxy failed; see private onboarding-ssh.log')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Operator SSH proxy did not start')
            yield 'socks5://127.0.0.1:' + str(port)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def check(command, output):
    output.unlink(missing_ok=True)
    run([*command, '--output', str(output)], timeout=1800)
    report = json.loads(output.read_text())
    if not (report.get('passed') is True or report.get('result') == 'passed'):
        raise RuntimeError('E2E command did not return a passing report')
    return report


def accept(work, masters, standard, revision, verify):
    report = {'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'revision': revision, 'accepted': False, 'nodes': [*masters, *standard]}
    output = work / 'onboarding-acceptance.json'
    output.unlink(missing_ok=True)
    try:
        report['node_uids'] = {name: json.loads(kubectl('get', 'node', name, '-o', 'json').stdout)['metadata']['uid']
                               for name in report['nodes']}
        for name in report['nodes']:
            mark(name, 'pending')
        for name in standard:
            quarantine(name)
        report['e2e'] = verify()
        for name, uid in report['node_uids'].items():
            if json.loads(kubectl('get', 'node', name, '-o', 'json').stdout)['metadata']['uid'] != uid:
                raise RuntimeError('Node identity changed during onboarding E2E')
        checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for name in report['nodes']:
            mark(name, 'accepted', revision, checked_at)
        for name in standard:
            kubectl('taint', 'node', name, TAINT + ':NoSchedule-')
        report.update(accepted=True, finished_at_utc=checked_at)
    except Exception:
        for name in report['nodes']:
            with contextlib.suppress(Exception):
                mark(name, 'failed')
        for name in standard:
            with contextlib.suppress(Exception):
                quarantine(name)
        report['failure'] = 'Live onboarding E2E or acceptance failed; node remains unaccepted'
        raise
    finally:
        output.write_text(json.dumps(report, indent=2) + '\n')
        output.chmod(0o600)
    return report


def proof_is_current(work, names, standard, revision):
    try:
        proof = json.loads((work / 'onboarding-acceptance.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    if proof.get('accepted') is not True or proof.get('revision') != revision or set(proof.get('nodes', [])) != set(names):
        return False
    for name in names:
        node = json.loads(kubectl('get', 'node', name, '-o', 'json').stdout)
        annotations = node['metadata'].get('annotations', {})
        if (node['metadata']['uid'] != proof.get('node_uids', {}).get(name) or
            annotations.get(STATUS) != 'accepted' or
            annotations.get('heteronetwork.io/onboarding-e2e-revision') != revision):
            return False
        if name in standard and any(t['key'] == TAINT for t in node['spec'].get('taints', [])):
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--branch', default='codex/master-only-iac-20260915')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    work = Path(args.work_dir).expanduser().resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    work.chmod(0o700)
    masters = json.loads((MODULE / 'nodes.json').read_text())
    standard = json.loads((MODULE / 'standard-nodes.json').read_text())
    heads = run(['git', 'bundle', 'list-heads', str(work / 'infrastructure.bundle')]).stdout
    revision = next(line.split()[0] for line in heads.splitlines()
                    if line.split()[1] == 'refs/heads/' + args.branch)
    if args.check:
        valid = proof_is_current(work, [*masters, *standard], standard, revision)
        print(json.dumps({'onboarding_accepted': valid, 'revision': revision}))
        raise SystemExit(0 if valid else 2)

    def verify():
        for _ in range(90):
            apps = [json.loads(kubectl('get', 'application', name, '-n', 'argocd', '-o', 'json').stdout)
                    for name in ['control-plane-only', 'standard-nodes']]
            if all(p['status']['sync']['status'] == 'Synced' and p['status']['health']['status'] == 'Healthy'
                   and p['status']['sync']['revision'] == revision for p in apps):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Argo CD did not become Synced/Healthy at the candidate revision')
        nodes = json.loads(kubectl('get', 'nodes', '-o', 'json').stdout)['items']
        selected = [p for p in nodes if p['metadata']['name'] in [*masters, *standard, 'ichikawap1', 'uc-k8sp5']]
        gateways = [next(a['address'] for a in p['status']['addresses'] if a['type'] == 'InternalIP') for p in selected]
        assert len(gateways) == len(masters) + len(standard) + 2
        with tempfile.TemporaryDirectory(prefix='onboarding-e2e-', dir=work) as temp:
            directory = Path(temp)
            with operator_proxy(work) as proxy:
                console = check(['node', str(ROOT / 'scripts/verify-console-gateways.mjs'),
                                 '--gateways', ','.join(gateways), '--proxy', proxy], directory / 'console.json')
            dedicated = check(['python3', str(ROOT / 'scripts/verify-master-only.py'),
                               '--exercise-admission'], directory / 'masters.json')
            full = {name: check(['python3', str(ROOT / 'scripts/verify-standard-node.py'), '--node', name,
                                '--exercise-storage', '--allow-onboarding-pending'], directory / (name + '.json'))
                    for name in standard}
            return {'console': console, 'dedicated_masters': dedicated, 'standard_nodes': full}

    report = accept(work, masters, standard, revision, verify)
    print(json.dumps({'accepted': report['accepted'], 'nodes': report['nodes'], 'revision': revision}))


if __name__ == '__main__':
    main()
