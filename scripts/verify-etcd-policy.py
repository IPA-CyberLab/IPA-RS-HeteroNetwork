#!/usr/bin/env python3
"""Guard a serial etcd policy rollout; never change membership or application Pods."""
import argparse
import json
import subprocess


def kube(*args):
    result = subprocess.run(['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf',
                             '--request-timeout=15s', *args], text=True,
                            capture_output=True, timeout=25)
    if result.returncode:
        raise ValueError('etcd rollout Kubernetes operation failed: ' + result.stderr[-500:])
    return result.stdout


def etcd(node, *args):
    return kube('-n', 'kube-system', 'exec', 'etcd-' + node, '--', 'etcdctl',
                '--endpoints=https://127.0.0.1:2379', '--command-timeout=10s',
                '--cacert=/etc/kubernetes/pki/etcd/ca.crt',
                '--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt',
                '--key=/etc/kubernetes/pki/etcd/healthcheck-client.key', *args)


def validate_cluster(members, statuses, health):
    voters = members['members']
    ids = {m['ID'] for m in voters}
    if len(ids) < 3 or len(ids) != len(voters) or any(m.get('isLearner') for m in voters):
        raise ValueError('Expected at least three distinct voting members and no learner')
    if len(statuses) != len(ids) or {s['Status']['header']['member_id'] for s in statuses} != ids:
        raise ValueError('Every member must report its status before another member changes')
    leaders = {s['Status']['leader'] for s in statuses}
    if len(leaders) != 1 or not leaders <= ids:
        raise ValueError('Cluster has not converged on a voting leader')
    endpoints = {u for m in voters for u in m['clientURLs']}
    if {h['endpoint'] for h in health} != endpoints or not all(h['health'] for h in health):
        raise ValueError('All existing endpoints must be healthy before continuing')
    if any(s['Status'].get('errors') or s['Status'].get('isLearner') for s in statuses):
        raise ValueError('etcd reports an error or learner')
    return next(iter(leaders))


def verify_pod(pod):
    containers = [c for c in pod['spec']['containers'] if c['name'] == 'etcd']
    if len(containers) != 1:
        raise ValueError('Expected one etcd container')
    container = containers[0]
    command = container.get('command', []) + container.get('args', [])
    for flag in ['--heartbeat-interval=500', '--election-timeout=5000']:
        if [a for a in command if a.startswith(flag.split('=')[0] + '=')] != [flag]:
            raise ValueError('Updated etcd timing not yet observed')
    if container['resources']['requests'] != {'cpu': '500m', 'memory': '512Mi'}:
        raise ValueError('Updated etcd reservations not yet observed')
    if container['livenessProbe']['failureThreshold'] != 30 or container['startupProbe']['failureThreshold'] != 180:
        raise ValueError('Updated etcd probes not yet observed')
    if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', [])):
        raise ValueError('etcd Pod is not ready')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'verify'])
    parser.add_argument('--node', required=True)
    args = parser.parse_args()
    members = json.loads(etcd(args.node, 'member', 'list', '-w', 'json'))
    statuses = json.loads(etcd(args.node, 'endpoint', 'status', '--cluster', '-w', 'json'))
    health = json.loads(etcd(args.node, 'endpoint', 'health', '--cluster', '-w', 'json'))
    leader = validate_cluster(members, statuses, health)
    local = next(m for m in members['members'] if m['name'] == args.node)
    pod = json.loads(kube('-n', 'kube-system', 'get', 'pod', 'etcd-' + args.node, '-o', 'json'))
    if args.operation == 'verify':
        verify_pod(pod)
    else:
        try:
            verify_pod(pod)
            needs_change = False
        except ValueError:
            needs_change = True
        if needs_change and local['ID'] == leader:
            # Transfer only to a healthy, caught-up existing voter, never add/remove one.
            followers = [s for s in statuses if s['Status']['header']['member_id'] != leader]
            target = max(followers, key=lambda s: s['Status']['raftAppliedIndex'])['Status']['header']['member_id']
            etcd(args.node, 'move-leader', format(target, 'x'))
            new = json.loads(etcd(args.node, 'endpoint', 'status', '--cluster', '-w', 'json'))
            if {s['Status']['leader'] for s in new} != {target}:
                raise ValueError('Leadership transfer has not converged')
    print(json.dumps({'node': args.node, 'healthy_members': len(members['members']), 'operation': args.operation}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, StopIteration, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
