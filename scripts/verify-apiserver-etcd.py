#!/usr/bin/env python3
"""Verify the applied static API Pod, including its arguments and readiness."""
import argparse
import ipaddress
import json
import subprocess


def expected_argument(backends):
    addresses = backends.split(',')
    if len(addresses) != 3 or len(set(addresses)) != 3:
        raise ValueError('Exactly three distinct etcd client endpoints are required')
    for address in addresses:
        if str(ipaddress.IPv4Address(address)) != address:
            raise ValueError('Noncanonical IPv4 endpoint')
    return '--etcd-servers=' + ','.join('https://' + ip + ':2379' for ip in addresses)


def verify_pod(pod, node, argument):
    if pod.get('spec', {}).get('nodeName') != node:
        raise ValueError('API Pod is assigned to a different node')
    containers = [c for c in pod['spec']['containers'] if c['name'] == 'kube-apiserver']
    if len(containers) != 1:
        raise ValueError('Expected exactly one API server container')
    arguments = containers[0].get('command', []) + containers[0].get('args', [])
    endpoints = [a for a in arguments if a.startswith('--etcd-servers=')]
    if endpoints != [argument]:
        raise ValueError('The updated API server manifest has not been observed')
    statuses = [c for c in pod.get('status', {}).get('containerStatuses', []) if c['name'] == 'kube-apiserver']
    if len(statuses) != 1 or not statuses[0].get('ready') or 'running' not in statuses[0].get('state', {}):
        raise ValueError('The API server container is not running and ready')
    if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', [])):
        raise ValueError('The API server Pod is not ready')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--backends', required=True)
    args = parser.parse_args()
    argument = expected_argument(args.backends)
    command = ['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--server=' + args.endpoint,
               '--request-timeout=8s', '-n', 'kube-system', 'get', 'pod', 'kube-apiserver-' + args.node, '-o', 'json']
    result = subprocess.run(command, capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise ValueError('Local API Pod lookup did not succeed')
    verify_pod(json.loads(result.stdout), args.node, argument)
    print(json.dumps({'node': args.node, 'etcd_client_endpoints': args.backends.split(','), 'ready': True}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
