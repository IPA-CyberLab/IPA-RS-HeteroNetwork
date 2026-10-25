#!/usr/bin/env python3
"""Audit actual healthy Longhorn copies on independent, Ready physical hosts."""
import argparse
import json
import subprocess


def ready(conditions):
    return any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in conditions)


def audit(volumes, replicas, nodes, storage_nodes):
    available_nodes = {n['metadata']['name'] for n in nodes['items']
                       if ready(n.get('status', {}).get('conditions', []))}
    disks = {(n['metadata']['name'], disk.get('diskUUID'))
             for n in storage_nodes['items']
             if ready(n.get('status', {}).get('conditions', []))
             for disk in n.get('status', {}).get('diskStatus', {}).values()
             if disk.get('diskUUID') and ready(disk.get('conditions', []))}
    rows = []
    for volume in volumes['items']:
        if volume['metadata'].get('deletionTimestamp'):
            continue
        name, desired = volume['metadata']['name'], volume['spec']['numberOfReplicas']
        copies = {r['spec']['nodeID'] for r in replicas['items']
                  if r['spec'].get('volumeName') == name
                  and not r['metadata'].get('deletionTimestamp')
                  and r['spec'].get('healthyAt') and not r['spec'].get('failedAt')
                  and r['spec'].get('nodeID') in available_nodes
                  and (r['spec'].get('nodeID'), r['spec'].get('diskID')) in disks}
        count = len(copies)
        rows.append({'volume': name, 'configured_copies': desired,
                     'healthy_independent_hosts': sorted(copies), 'available_copies': count,
                     'severity': 'critical' if count < 2 else
                                 'warning' if count < desired else 'healthy',
                     'backup_record_present': bool(volume.get('status', {}).get('lastBackup'))})
    return {'result': 'passed' if rows and all(r['severity'] == 'healthy' for r in rows) else 'failed',
            'checked_volumes': len(rows),
            'critical_volumes': sum(r['severity'] == 'critical' for r in rows),
            'under_replicated_volumes': sum(r['severity'] != 'healthy' for r in rows),
            'volumes': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--server')
    parser.add_argument('--tls-server-name')
    args = parser.parse_args()
    command = ['kubectl', '--kubeconfig=' + args.kubeconfig,
               '--request-timeout=12s', '-n', 'longhorn-system']
    if args.server:
        command += ['--server=' + args.server]
    if args.tls_server_name:
        command += ['--tls-server-name=' + args.tls_server_name]
    try:
        data = []
        for kind in ['volumes.longhorn.io', 'replicas.longhorn.io', 'nodes', 'nodes.longhorn.io']:
            result = subprocess.run(command + ['get', kind, '-o', 'json'],
                                    capture_output=True, timeout=15)
            if result.returncode:
                raise RuntimeError('storage_inventory_unavailable')
            data.append(json.loads(result.stdout))
        report = audit(*data)
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired):
        print(json.dumps({'result': 'failed', 'failure': 'storage_inventory_unavailable_or_invalid'}))
        return 1
    print(json.dumps(report))
    return 0 if report['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
