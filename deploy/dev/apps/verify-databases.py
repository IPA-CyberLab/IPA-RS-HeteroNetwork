#!/usr/bin/env python3
"""Read-only DEV application database replication, placement and PVC checks."""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('apply_databases', Path(__file__).with_name('apply-databases.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def verify(namespace):
    helper.require(namespace in helper.databases.NAMESPACES)
    helper.guard()
    get, require, run = helper.get, helper.require, helper.run
    cluster = get('cluster.postgresql.cnpg.io', 'dev-postgres', namespace)
    require(cluster['status'].get('readyInstances') == 3)
    primary = cluster['status']['currentPrimary']
    names = [f'dev-postgres-{i}' for i in range(1, 4)]
    require(primary in names and cluster['status'].get('targetPrimary') == primary)
    database = namespace.replace('-', '_')
    result = []
    for number, name in enumerate(names, 1):
        pod = get('pod', name, namespace)
        require(pod['spec']['nodeName'] == f'hetero-dev-{number}')
        require(any(c['type'] == 'Ready' and c['status'] == 'True'
                    for c in pod['status'].get('conditions', [])))
        claim = get('pvc', name, namespace)
        require(claim['status']['phase'] == 'Bound')
        expected = f'dev-app-{namespace.removesuffix("-dev")}-postgres-{number}'
        require(claim['spec']['volumeName'] == expected)
        query = """SELECT json_build_object(
            'recovery', pg_is_in_recovery(),
            'synchronous_commit', current_setting('synchronous_commit'),
            'synchronous_standby_names', current_setting('synchronous_standby_names'),
            'replication', (SELECT coalesce(json_agg(json_build_object(
                'application', application_name, 'state', state, 'sync_state', sync_state)), '[]')
                FROM pg_stat_replication));"""
        sql = json.loads(run(['exec', '-n', namespace, name, '-c', 'postgres', '--',
                              'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                              '-U', 'postgres', '-d', database, '-c', query]))
        require(sql['recovery'] == (name != primary) and sql['synchronous_commit'] == 'on')
        if name == primary:
            peers = sql['replication']
            require(len(peers) == 2 and {p['application'] for p in peers} == set(names) - {primary})
            require(all(p['state'] == 'streaming' and p['sync_state'] == 'quorum' for p in peers))
            require(sql['synchronous_standby_names'].upper().startswith('ANY 1 ('))
        result.append({'pod': name, 'node': pod['spec']['nodeName'], 'volume': expected, **sql})
    return {'namespace': namespace, 'primary': primary, 'instances': result,
            'replication_verified': True, 'write_recovery_tested': False, 'physical_ha': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('namespace', choices=helper.databases.NAMESPACES)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.namespace)))
    except (OSError, ValueError, KeyError, TypeError, helper.subprocess.SubprocessError):
        print(json.dumps({'error': 'DEV database verification failed; inspect readiness, PVCs and replication'}))
        raise SystemExit(1)
