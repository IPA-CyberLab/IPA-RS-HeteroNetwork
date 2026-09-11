#!/usr/bin/env python3
"""DEV Syouyu API readiness, authentication rejection, migrations and DB TLS."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
NS = 'heterocloud-syouyu-dev'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-syouyu:0.1.7-dev.2@sha256:2021bc7161146b212e41ec51ae5f1e127d11cfa03ad03d588e05de2335a0d1d6'


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()

    def get(kind, name):
        return json.loads(helper.run(['get', kind, name, '-n', NS, '-o', 'json']))

    deployment = get('deployment', NS + '-api')
    helper.require(deployment['status'].get('availableReplicas') == 3
                   and deployment['status'].get('updatedReplicas') == 3
                   and deployment['status'].get('observedGeneration') == deployment['metadata']['generation'])
    pods = json.loads(helper.run(['get', 'pods', '-n', NS, '-l',
        f'app.kubernetes.io/instance={NS},app.kubernetes.io/component=api', '-o', 'json']))['items']
    helper.require(len(pods) == 3 and {p['spec']['nodeName'] for p in pods} ==
                   {f'hetero-dev-{i}' for i in range(1, 4)})
    placements = {}
    for pod in pods:
        name = pod['metadata']['name']
        helper.require(pod['spec']['containers'][0]['image'] == IMAGE
                       and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status']['conditions']))
        command = ['exec', '-n', NS, name, '-c', 'api', '--', 'curl', '--silent', '--show-error', '--max-time', '10']
        ready = json.loads(helper.run([*command, '--fail', 'http://127.0.0.1:8080/health/ready']))
        helper.require(ready == {'status': 'ready'})
        status = helper.run([*command, '--output', '/dev/null', '--write-out', '%{http_code}',
                             'http://127.0.0.1:8080/v1/service-overview']).decode()
        helper.require(status == '401')
        placements[name] = {'node': pod['spec']['nodeName'], 'uid': pod['metadata']['uid']}
    cluster = get('cluster.postgresql.cnpg.io', 'dev-postgres')
    helper.require(cluster['status']['readyInstances'] == 3)
    primary = cluster['status']['currentPrimary']
    helper.require(primary in {f'dev-postgres-{i}' for i in range(1, 4)})
    query = """SELECT json_build_object(
      'migrations', (SELECT json_agg(json_build_object('version',version,'success',success) ORDER BY version) FROM _sqlx_migrations),
      'connections', (SELECT json_agg(json_build_object('client',a.client_addr,'tls',s.ssl))
        FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s ON a.pid=s.pid
        WHERE a.datname='heterocloud_syouyu_dev' AND a.usename='heterocloud_syouyu_dev'
          AND a.backend_type='client backend' AND a.client_addr IS NOT NULL))"""
    database = json.loads(helper.run(['exec', '-n', NS, primary, '-c', 'postgres', '--',
        'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres',
        '-d', 'heterocloud_syouyu_dev', '-c', query]))
    helper.require(database['migrations'] == [{'version': 1, 'success': True}, {'version': 2, 'success': True}])
    connections = database['connections'] or []
    helper.require(connections and all(c['tls'] is True for c in connections)
                   and {p['status']['podIP'] for p in pods}.issubset({c['client'] for c in connections}))
    print(json.dumps({'placements': placements, 'ready_checks': 3, 'unauthenticated_401_checks': 3,
                      'migrations': database['migrations'], 'application_connections_all_tls': True,
                      'postgres_ready': 3}), flush=True)


if __name__ == '__main__':
    main()
