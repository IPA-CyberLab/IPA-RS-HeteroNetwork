#!/usr/bin/env python3
"""DEV Flow startup checks; not WebRTC, TURN allocation or public ingress E2E."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys
import urllib.request

sys.dont_write_bytecode = True
NS = 'heterocloud-flow-dev'
PORTS = {'api': 8080, 'matchmaker': 8081, 'signaling': 8082, 'livekit': 7880, 'coturn': 13478}


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get(kind, name):
        return json.loads(helper.run(['get', kind, name, '-n', NS, '-o', 'json']))

    results = {}
    db_clients = set()
    source_namespace = NS
    sources = json.loads(helper.run(['get', 'pods', '-n', source_namespace, '-l',
        f'app.kubernetes.io/instance={NS},app.kubernetes.io/component=livekit', '-o', 'json']))['items']
    helper.require(len(sources) == 3)
    for source in sources:
        helper.require(not source['metadata'].get('deletionTimestamp')
                       and any(c['type'] == 'Ready' and c['status'] == 'True' for c in source['status']['conditions'])
                       and any(c['name'] == 'livekit' and c['image'].endswith('@sha256:6f532540530d5673f4030dc5a29bde5f0d4511261d1b1e2caab28aead3529db0')
                               for c in source['spec']['containers']))
    for component, port in PORTS.items():
        deployment = get('deployment', NS + '-' + component)
        helper.require(deployment['status'].get('availableReplicas') == 3
                       and deployment['status'].get('updatedReplicas') == 3
                       and deployment['status'].get('observedGeneration') == deployment['metadata']['generation'])
        pods = json.loads(helper.run(['get', 'pods', '-n', NS, '-l',
            f'app.kubernetes.io/instance={NS},app.kubernetes.io/component={component}', '-o', 'json']))['items']
        helper.require(len(pods) == 3 and {p['spec']['nodeName'] for p in pods} ==
                       {f'hetero-dev-{i}' for i in range(1, 4)})
        results[component] = []
        for pod in pods:
            helper.require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status']['conditions']))
            address = pod['status']['podIP']
            if component == 'coturn':
                helper.require(address in {'10.251.0.1', '10.251.0.2', '10.251.0.3'})
                with socket.create_connection((address, port), timeout=5):
                    pass
            else:
                suffix = '/' if component == 'livekit' else '/health/ready'
                url = f'http://{address}:{port}{suffix}'
                if component == 'matchmaker':
                    # Its health port admits cluster pods, not remote node hosts.
                    source = next(p for p in sources if p['spec']['nodeName'] != pod['spec']['nodeName'])
                    body = helper.run(['exec', '-n', source_namespace, source['metadata']['name'], '-c', 'livekit', '--',
                        'wget', '-Y', 'off', '-q', '-T', '10', '-O', '-', url])
                else:
                    with opener.open(url, timeout=10) as response:
                        helper.require(response.status == 200)
                        body = response.read(4097)
                helper.require(len(body) <= 4096)
                if component != 'livekit':
                    helper.require(json.loads(body) == {'status': 'ready'})
                    db_clients.add(address)
            results[component].append({'pod': pod['metadata']['name'], 'node': pod['spec']['nodeName'],
                                       'uid': pod['metadata']['uid']})
    cluster = get('cluster.postgresql.cnpg.io', 'dev-postgres')
    helper.require(cluster['status']['readyInstances'] == 3)
    primary = cluster['status']['currentPrimary']
    helper.require(primary in {f'dev-postgres-{i}' for i in range(1, 4)})
    query = """SELECT json_build_object(
      'migrations', (SELECT json_agg(json_build_object('version',version,'success',success) ORDER BY version) FROM _sqlx_migrations),
      'connections', (SELECT json_agg(json_build_object('client',a.client_addr,'tls',s.ssl))
        FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s ON a.pid=s.pid
        WHERE a.datname='heterocloud_flow_dev' AND a.usename='heterocloud_flow_dev'
          AND a.backend_type='client backend' AND a.client_addr IS NOT NULL))"""
    database = json.loads(helper.run(['exec', '-n', NS, primary, '-c', 'postgres', '--',
        'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'heterocloud_flow_dev', '-c', query]))
    helper.require(database['migrations'] == [{'version': i, 'success': True} for i in range(1, 7)])
    connections = database['connections'] or []
    helper.require(connections and all(c['tls'] is True for c in connections)
                   and db_clients.issubset({c['client'] for c in connections}))
    print(json.dumps({'components': results, 'http_checks': 12, 'turn_tcp_listeners': 3,
                      'migrations_successful': 6, 'application_connections_all_tls': True,
                      'turn_allocation_tested': False, 'webrtc_tested': False}), flush=True)


if __name__ == '__main__':
    main()
