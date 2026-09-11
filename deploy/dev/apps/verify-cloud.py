#!/usr/bin/env python3
"""DEV Cloud startup, TLS and OIDC initiation; not authenticated browser E2E."""
import hashlib
import http.client
from http.cookies import SimpleCookie
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import sys
from urllib.parse import parse_qs, urlsplit

sys.dont_write_bytecode = True
NS = 'heterocloud-dev'
HOST = 'dev.heterocloud.mizuame.app'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud:0.1.71-dev.5@sha256:70a41870b9e5c986512f2665bceb5a4d079dd7e1e0958ac36751b95e7928b9b3'


def validate_start(status, headers):
    if status != 303:
        raise ValueError('OIDC initiation did not redirect')
    url = urlsplit(headers.get('location', ''))
    query = parse_qs(url.query)
    expected = {'client_id': ['heterocloud-dev-web'], 'response_type': ['code'],
                'redirect_uri': ['https://' + HOST + '/api/v1/auth/oidc/callback'],
                'code_challenge_method': ['S256']}
    if (url.scheme != 'https' or url.netloc != 'id.' + HOST
            or url.path != '/realms/heterocloud-dev/protocol/openid-connect/auth'
            or any(query.get(k) != v for k, v in expected.items())
            or any(len(query.get(k, [])) != 1 or not query[k][0] for k in ('state', 'nonce', 'code_challenge'))):
        raise ValueError('Unexpected DEV OIDC redirect')
    jar = SimpleCookie()
    jar.load(headers.get('set-cookie', ''))
    cookie = jar.get('hc_oidc_transaction')
    if not cookie or not cookie['secure'] or not cookie['httponly'] or cookie['samesite'].lower() != 'lax':
        raise ValueError('OIDC transaction cookie is not protected')


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    ca = helper.trusted_file(Path('/var/lib/heteronetwork-dev-cloud-tls/ca.crt'), 16384)
    context = ssl.create_default_context(cadata=ca.decode())

    def get(kind, name, namespace=NS):
        return json.loads(helper.run(['get', kind, name, '-n', namespace, '-o', 'json']))

    def request(address, path):
        connection = http.client.HTTPSConnection(HOST, 8443, timeout=10, context=context)
        # Dial the selected Pod while retaining the certificate name and SNI.
        connection._create_connection = lambda *args, **kwargs: socket.create_connection((address, 8443), timeout=10)
        try:
            connection.request('GET', path, headers={'Host': HOST})
            response = connection.getresponse()
            body = response.read(1048577)
            helper.require(len(body) <= 1048576)
            return response.status, {k.lower(): v for k, v in response.getheaders()}, body
        finally:
            connection.close()

    sources = json.loads(helper.run(['get', 'pods', '-n', 'heterocloud-flow-dev', '-l',
        'app.kubernetes.io/instance=heterocloud-flow-dev,app.kubernetes.io/component=livekit', '-o', 'json']))['items']
    helper.require(len(sources) == 3)
    for pod in sources:
        helper.require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status']['conditions'])
                       and pod['spec']['containers'][0]['image'].endswith('@sha256:6f532540530d5673f4030dc5a29bde5f0d4511261d1b1e2caab28aead3529db0'))
    placements, addresses = {}, set()
    for component, suffix in [('api', ''), ('owner-console', '-owner-console'), ('worker', '-worker')]:
        deployment = get('deployment', NS + suffix)
        helper.require(deployment['status'].get('availableReplicas') == 3
                       and deployment['status'].get('updatedReplicas') == 3
                       and deployment['status'].get('observedGeneration') == deployment['metadata']['generation'])
        pods = json.loads(helper.run(['get', 'pods', '-n', NS, '-l',
            f'app.kubernetes.io/instance={NS},app.kubernetes.io/component={component}', '-o', 'json']))['items']
        helper.require(len(pods) == 3 and {p['spec']['nodeName'] for p in pods} ==
                       {f'hetero-dev-{i}' for i in range(1, 4)})
        placements[component] = []
        for pod in pods:
            helper.require(pod['spec']['containers'][0]['image'] == IMAGE
                           and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status']['conditions']))
            ip = pod['status']['podIP']
            addresses.add(ip)
            if component == 'api':
                for endpoint, expected in [('/api/v1/health/live', {'status': 'ok'}),
                                           ('/api/v1/health/ready', {'status': 'ready'})]:
                    status, _, body = request(ip, endpoint)
                    helper.require(status == 200 and json.loads(body) == expected)
                status, _, body = request(ip, '/login')
                helper.require(status == 200 and b'<html' in body and b'HeteroCloud' in body)
                status, _, _ = request(ip, '/api/v1/auth/session')
                helper.require(status == 401)
                status, headers, _ = request(ip, '/api/v1/auth/oidc/start')
                validate_start(status, headers)
            elif component == 'owner-console':
                source = next(p for p in sources if p['spec']['nodeName'] != pod['spec']['nodeName'])
                command = ['exec', '-n', 'heterocloud-flow-dev', source['metadata']['name'], '-c', 'livekit', '--',
                           'wget', '-Y', 'off', '-q', '-T', '10', '-O', '-']
                body = helper.run([*command, f'http://{ip}:21443/api/v1/health/ready'])
                helper.require(json.loads(body) == {'status': 'ready'})
            placements[component].append({'pod': pod['metadata']['name'], 'node': pod['spec']['nodeName'],
                                          'uid': pod['metadata']['uid']})
    cluster = get('cluster.postgresql.cnpg.io', 'dev-postgres')
    helper.require(cluster['status']['readyInstances'] == 3)
    primary = cluster['status']['currentPrimary']
    helper.require(primary in {f'dev-postgres-{i}' for i in range(1, 4)})
    query = """SELECT json_build_object(
      'migrations', (SELECT json_agg(json_build_object('version',version,'success',success) ORDER BY version) FROM _sqlx_migrations),
      'connections', (SELECT json_agg(json_build_object('client',a.client_addr,'tls',s.ssl))
        FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s ON a.pid=s.pid
        WHERE a.datname='heterocloud_dev' AND a.usename='heterocloud_dev'
          AND a.backend_type='client backend' AND a.client_addr IS NOT NULL))"""
    database = json.loads(helper.run(['exec', '-n', NS, primary, '-c', 'postgres', '--',
        'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'heterocloud_dev', '-c', query]))
    helper.require(database['migrations'] == [{'version': i, 'success': True} for i in range(1, 16)])
    connections = database['connections'] or []
    helper.require(connections and all(c['tls'] is True for c in connections)
                   and addresses.issubset({c['client'] for c in connections}))
    print(json.dumps({'placements': placements, 'tls_api_checks': 15, 'owner_ready_checks': 3,
                      'oidc_initiations': 3, 'migrations_successful': 15, 'application_connections_all_tls': True,
                      'owner_login_verified': False, 'browser_e2e_verified': False,
                      'worker_operations_verified': False}), flush=True)


if __name__ == '__main__':
    main()
