#!/usr/bin/env python3
"""Read-only per-replica HTTPS/OIDC discovery checks for the fixed DEV server."""
import hashlib
import http.client
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys

sys.dont_write_bytecode = True
ROOT = Path('/opt/heteronetwork-dev-identity')
ORIGIN = 'https://id.dev.heterocloud.mizuame.app'
HOST = 'id.dev.heterocloud.mizuame.app'
NAMESPACE = 'hetero-dev-identity'


def discover(address, port, context):
    connection = http.client.HTTPSConnection(HOST, port, context=context, timeout=10)
    raw = socket.create_connection((address, port), timeout=10)
    try:
        # Connect to observed DEV endpoints while retaining real SNI/hostname validation.
        connection.sock = context.wrap_socket(raw, server_hostname=HOST)
        connection.request('GET', '/realms/master/.well-known/openid-configuration', headers={'Host': HOST})
        response = connection.getresponse()
        body = response.read(131073)
        if response.status != 200 or len(body) > 131072:
            raise ValueError('DEV discovery response rejected')
        document = json.loads(body)
        issuer = ORIGIN + '/realms/master'
        if document.get('issuer') != issuer:
            raise ValueError('DEV issuer differs')
        for field, suffix in [('authorization_endpoint', '/protocol/openid-connect/auth'),
                              ('token_endpoint', '/protocol/openid-connect/token'),
                              ('jwks_uri', '/protocol/openid-connect/certs')]:
            if document.get(field) != issuer + suffix:
                raise ValueError('DEV discovery endpoint differs')
        return {'address': address, 'port': port, 'https_verified': True, 'issuer': issuer}
    finally:
        connection.close()
        raw.close()


def main():
    helper_path = ROOT / 'apply.py'
    if hashlib.sha256(helper_path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed helper')
    spec = importlib.util.spec_from_file_location('identity_apply', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    require = helper.require
    ca = helper.trusted_file(Path('/var/lib/heteronetwork-dev-identity-tls/ca.crt'), 16384)
    context = ssl.create_default_context(cadata=ca.decode())
    pods = json.loads(helper.run(['get', 'pods', '-n', NAMESPACE, '-l', 'app.kubernetes.io/name=keycloak',
                                 '-o', 'json']))['items']
    require(len(pods) == 3 and {p['spec']['nodeName'] for p in pods} == {f'hetero-dev-{i}' for i in range(1, 4)})
    results = []
    for pod in pods:
        require(not pod['metadata'].get('deletionTimestamp'))
        require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', [])))
        address = pod['status']['podIP']
        require(ipaddress.ip_address(address) in ipaddress.ip_network('172.29.0.0/16'))
        results.append({'pod': pod['metadata']['name'], 'node': pod['spec']['nodeName'],
                        **discover(address, 8443, context)})
    service = json.loads(helper.run(['get', 'service', 'dev-keycloak', '-n', NAMESPACE, '-o', 'json']))
    require(service['spec']['type'] == 'ClusterIP')
    address = service['spec']['clusterIP']
    require(ipaddress.ip_address(address) in ipaddress.ip_network('172.30.0.0/16'))
    vip = discover(address, 443, context)
    print(json.dumps({'cluster_uid': helper.UID, 'replicas': results, 'service': vip,
                      'owner_login_verified': False, 'external_dns_verified': False,
                      'failure_recovery_verified': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV Keycloak HTTPS/discovery check failed', file=sys.stderr)
        sys.exit(1)
