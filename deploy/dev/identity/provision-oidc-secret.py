#!/usr/bin/env python3
"""Create/verify the DEV Cloud OIDC Secret without rotating Keycloak credentials."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlencode
from uuid import UUID

sys.dont_write_bytecode = True
FOUNDATION = Path('/opt/heteronetwork-dev-identity/apply.py')
REALM_TOOLS = Path('/opt/heteronetwork-dev-realm-b4f13fa7')
NAMESPACE = 'heterocloud-dev'
NAME = 'heterocloud-dev-oidc'
MANAGER = 'hetero-dev-oidc-secret'


def require(value):
    if not value:
        raise ValueError('DEV OIDC credential contract failed')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def desired_secret(uid, client_id, value):
    require(isinstance(value, str) and 16 <= len(value.encode()) <= 4096
            and not any(ord(c) < 32 for c in value))
    require(str(UUID(client_id)) == client_id)
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
            'metadata': {'name': NAME, 'namespace': NAMESPACE,
                         'labels': {'app.kubernetes.io/managed-by': MANAGER},
                         'annotations': {'heteronetwork.dev.cluster-uid': uid,
                                         'heteronetwork.dev.oidc-client-id': client_id}},
            'data': {'client-secret': base64.b64encode(value.encode()).decode()}}


def verify_secret(actual, desired):
    require(actual.get('apiVersion') == 'v1' and actual.get('kind') == 'Secret'
            and actual.get('type') == 'Opaque' and actual.get('data') == desired['data'])
    metadata = actual.get('metadata', {})
    require(not metadata.get('deletionTimestamp'))
    for key in ('name', 'namespace'):
        require(metadata.get(key) == desired['metadata'][key])
    for key in ('labels', 'annotations'):
        require(all(metadata.get(key, {}).get(k) == v for k, v in desired['metadata'][key].items()))


def main():
    require(len(sys.argv) == 1)
    require(hashlib.sha256(FOUNDATION.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    helper = load('identity_apply', FOUNDATION)
    helper.guard()
    source = REALM_TOOLS / 'configure-realm.py'
    require(hashlib.sha256(helper.trusted_file(source, 32768)).hexdigest() ==
            'd1b20c180f8cdc49605b83d6b96ed25f0bbef378e14b1e287a6715a38d10e57c')
    realm = load('realm_tools', source)
    desired_bytes = helper.trusted_file(REALM_TOOLS / 'realm.json', 32768)
    require(hashlib.sha256(desired_bytes).hexdigest() ==
            '77b1c2ffd870e5d369b432a490bf82ea71471ef43263e42c4e515d22cf06bd03')
    desired = json.loads(desired_bytes)
    service = json.loads(helper.run(['get', 'service', 'dev-keycloak', '-n', 'hetero-dev-identity', '-o', 'json']))
    address = service['spec']['clusterIP']
    require(service['spec']['type'] == 'ClusterIP' and ipaddress.ip_address(address) in ipaddress.ip_network('172.30.0.0/16'))
    state = Path('/var/lib/heteronetwork-dev-identity-tls')
    api = realm.Api(address, helper.trusted_file(state / 'ca.crt', 16384))
    credentials = json.loads(helper.trusted_file(state / 'bootstrap.json', 4096))
    require(credentials['username'] == 'dev-bootstrap')
    status, token = api.request('POST', '/realms/master/protocol/openid-connect/token',
                               {'grant_type': 'password', 'client_id': 'admin-cli', **credentials}, form=True)
    require(status == 200 and isinstance(token.get('access_token'), str))
    api.token = token['access_token']
    try:
        realm.configure(api, desired, helper.UID)
        base = '/admin/realms/heterocloud-dev/clients'
        status, clients = api.request('GET', base + '?' + urlencode({'clientId': 'heterocloud-dev-web'}), authenticated=True)
        require(status == 200 and len(clients) == 1 and clients[0]['publicClient'] is False)
        client_id = clients[0]['id']
        require(str(UUID(client_id)) == client_id)
        status, credential = api.request('GET', base + '/' + client_id + '/client-secret', authenticated=True)
        require(status == 200 and credential.get('type') == 'secret')
        desired = desired_secret(helper.UID, client_id, credential['value'])
        args = ['get', 'secret', NAME, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json']
        existing = helper.run(args).strip()
        created = not existing
        if existing:
            verify_secret(json.loads(existing), desired)
        else:
            payload = json.dumps(desired).encode()
            helper.run(['create', '--dry-run=server', '-f', '-'], payload)
            helper.run(['create', '-f', '-'], payload)
        verify_secret(json.loads(helper.run(args)), desired)
        print(json.dumps({'namespace': NAMESPACE, 'secret': NAME, 'created': created,
                          'credential_matches_keycloak': True, 'credential_rotated': False}))
    finally:
        api.token = None


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV OIDC Secret provisioning stopped; no credential values emitted', file=sys.stderr)
        sys.exit(1)
