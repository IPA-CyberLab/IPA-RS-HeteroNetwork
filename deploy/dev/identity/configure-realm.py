#!/usr/bin/env python3
"""Create or verify the fixed DEV realm; never import or manufacture owner users."""
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import urlencode

sys.dont_write_bytecode = True
ROOT = Path('/opt/heteronetwork-dev-identity')
HOST = 'id.dev.heterocloud.mizuame.app'
REALM = 'heterocloud-dev'
MARKER = 'heteronetwork.dev.cluster-uid'


def require(value):
    if not value:
        raise ValueError('DEV realm contract failed')


def matches(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and matches(actual[key], value)
                                               for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and sorted(actual) == sorted(expected)
    return type(actual) is type(expected) and actual == expected


class Api:
    def __init__(self, address, ca):
        self.address = address
        self.context = ssl.create_default_context(cadata=ca.decode())
        self.token = None

    def request(self, method, path, data=None, form=False, authenticated=False):
        require(path.startswith(('/admin/realms', '/realms/')) and '\r' not in path and '\n' not in path)
        headers = {'Host': HOST}
        body = None
        if data is not None:
            body = urlencode(data).encode() if form else json.dumps(data).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        if authenticated:
            require(isinstance(self.token, str) and self.token)
            headers['Authorization'] = 'Bearer ' + self.token
        connection = http.client.HTTPSConnection(HOST, 443, context=self.context, timeout=15)
        raw = socket.create_connection((self.address, 443), timeout=15)
        try:
            connection.sock = self.context.wrap_socket(raw, server_hostname=HOST)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(524289)
            require(len(payload) <= 524288)
            return response.status, json.loads(payload) if payload else None
        finally:
            connection.close()
            raw.close()


def configure(api, desired, uid):
    base = '/admin/realms/' + REALM
    status, current = api.request('GET', base, authenticated=True)
    created = status == 404
    if created:
        status, _ = api.request('POST', '/admin/realms', desired, authenticated=True)
        require(status == 201)
        status, current = api.request('GET', base, authenticated=True)
    require(status == 200 and current.get('attributes', {}).get(MARKER) == uid)
    require(matches(current, {key: value for key, value in desired.items() if key != 'clients'}))
    verified = []
    for expected in desired['clients']:
        status, clients = api.request('GET', base + '/clients?' + urlencode({'clientId': expected['clientId']}),
                                      authenticated=True)
        require(status == 200 and len(clients) == 1)
        client = clients[0]
        require(client.get('attributes', {}).get(MARKER) == uid)
        require(matches(client, expected))
        verified.append(client['clientId'])
    return {'created': created, 'realm': REALM, 'verified_clients': verified}


def main():
    require(len(sys.argv) == 1)
    helper_path = ROOT / 'apply.py'
    require(hashlib.sha256(helper_path.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    spec = importlib.util.spec_from_file_location('identity_apply', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    desired_raw = helper.trusted_file(ROOT / 'realm.json', 32768)
    require(hashlib.sha256(desired_raw).hexdigest() ==
            '6cdddc89e98e6a0bbbc44a29d42efa5ad93a117590ac97b909cdb38a5778e5ba')
    desired = json.loads(desired_raw)
    require(desired['realm'] == REALM and desired['attributes'][MARKER] == helper.UID)
    service = json.loads(helper.run(['get', 'service', 'dev-keycloak', '-n', 'hetero-dev-identity', '-o', 'json']))
    address = service['spec']['clusterIP']
    require(service['spec']['type'] == 'ClusterIP' and
            ipaddress.ip_address(address) in ipaddress.ip_network('172.30.0.0/16'))
    state = Path('/var/lib/heteronetwork-dev-identity-tls')
    api = Api(address, helper.trusted_file(state / 'ca.crt', 16384))
    credentials = json.loads(helper.trusted_file(state / 'bootstrap.json', 4096))
    require(credentials['username'] == 'dev-bootstrap')
    status, token = api.request('POST', '/realms/master/protocol/openid-connect/token',
                               {'grant_type': 'password', 'client_id': 'admin-cli', **credentials}, form=True)
    require(status == 200 and isinstance(token.get('access_token'), str))
    api.token = token['access_token']
    try:
        result = configure(api, desired, helper.UID)
        status, discovery = api.request('GET', '/realms/' + REALM + '/.well-known/openid-configuration')
        issuer = 'https://' + HOST + '/realms/' + REALM
        require(status == 200 and discovery['issuer'] == issuer)
        require(discovery['device_authorization_endpoint'] == issuer + '/protocol/openid-connect/auth/device')
        status, device = api.request('POST', '/realms/' + REALM + '/protocol/openid-connect/auth/device',
                                    {'client_id': 'heteronetwork-dev-web', 'scope': 'openid profile email'}, form=True)
        require(status == 200 and device.get('device_code') and device.get('user_code'))
        require(device['verification_uri'] == issuer + '/device')
        print(json.dumps({**result, 'issuer': issuer, 'device_authorization_started': True,
                          'owner_created': False, 'owner_authenticated': False}))
    finally:
        api.token = None


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV realm setup stopped; preserve existing realm and inspect contract', file=sys.stderr)
        sys.exit(1)
