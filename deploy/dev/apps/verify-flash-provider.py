#!/usr/bin/env python3
"""Create a private DEV Flash tenant through the real signed provider API."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NS = 'heterocloud-flash-dev'
WORK = NS + '-workloads'
SERVICE = 'da8841e7-5621-4a8f-8730-8754cb321c79'
ORG = 'b6850899-40d1-4265-9b3a-42b9c2e30bdb'
PROJECT = '84d36f8c-19cb-4476-98cb-bd7a47e29fd0'
SUBJECT = 'e5fb01bf-32e1-4397-a25b-84287a433e48'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit@sha256:6f532540530d5673f4030dc5a29bde5f0d4511261d1b1e2caab28aead3529db0'


def workload():
    return {'region': 'heteronet-global', 'image': IMAGE, 'replicas': 1, 'cpu_millis': 100,
            'memory_mib': 128, 'ephemeral_storage_gib': 2, 'ports': [],
            'exposure': {'type': 'internal', 'traffic_mode': 'forwarded'},
            'egress': {'mode': 'disabled'}, 'env': {},
            'command': ['sh', '-ec'], 'args': ['dmesg | grep -q "Starting gVisor"; exec sleep 3600'],
            'metadata': {'dev_probe': 'signed-provider-rwx'}}


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=')


def main():
    foundation = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(foundation.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', foundation)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    h.guard()

    def get(kind, name=None, namespace=WORK):
        raw = h.run(['get', kind, *([name] if name else []), '-n', namespace, '--ignore-not-found', '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    name = 'flash-' + SERVICE
    h.require(get('flashservices.flash.heterocloud.io', name) is None)
    deployment = get('deployment', NS + '-controller', NS)
    env = {e['name']: e.get('value') for e in deployment['spec']['template']['spec']['containers'][0]['env']}
    h.require(env['FLASH_PERSISTENT_STORAGE_CLASS'] == 'dev-flash-rwx')
    secret = get('secret', 'heterocloud-dev-provider-signing', 'heterocloud-dev')
    h.require(secret['metadata']['annotations']['heteronetwork.dev.cluster-uid'] ==
              'a39281cb-d273-4c5f-b7a7-fca722fb417b')
    key = serialization.load_pem_private_key(base64.b64decode(secret['data']['ed25519-private.pem']), password=None)
    h.require(isinstance(key, Ed25519PrivateKey))
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    configured = json.loads(base64.b64decode(get('secret', NS + '-provider-auth', NS)['data']['provider-public-keys.json']))
    h.require(configured == {'heterocloud-dev-provider-1': public})
    service = get('service', NS + '-api', NS)
    address = service['spec']['clusterIP']
    h.require(ipaddress.ip_address(address) in ipaddress.ip_network('172.30.0.0/16')
              and service['spec']['type'] == 'ClusterIP' and len(service['spec']['ports']) == 1)
    port = service['spec']['ports'][0]['port']
    base = f'http://{address}:{port}/internal/v1/service-instances/{SERVICE}'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(method, action, generation=1, body=None, suffix=''):
        now = int(time.time())
        claims = {'iss': 'heterocloud-dev', 'aud': 'heterocloud-flash-dev', 'sub': SUBJECT,
                  'organization_id': ORG, 'project_id': PROJECT, 'service_instance_id': SERVICE,
                  'action': action, 'generation': generation, 'jti': str(uuid.uuid4()),
                  'iat': now, 'nbf': now - 5, 'exp': now + 60}
        header = {'alg': 'EdDSA', 'typ': 'JWT', 'kid': 'heterocloud-dev-provider-1'}
        payload = b'.'.join(encoded(json.dumps(v, separators=(',', ':')).encode()) for v in (header, claims))
        token = (payload + b'.' + encoded(key.sign(payload))).decode()
        req = urllib.request.Request(base + suffix, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=15) as response:
                return response.status, response.read(65537)
        except urllib.error.HTTPError as error:
            return error.code, error.read(65537)

    code, _ = request('PUT', 'service-instance.reconcile', body={'generation': 1, 'name': 'DEV signed storage check', 'spec': workload()})
    h.require(code in (200, 202, 503))
    actual = get('flashservices.flash.heterocloud.io', name)
    h.require(actual and actual['spec']['organization_id'] == ORG and actual['spec']['project_id'] == PROJECT
              and actual['spec']['service_instance_id'] == SERVICE)
    print(json.dumps({'created_through_provider': True, 'service_id': SERVICE, 'initial_http_status': code}), flush=True)
    deadline = time.monotonic() + 360
    while True:
        code, raw = request('GET', 'flash.status.get', suffix='?generation=1')
        if code == 200:
            status = json.loads(raw)
            if status.get('phase') == 'ready':
                h.require(status['runtime_class'] == 'gvisor')
                break
            if status.get('phase') == 'error':
                raise ValueError('DEV Flash provisioning failed: ' + json.dumps(status))
        h.require(code in (200, 503) and time.monotonic() < deadline)
        time.sleep(5)
    code, raw = request('GET', 'flash.containers.list', suffix='/containers?generation=1')
    h.require(code == 200)
    print(json.dumps({'provider_status_ready': True, 'container_list': json.loads(raw),
                      'service_id': SERVICE, 'service_retained_for_exec_update_checks': True,
                      'delete_verified': False, 'exec_verified': False}), flush=True)


if __name__ == '__main__':
    main()
