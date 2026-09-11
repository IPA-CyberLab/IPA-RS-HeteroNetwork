#!/usr/bin/env python3
"""Create a private DEV Flash tenant through the real signed provider API."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid
import sys

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
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--exercise-retained', action='store_true')
    mode.add_argument('--verify-deleted', action='store_true')
    parser.add_argument('--websocket-wheel', type=Path)
    args = parser.parse_args()
    foundation = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(foundation.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', foundation)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    h.guard()

    def get(kind, name=None, namespace=WORK):
        raw = h.run(['get', kind, *([name, '--ignore-not-found'] if name else []), '-n', namespace, '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    name = 'flash-' + SERVICE
    retained = get('flashservices.flash.heterocloud.io', name)
    generation = retained['spec']['desired_generation'] if args.exercise_retained and retained else 1
    if args.exercise_retained:
        h.require(retained and retained['metadata']['uid'] == 'dd74ad7d-3ba3-43c2-9fa0-888f3b68dea6'
                  and generation in (1, 2)
                  and retained['spec']['organization_id'] == ORG and retained['spec']['project_id'] == PROJECT
                  and retained['spec']['service_instance_id'] == SERVICE
                  and not retained['metadata'].get('deletionTimestamp'))
        expected_workload = workload()
        if generation == 2:
            expected_workload['env'] = {'DEV_CHECK_GENERATION': '2'}
        for field in ('image', 'replicas', 'cpu_millis', 'memory_mib', 'ephemeral_storage_gib', 'ports',
                      'command', 'args', 'metadata', 'env'):
            h.require(retained['spec']['workload'][field] == expected_workload[field])
        h.require(args.websocket_wheel and hashlib.sha256(h.trusted_file(args.websocket_wheel, 131072)).hexdigest()
                  == 'af248a825037ef591efbf6ed20cc5faa03d3b47b9e5a2230a529eeee1c1fc3ef')
        sys.path.insert(0, str(args.websocket_wheel))
    else:
        h.require(retained is None)
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

    def token(action, generation):
        now = int(time.time())
        claims = {'iss': 'heterocloud-dev', 'aud': 'heterocloud-flash-dev', 'sub': SUBJECT,
                  'organization_id': ORG, 'project_id': PROJECT, 'service_instance_id': SERVICE,
                  'action': action, 'generation': generation, 'jti': str(uuid.uuid4()),
                  'iat': now, 'nbf': now - 5, 'exp': now + 60}
        header = {'alg': 'EdDSA', 'typ': 'JWT', 'kid': 'heterocloud-dev-provider-1'}
        payload = b'.'.join(encoded(json.dumps(v, separators=(',', ':')).encode()) for v in (header, claims))
        return (payload + b'.' + encoded(key.sign(payload))).decode()

    def request(method, action, generation=1, body=None, suffix=''):
        req = urllib.request.Request(base + suffix, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Authorization': 'Bearer ' + token(action, generation), 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=15) as response:
                return response.status, response.read(65537)
        except urllib.error.HTTPError as error:
            return error.code, error.read(65537)

    if args.verify_deleted:
        h.require(retained is None and get('pvc', name + '-home') is None)
        h.require(not any(p['metadata'].get('labels', {}).get('flash.heterocloud.io/instance') == SERVICE
                          for p in get('pods')['items']))
        code, _ = request('DELETE', 'service-instance.delete', generation=3, suffix='?generation=3')
        h.require(code == 202)
        h.guard()
        print(json.dumps({'service_pods_pvc_deleted': True, 'repeat_delete_accepted': True,
                          'service_id': SERVICE, 'retained_pv_cleanup_verified': False}), flush=True)
        return

    code = None
    if not args.exercise_retained:
        code, _ = request('PUT', 'service-instance.reconcile', body={'generation': 1, 'name': 'DEV signed storage check', 'spec': workload()})
        h.require(code in (200, 202, 503))
    actual = get('flashservices.flash.heterocloud.io', name)
    h.require(actual and actual['spec']['organization_id'] == ORG and actual['spec']['project_id'] == PROJECT
              and actual['spec']['service_instance_id'] == SERVICE)
    print(json.dumps({'created_through_provider': True, 'service_id': SERVICE, 'initial_http_status': code}), flush=True)
    deadline = time.monotonic() + 360
    while True:
        code, raw = request('GET', 'flash.status.get', generation=generation, suffix=f'?generation={generation}')
        if code == 200:
            status = json.loads(raw)
            if status.get('phase') == 'ready':
                h.require(status['runtime_class'] == 'gvisor')
                break
            if status.get('phase') == 'error':
                raise ValueError('DEV Flash provisioning failed: ' + json.dumps(status))
        h.require(code in (200, 503) and time.monotonic() < deadline)
        time.sleep(5)
    code, raw = request('GET', 'flash.containers.list', generation=generation, suffix=f'/containers?generation={generation}')
    h.require(code == 200)
    print(json.dumps({'provider_status_ready': True, 'container_list': json.loads(raw),
                      'service_id': SERVICE, 'service_retained_for_exec_update_checks': True,
                      'delete_verified': False, 'exec_verified': False}), flush=True)
    if not args.exercise_retained:
        return
    import websocket

    def shell(pod, generation, command, expected):
        url = base.replace('http:', 'ws:', 1) + '/exec?' + urllib.parse.urlencode({'generation': generation, 'pod': pod})
        ws = websocket.create_connection(url, header={'Authorization': 'Bearer ' + token('flash.exec', generation)},
                                         timeout=15, http_no_proxy=[address], redirect_limit=0)
        try:
            ws.send(json.dumps({'type': 'resize', 'cols': 100, 'rows': 30}))
            # Split the marker in the command so PTY echo cannot satisfy the check.
            marker = uuid.uuid4().hex
            ws.send_binary(('stty -echo; printf "\\nREADY_%s\\n" ' + marker + '\n').encode())

            def receive(needle):
                output = b''
                deadline = time.monotonic() + 45
                while needle not in output:
                    h.require(time.monotonic() < deadline and len(output) < 1048576)
                    chunk = ws.recv()
                    h.require(isinstance(chunk, bytes) and chunk)
                    output += chunk

            receive(('READY_' + marker).encode())
            ws.send_binary(command.encode() + b'\n')
            receive(expected)
        finally:
            ws.close()

    items = json.loads(raw)['items']
    h.require(len(items) == 1 and items[0]['ready'])
    old_pod = get('pod', items[0]['name'])
    pvc = get('pvc', name + '-home')
    h.require(pvc['spec']['storageClassName'] == 'dev-flash-rwx' and pvc['status']['phase'] == 'Bound')
    value = uuid.uuid4().hex
    shell(items[0]['name'], generation,
          'printf %s ' + value + ' > /root/dev-provider-check; sync; printf "WRITE_%s\\n" OK', b'WRITE_OK')
    shell(items[0]['name'], generation, 'cat /root/dev-provider-check', value.encode())
    print(json.dumps({'websocket_write_and_read': True, 'generation': generation}), flush=True)
    updated = workload()
    next_generation = generation + 1
    updated['env'] = {'DEV_CHECK_GENERATION': str(next_generation)}
    code, _ = request('PUT', 'service-instance.reconcile', generation=next_generation,
                      body={'generation': next_generation, 'name': 'DEV signed storage check', 'spec': updated})
    h.require(code in (200, 202, 503))
    deadline = time.monotonic() + 240
    while True:
        # Status returns operation-in-progress until the requested generation is observed.
        code, _ = request('GET', 'flash.status.get', generation=next_generation,
                          suffix=f'?generation={next_generation}')
        h.require(code in (200, 409, 503) and time.monotonic() < deadline)
        if code != 200:
            time.sleep(5)
            continue
        code, raw = request('GET', 'flash.containers.list', generation=next_generation,
                            suffix=f'/containers?generation={next_generation}')
        if code == 200:
            candidates = [p for p in json.loads(raw)['items'] if p['ready'] and p['name'] != old_pod['metadata']['name']]
            if len(candidates) == 1:
                new_pod = get('pod', candidates[0]['name'])
                if any(e['name'] == 'DEV_CHECK_GENERATION' and e.get('value') == str(next_generation)
                       for e in new_pod['spec']['containers'][0]['env']):
                    break
        h.require(code in (200, 409, 503) and time.monotonic() < deadline)
        time.sleep(5)
    h.require(new_pod['metadata']['uid'] != old_pod['metadata']['uid']
              and get('pvc', name + '-home')['metadata']['uid'] == pvc['metadata']['uid'])
    shell(new_pod['metadata']['name'], next_generation, 'cat /root/dev-provider-check', value.encode())
    print(json.dumps({'replacement_data_matched': True, 'generation': next_generation}), flush=True)
    code, _ = request('DELETE', 'service-instance.delete', generation=next_generation, suffix=f'?generation={next_generation}')
    h.require(code in (202, 503))
    deadline = time.monotonic() + 180
    while True:
        remaining = get('pods')['items']
        owned = [p for p in remaining if p['metadata'].get('labels', {}).get('flash.heterocloud.io/instance') == SERVICE]
        if get('flashservices.flash.heterocloud.io', name) is None and not owned and get('pvc', name + '-home') is None:
            break
        h.require(time.monotonic() < deadline)
        time.sleep(5)
    code, _ = request('DELETE', 'service-instance.delete', generation=next_generation, suffix=f'?generation={next_generation}')
    h.require(code == 202)
    h.guard()
    print(json.dumps({'exec_websocket_checks': 3, 'generation_update': next_generation, 'replacement_data_matched': True,
                      'service_pods_pvc_deleted': True, 'repeat_delete_accepted': True,
                      'retained_pv': pvc['spec']['volumeName'], 'browser_verified': False,
                      'node_failure_ha_verified': False}), flush=True)


if __name__ == '__main__':
    main()
