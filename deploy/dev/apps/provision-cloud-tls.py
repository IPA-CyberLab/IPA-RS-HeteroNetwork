#!/usr/bin/env python3
"""Issue/verify isolated DEV Cloud TLS Secrets; no serving workload changes."""
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
import app_secrets
import cloud_tls

STATE = Path('/var/lib/heteronetwork-dev-cloud-tls')
CA_STATE = Path('/var/lib/heteronetwork-dev-identity-tls')
FILES = {'tls.crt', 'tls.key', 'ca.crt'}


def require(value):
    if not value:
        raise ValueError('DEV Cloud TLS contract failed')


def write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def material(helper):
    record = json.loads(helper.trusted_file(CA_STATE / 'manifest.json', 16384))
    require(record['cluster_uid'] == helper.UID and record['origin'] == 'https://id.dev.heterocloud.mizuame.app')
    ca = {}
    for name in ('ca.crt', 'ca.key'):
        require(stat.S_IMODE((CA_STATE / name).lstat().st_mode) == 0o600)
        ca[name] = helper.trusted_file(CA_STATE / name, 16384)
        require(hashlib.sha256(ca[name]).hexdigest() == record['files'][name])
    ca_digest = hashlib.sha256(ca['ca.crt']).hexdigest()
    fresh = not STATE.exists()
    if fresh:
        STATE.mkdir(mode=0o700)
        values = cloud_tls.generate(ca['ca.crt'], ca['ca.key'])
        cloud_tls.verify(values, ca['ca.crt'])
        for name, data in values.items():
            write(STATE / name, data)
        manifest = {'cluster_uid': helper.UID, 'ca_sha256': ca_digest,
                    'files': {name: hashlib.sha256(data).hexdigest() for name, data in values.items()}}
        write(STATE / 'manifest.json', json.dumps(manifest).encode())
        for directory in (STATE, STATE.parent):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    require(stat.S_IMODE(STATE.lstat().st_mode) == 0o700)
    manifest = json.loads(helper.trusted_file(STATE / 'manifest.json', 16384))
    require(manifest['cluster_uid'] == helper.UID and manifest['ca_sha256'] == ca_digest
            and set(manifest['files']) == FILES)
    values = {}
    for name in FILES:
        require(stat.S_IMODE((STATE / name).lstat().st_mode) == 0o600)
        values[name] = helper.trusted_file(STATE / name, 16384)
        require(hashlib.sha256(values[name]).hexdigest() == manifest['files'][name])
    cloud_tls.verify(values, ca['ca.crt'])
    return values, fresh


def main():
    require(len(sys.argv) == 1)
    foundation = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(foundation.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    spec = importlib.util.spec_from_file_location('identity_apply', foundation)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    require(helper.UID == app_secrets.UID)
    fd = os.open('/var/lib', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        values, fresh = material(helper)
        desired = []
        for name, kind, fields in (('heterocloud-dev-tls', 'kubernetes.io/tls', ('tls.crt', 'tls.key')),
                                   ('heterocloud-dev-identity-ca', 'Opaque', ('ca.crt',))):
            desired.append({'apiVersion': 'v1', 'kind': 'Secret', 'type': kind,
                'metadata': {'namespace': 'heterocloud-dev', 'name': name,
                    'labels': {'app.kubernetes.io/managed-by': 'hetero-dev-cloud-tls'},
                    'annotations': {'heteronetwork.dev.cluster-uid': helper.UID}},
                'data': {field: base64.b64encode(values[field]).decode() for field in fields}})
        pending = []
        for obj in desired:
            raw = helper.run(['get', 'secret', obj['metadata']['name'], '-n', 'heterocloud-dev',
                              '--ignore-not-found', '-o', 'json']).strip()
            if raw:
                app_secrets.verify(json.loads(raw), obj)
            else:
                pending.append(obj)
        for obj in pending:
            helper.run(['create', '--dry-run=server', '-f', '-'], json.dumps(obj).encode())
        for obj in pending:
            helper.run(['create', '-f', '-'], json.dumps(obj).encode())
        for obj in desired:
            actual = json.loads(helper.run(['get', 'secret', obj['metadata']['name'], '-n', 'heterocloud-dev', '-o', 'json']))
            app_secrets.verify(actual, obj)
        print(json.dumps({'created_secrets': len(pending), 'verified_secrets': 2,
                          'certificate_created': fresh, 'workloads_changed': False}))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV Cloud TLS stopped; preserve private state, no keys emitted', file=sys.stderr)
        sys.exit(1)
