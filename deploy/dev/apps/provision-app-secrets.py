#!/usr/bin/env python3
"""Provision service credentials only on the identity-pinned DEV cluster.

No workload changes, credential rotation, owner creation or production imports.
Interrupted state is retained; never delete it to rerun credential generation.
"""
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import app_secrets
from database_credentials import connection_material, DATABASES

STATE = Path('/var/lib/heteronetwork-dev-app-credentials')
FOUNDATION = Path('/opt/heteronetwork-dev-identity/apply.py')


def require(value):
    if not value:
        raise ValueError('DEV application credential contract failed')


def main():
    require(len(sys.argv) == 1)
    require(hashlib.sha256(FOUNDATION.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    spec = importlib.util.spec_from_file_location('identity_apply', FOUNDATION)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    require(helper.UID == app_secrets.UID)
    # Serialise creators before checking or generating any private state.
    import fcntl
    descriptor = os.open('/var/lib', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        provision(helper)
    finally:
        os.close(descriptor)


def provision(helper):
    namespaces = (*DATABASES, 'heterocloud-flash-dev')
    for namespace in namespaces:
        raw = helper.run(['get', 'namespace', namespace, '--ignore-not-found', '-o', 'json']).strip()
        if raw:
            metadata = json.loads(raw)['metadata']
            require(not metadata.get('deletionTimestamp') and
                    metadata.get('labels', {}).get('release.heteronetwork.io/channel') == 'dev')
        else:
            require(namespace == 'heterocloud-flash-dev')
            obj = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace,
                   'labels': {'release.heteronetwork.io/channel': 'dev',
                              'app.kubernetes.io/managed-by': app_secrets.MANAGER},
                   'annotations': {'heteronetwork.dev.cluster-uid': helper.UID}}}
            helper.run(['create', '--dry-run=server', '-f', '-'], json.dumps(obj).encode())
            helper.run(['create', '-f', '-'], json.dumps(obj).encode())
    databases = {}
    for namespace in DATABASES:
        items = json.loads(helper.run(['get', 'secret', 'dev-postgres-app', 'dev-postgres-ca',
                                      '-n', namespace, '-o', 'json']))['items']
        records = {obj['metadata']['name']: obj for obj in items}
        databases[namespace] = connection_material(namespace, records['dev-postgres-app'], records['dev-postgres-ca'])
    state_created = not STATE.exists()
    if state_created:
        STATE.mkdir(mode=0o700)
        seeds = app_secrets.generate_seeds()
        app_secrets.validate_seeds(seeds)
        fd = os.open(STATE / 'seeds.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(seeds, sort_keys=True).encode())
            output.flush()
            os.fsync(output.fileno())
        for directory in (STATE, STATE.parent):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    # An incomplete existing directory/file is an error, never a reason to regenerate.
    directory_info, file_info = STATE.lstat(), (STATE / 'seeds.json').lstat()
    require(stat.S_ISDIR(directory_info.st_mode) and directory_info.st_uid == 0
            and stat.S_IMODE(directory_info.st_mode) == 0o700)
    require(stat.S_ISREG(file_info.st_mode) and file_info.st_uid == 0
            and file_info.st_nlink == 1 and stat.S_IMODE(file_info.st_mode) == 0o600)
    seeds = json.loads(helper.trusted_file(STATE / 'seeds.json', 65536))
    desired = app_secrets.build(seeds, databases)
    pending = []
    for obj in desired:
        metadata = obj['metadata']
        args = ['get', 'secret', metadata['name'], '-n', metadata['namespace'], '--ignore-not-found', '-o', 'json']
        raw = helper.run(args).strip()
        if raw:
            app_secrets.verify(json.loads(raw), obj)
        else:
            pending.append(obj)
    # Verify all existing credentials before creating any missing Secret.
    for obj in pending:
        helper.run(['create', '--dry-run=server', '-f', '-'], json.dumps(obj).encode())
    for obj in pending:
        helper.run(['create', '-f', '-'], json.dumps(obj).encode())
    for obj in desired:
        metadata = obj['metadata']
        actual = json.loads(helper.run(['get', 'secret', metadata['name'], '-n', metadata['namespace'], '-o', 'json']))
        app_secrets.verify(actual, obj)
    print(json.dumps({'verified_secrets': len(desired), 'created_secrets': len(pending),
                      'seed_state_created': state_created, 'credentials_rotated': False,
                      'workloads_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV app credentials stopped; preserve private state, no secret values emitted', file=sys.stderr)
        sys.exit(1)
