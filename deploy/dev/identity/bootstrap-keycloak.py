#!/usr/bin/env python3
"""Bootstrap the fixed DEV Keycloak server, never production users or owner pins."""
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path('/opt/heteronetwork-dev-identity')
STATE = Path('/var/lib/heteronetwork-dev-identity-tls')
ORIGIN = 'https://id.dev.heterocloud.mizuame.app'
HOST = 'id.dev.heterocloud.mizuame.app'
BUNDLE_SHA = '173b43147ae732f39af530c41f1bc0525710b9073669bb4d6cbda958d477c25d'
HELPER_SHA = '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006'
NAMESPACE = 'hetero-dev-identity'
FILES = {'ca.key', 'ca.crt', 'tls.key', 'tls.csr', 'tls.crt', 'extensions.cnf', 'bootstrap.json'}


def require(value):
    if not value:
        raise ValueError('DEV Keycloak prerequisite failed')


def protected(path, directory=False):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o077)
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    if not directory:
        require(info.st_size <= 131072)


def write(name, raw):
    fd = os.open(STATE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def openssl(*args):
    return subprocess.run(['/usr/bin/openssl', *args], cwd=STATE, check=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=60, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}).stdout


def material(uid):
    marker = STATE / 'manifest.json'
    if not marker.exists():
        # Partial generation is preserved for inspection, never silently replaced.
        require(not list(STATE.iterdir()))
        write('extensions.cnf', ('basicConstraints=critical,CA:FALSE\n'
              'keyUsage=critical,digitalSignature,keyEncipherment\n'
              'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + HOST + '\n').encode())
        openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
                '-keyout', 'ca.key', '-out', 'ca.crt', '-subj', '/CN=HeteroNetwork isolated DEV CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256',
                '-keyout', 'tls.key', '-out', 'tls.csr', '-subj', '/CN=' + HOST)
        openssl('x509', '-req', '-in', 'tls.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-set_serial', '0x' + secrets.token_hex(16), '-days', '30', '-sha256',
                '-extfile', 'extensions.cnf', '-out', 'tls.crt')
        write('bootstrap.json', json.dumps({'username': 'dev-bootstrap',
                                           'password': secrets.token_urlsafe(48)}).encode())
        hashes = {}
        for name in FILES:
            protected(STATE / name)
            hashes[name] = hashlib.sha256((STATE / name).read_bytes()).hexdigest()
        write('manifest.json', json.dumps({'cluster_uid': uid, 'origin': ORIGIN, 'files': hashes}).encode())
    protected(marker)
    record = json.loads(marker.read_bytes())
    require(record['cluster_uid'] == uid and record['origin'] == ORIGIN and set(record['files']) == FILES)
    for name, digest in record['files'].items():
        protected(STATE / name)
        require(hashlib.sha256((STATE / name).read_bytes()).hexdigest() == digest)
    openssl('verify', '-CAfile', 'ca.crt', '-verify_hostname', HOST, 'tls.crt')
    openssl('x509', '-in', 'tls.crt', '-checkend', '86400', '-noout')
    require(openssl('x509', '-in', 'tls.crt', '-pubkey', '-noout') ==
            openssl('pkey', '-in', 'tls.key', '-pubout'))
    credentials = json.loads((STATE / 'bootstrap.json').read_bytes())
    require(credentials['username'] == 'dev-bootstrap' and len(credentials['password']) == 64)
    return credentials


def ensure_secret(helper, name, kind, data):
    encoded = {key: base64.b64encode(value).decode() for key, value in data.items()}
    existing = helper.run(['get', 'secret', name, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json'])
    if existing.strip():
        current = json.loads(existing)
        require(current['type'] == kind and current['data'] == encoded)
        require(current['metadata'].get('annotations', {}).get('heteronetwork.dev/cluster-uid') == helper.UID)
        return
    document = {'apiVersion': 'v1', 'kind': 'Secret', 'type': kind,
                'metadata': {'name': name, 'namespace': NAMESPACE,
                             'annotations': {'heteronetwork.dev/cluster-uid': helper.UID}}, 'data': encoded}
    # Secret bytes travel through stdin, never arguments or command output.
    helper.run(['create', '-f', '-'], json.dumps(document).encode())


def main():
    require(len(sys.argv) == 1 and os.getuid() == 0 and os.geteuid() == 0)
    os.umask(0o077)
    helper_path = ROOT / 'apply.py'
    protected(helper_path)
    require(hashlib.sha256(helper_path.read_bytes()).hexdigest() == HELPER_SHA)
    spec = importlib.util.spec_from_file_location('identity_apply', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    bundle_path = ROOT / 'keycloak.json'
    protected(bundle_path)
    raw = bundle_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == BUNDLE_SHA)
    database = json.loads(helper.run(['get', 'cluster.postgresql.cnpg.io', 'dev-identity-postgres',
                                     '-n', NAMESPACE, '-o', 'json']))
    require(database['status'].get('readyInstances') == 3)
    helper.run(['apply', '--server-side', '--dry-run=server', '--field-manager=hetero-dev-identity', '-f', '-'], raw)
    try:
        STATE.mkdir(mode=0o700)
    except FileExistsError:
        pass
    protected(STATE, directory=True)
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        credentials = material(helper.UID)
        ensure_secret(helper, 'dev-keycloak-tls', 'kubernetes.io/tls',
                      {key: (STATE / key).read_bytes() for key in ('tls.crt', 'tls.key')})
        ensure_secret(helper, 'dev-keycloak-bootstrap', 'Opaque',
                      {key: value.encode() for key, value in credentials.items()})
        output = helper.run(['apply', '--server-side', '--field-manager=hetero-dev-identity', '-f', '-'], raw)
        print(json.dumps({'cluster_uid': helper.UID, 'applied': True, 'origin': ORIGIN,
                          'resources': output.decode().splitlines(), 'ready_verified': False,
                          'owner_configured': False, 'dns_provisioned': False}))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV Keycloak bootstrap stopped; preserve state and inspect prerequisites', file=sys.stderr)
        sys.exit(1)
