#!/usr/bin/env python3
"""Restore a disposable identity server, secret store and Coder workspace from S3.

Every process and credential is created by the fixture. The services bind to
loopback, and no production configuration, kubeconfig or data is used.
"""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
import urllib.request
from unittest.mock import patch

import control_plane_dr as dr


WORKSPACE = 'recoverable'
OWNER = 'restore-owner'
OWNER_EMAIL = 'restore-owner@example.test'
COMPONENTS = {'postgres', 'secret-manager', 'coder-home'}


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def private_file(path, value, *, executable=False):
    mode = 0o700 if executable else 0o600
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), 'wb') as output:
        output.write(value.encode() if isinstance(value, str) else value)
    return path


def command(*args, env=None, data=None, stdin=None, timeout=120):
    result = subprocess.run(args, env=env, input=data, stdin=stdin, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} exited {result.returncode}')
    return result.stdout


def stop(process):
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def launch(stack, log, *argv, env=None, cwd=None):
    with log.open('wb') as output:
        process = subprocess.Popen(argv, env=env, cwd=cwd, start_new_session=True,
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output)
    stack.callback(stop, process)
    return process


def wait_for(check, label, *, process=None, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f'{label} exited before becoming ready')
        try:
            if result := check():
                return result
        except (OSError, URLError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f'{label} did not become ready')


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('unexpected fixture redirect')


def api(url, path, *, method='GET', data=None, headers=None, form=False, raw=False):
    headers = dict(headers or {})
    if isinstance(data, dict):
        data = urlencode(data).encode() if form else json.dumps(data).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    elif data is not None:
        headers['Content-Type'] = 'application/octet-stream'
    request = urllib.request.Request(url + path, data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    with opener.open(request, timeout=10) as response:
        payload = response.read(32 * 1024**2 + 1)
    if len(payload) > 32 * 1024**2:
        raise RuntimeError('fixture response exceeded its size budget')
    return payload if raw else (json.loads(payload) if payload else {})


def s3_fixture(args, root, stack, env):
    s3_port, rpc_port, tls_port = port(), port(), port()
    config = private_file(root / 'garage.toml', f'''
metadata_dir = "{root}/garage-meta"
data_dir = "{root}/garage-data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "127.0.0.1:{rpc_port}"
rpc_public_addr = "127.0.0.1:{rpc_port}"
rpc_secret = "{secrets.token_hex(32)}"

[s3_api]
s3_region = "us-east-1"
api_bind_addr = "127.0.0.1:{s3_port}"
''')
    access_key, secret_key = 'GK' + secrets.token_hex(12), secrets.token_hex(32)
    bucket = 'fixture-recovery'
    garage = launch(stack, root / 'garage.log', args.garage, '-c', str(config), 'server',
                    '--single-node', '--default-bucket',
                    env={**env, 'GARAGE_DEFAULT_ACCESS_KEY': access_key,
                         'GARAGE_DEFAULT_SECRET_KEY': secret_key, 'GARAGE_DEFAULT_BUCKET': bucket})
    cert, key = root / 's3.crt', root / 's3.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-keyout', str(key), '-out', str(cert))
    proxy = launch(stack, root / 's3-tls.log', args.socat,
                   f'OPENSSL-LISTEN:{tls_port},bind=127.0.0.1,reuseaddr,fork,verify=0,cert={cert},key={key}',
                   f'TCP:127.0.0.1:{s3_port}')

    def s3_ready():
        context = ssl.create_default_context(cafile=str(cert))
        if garage.poll() is not None:
            raise RuntimeError('fixture S3 server exited')
        try:
            with urllib.request.urlopen(f'https://127.0.0.1:{tls_port}/{bucket}', context=context, timeout=2):
                raise RuntimeError('anonymous S3 access was unexpectedly allowed')
        except HTTPError as error:
            return error.code == 403

    wait_for(s3_ready, 'HTTPS S3 fixture', process=proxy)
    return f's3:https://127.0.0.1:{tls_port}/{bucket}/site-recovery', {
        'AWS_ACCESS_KEY_ID': access_key, 'AWS_SECRET_ACCESS_KEY': secret_key,
        'AWS_DEFAULT_REGION': 'us-east-1', 'RESTIC_CACERT': str(cert),
    }


def database(pg_bin, pg_root, name, owner, stack):
    path = pg_root / name
    listen = port()
    run_as = ('runuser', '-u', 'nobody', '--')
    command(*run_as, str(pg_bin / 'initdb'), '-D', str(path), '--auth=trust',
            '--no-locale', '--encoding=UTF8', '--username=' + owner)
    control = (*run_as, str(pg_bin / 'pg_ctl'), '-D', str(path))
    command(*control, '-l', str(pg_root / (name + '.log')),
            '-o', f'-h 127.0.0.1 -p {listen} -k {pg_root}', '-w', 'start')
    stack.callback(command, *control, '-m', 'fast', '-w', 'stop', timeout=30)
    return ('-h', '127.0.0.1', '-p', str(listen), '-U', owner)


def identity(args, root, stack, env, pg_port, listen, password=None):
    origin = f'http://127.0.0.1:{listen}'
    config = {**env, 'KC_DB': 'postgres', 'KC_DB_URL': f'jdbc:postgresql://127.0.0.1:{pg_port}/identity',
              'KC_DB_USERNAME': OWNER, 'KC_DB_PASSWORD': '',
              'JAVA_OPTS_APPEND': '-Xms64m -Xmx384m -XX:ActiveProcessorCount=2'}
    if password:
        config.update(KC_BOOTSTRAP_ADMIN_USERNAME=OWNER, KC_BOOTSTRAP_ADMIN_PASSWORD=password)
    process = launch(stack, root / 'keycloak.log', args.keycloak, 'start-dev',
                     '--http-host', '127.0.0.1', '--http-port', str(listen),
                     '--hostname-strict=false', env=config)
    wait_for(lambda: api(origin, '/realms/master/.well-known/openid-configuration'),
             'identity server', process=process)
    return origin


def identity_login(origin, password):
    tokens = api(origin, '/realms/master/protocol/openid-connect/token', method='POST', form=True,
                 data={'grant_type': 'password', 'client_id': 'admin-cli', 'username': OWNER, 'password': password})
    users = api(origin, '/admin/realms/master/users?' + urlencode({'username': OWNER, 'exact': 'true'}),
                headers={'Authorization': 'Bearer ' + tokens['access_token']})
    if len(users) != 1 or users[0]['username'] != OWNER:
        raise RuntimeError('the recovered identity could not administer the realm')
    return users[0]['id']


def bao(args, directory, stack, env):
    directory.mkdir(mode=0o700)
    listen, cluster = port(), port()
    origin = f'http://127.0.0.1:{listen}'
    config = private_file(directory / 'bao.hcl', f'''
disable_mlock = true
api_addr = "{origin}"
cluster_addr = "https://127.0.0.1:{cluster}"

listener "tcp" {{
  address = "127.0.0.1:{listen}"
  cluster_address = "127.0.0.1:{cluster}"
  tls_disable = true
}}
storage "raft" {{
  path = "{directory}/raft"
  node_id = "site-recovery-fixture"
}}
''')
    (directory / 'raft').mkdir(mode=0o700)
    process = launch(stack, directory / 'bao.log', args.bao, 'server', '-config', str(config), env=env)
    wait_for(lambda: api(origin, '/v1/sys/init'), 'secret store', process=process)
    return origin


def unseal(origin, shares):
    for share in shares:
        state = api(origin, '/v1/sys/unseal', method='PUT', data={'key': share})
    if state['sealed']:
        raise RuntimeError('the secret store remained sealed')


def init_bao(origin):
    keys = api(origin, '/v1/sys/init', method='PUT', data={'secret_shares': 3, 'secret_threshold': 2})
    unseal(origin, keys['keys_base64'][:2])
    return keys


def coder(args, root, stack, env, pg_port, listen):
    origin = f'http://127.0.0.1:{listen}'
    config = {**env, 'CODER_PG_CONNECTION_URL': f'postgres://{OWNER}@127.0.0.1:{pg_port}/coder?sslmode=disable',
              'CODER_HTTP_ADDRESS': f'127.0.0.1:{listen}', 'CODER_ACCESS_URL': origin,
              'CODER_TELEMETRY_ENABLE': 'false', 'CODER_PROVISIONER_DAEMONS': '1',
              'CODER_DERP_SERVER_STUN_ADDRESSES': 'disable',
              'CODER_CACHE_DIRECTORY': str(root / 'coder-cache')}
    process = launch(stack, root / 'coder.log', args.coder, 'server', env=config)
    wait_for(lambda: api(origin, '/api/v2/buildinfo'), 'Coder', process=process)
    return origin


def coder_login(origin, password):
    return api(origin, '/api/v2/users/login', method='POST',
               data={'email': OWNER_EMAIL, 'password': password})['session_token']


def coder_cli(args, root, env, origin, token, *argv):
    return command(args.coder, '--global-config', str(root / 'coder-cli'), *argv,
                   env={**env, 'CODER_URL': origin, 'CODER_SESSION_TOKEN': token}, timeout=180)


def workspace_id(origin, token):
    value = api(origin, '/api/v2/users/me/workspace/' + WORKSPACE,
                headers={'Coder-Session-Token': token})
    return value['id']


def template(directory, home, token_file, proof_file):
    directory.mkdir(mode=0o700)
    body = '''
terraform {
  required_providers {
    coder = { source = "coder/coder", version = "2.19.0" }
  }
}
data "coder_workspace" "me" {}
resource "coder_agent" "main" {
  os   = "linux"
  arch = "amd64"
  dir  = WORKSPACE_HOME
  startup_script = STARTUP_SCRIPT
}
resource "terraform_data" "agent_file" {
  count = data.coder_workspace.me.start_count
  triggers_replace = [coder_agent.main.id]
  provisioner "local-exec" {
    command = "umask 077; printf '%s' \\"$AGENT_TOKEN\\" > \\"$AGENT_FILE\\""
    environment = {
      AGENT_FILE  = TOKEN_FILE
      AGENT_TOKEN = coder_agent.main.token
    }
  }
}
'''
    script = 'umask 077\ncat ' + shlex.quote(str(home / 'recovery-marker')) + ' > ' + shlex.quote(str(proof_file))
    private_file(directory / 'main.tf', body.replace('WORKSPACE_HOME', json.dumps(str(home)))
                 .replace('TOKEN_FILE', json.dumps(str(token_file)))
                 .replace('STARTUP_SCRIPT', json.dumps(script)))


def fixture_env(args, root):
    return {'PATH': str(Path(args.terraform).resolve().parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
            'HOME': str(root), 'LANG': 'C.UTF-8', 'JAVA_HOME': str(Path(args.java_home).resolve())}


def source(root, name, *argv):
    return {'name': name, 'executable': str(private_file(root / f'backup-{name}',
                '#!/bin/sh\nexec ' + shlex.join(argv) + '\n', executable=True))}


def run(args, root, pg_root):
    env = fixture_env(args, root)
    workspace_home = root / 'workspace-home'
    workspace_home.mkdir(mode=0o700)
    marker = secrets.token_hex(24)
    password = secrets.token_urlsafe(32)
    private_file(workspace_home / 'recovery-marker', marker)
    identity_port, coder_port = port(), port()
    agent_file = root / 'agent-token'
    proof_file = root / 'workspace-startup-proof'
    backup = root / 'source-raft.snap'

    with ExitStack() as store:
        repository, storage_env = s3_fixture(args, root, store, env)
        with ExitStack() as original:
            print('Creating disposable source services', flush=True)
            pg = database(args.pg_bin, pg_root, 'source', OWNER, original)
            pg_port = pg[3]
            psql = str(args.pg_bin / 'psql')
            for name in ('identity', 'coder'):
                command(psql, *pg, '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', f'CREATE DATABASE {name}')
            idp = identity(args, root, original, env, pg_port, identity_port, password)
            owner_id = identity_login(idp, password)
            coder_origin = coder(args, root, original, env, pg_port, coder_port)
            api(coder_origin, '/api/v2/users/first', method='POST',
                data={'email': OWNER_EMAIL, 'username': OWNER, 'password': password})
            session = coder_login(coder_origin, password)
            template(root / 'template', workspace_home, agent_file, proof_file)
            def cli(*argv):
                return coder_cli(args, root, env, coder_origin, session, *argv)

            cli('templates', 'push', WORKSPACE, '--directory', str(root / 'template'), '--ignore-lockfile', '--yes')
            cli('create', WORKSPACE, '--template', WORKSPACE, '--yes')
            original_workspace = workspace_id(coder_origin, session)
            cli('stop', WORKSPACE, '--yes')

            bao_origin = bao(args, root / 'source-bao', original, env)
            keys = init_bao(bao_origin)
            root_header = {'X-Vault-Token': keys['root_token']}
            api(bao_origin, '/v1/sys/mounts/secret', method='POST', headers=root_header,
                data={'type': 'kv', 'options': {'version': '2'}})
            api(bao_origin, '/v1/secret/data/restore-probe', method='POST', headers=root_header,
                data={'data': {'marker': marker}})
            private_file(backup, api(bao_origin, '/v1/sys/storage/raft/snapshot', headers=root_header, raw=True))
            repository_password = private_file(root / 'repository-password', secrets.token_urlsafe(32) + '\n')
            config_file = private_file(root / 'backup.json', json.dumps({
                'repository': repository, 'password_file': str(repository_password),
                'sources': [source(root, 'postgres', str(args.pg_bin / 'pg_dumpall'), *pg, '--no-password'),
                            source(root, 'secret-manager', '/bin/cat', str(backup)),
                            source(root, 'coder-home', '/bin/tar', '-C', str(workspace_home), '-cf', '-', '.')],
                'max_component_bytes': 128 * 1024**2, 'max_total_bytes': 256 * 1024**2, 'timeout_seconds': 120,
            }))
            config = dr.read_config(config_file)
            print('Committing fixture backups to HTTPS S3', flush=True)
            with patch.dict(os.environ, {**env, **storage_env, 'XDG_CACHE_HOME': str(root / 'source-cache')},
                            clear=True):
                command(args.restic, 'init', '--quiet', env=dr.restic_env(config))
                saved = dr.backup(config, args.restic)

        # Remove only this fixture's original state. Recovery does not need the
        # original source programs, processes or database files.
        shutil.rmtree(pg_root / 'source')
        shutil.rmtree(root / 'source-bao')
        shutil.rmtree(workspace_home)
        shutil.rmtree(root / 'source-cache')
        backup.unlink()
        agent_file.unlink(missing_ok=True)
        started = time.monotonic()
        restore_started_at = int(time.time())
        destination = root / 'recovered'
        destination.mkdir(mode=0o700)
        print('Restoring the selected set with source services stopped', flush=True)
        with patch.dict(os.environ, {**env, **storage_env, 'XDG_CACHE_HOME': str(root / 'restore-cache')},
                        clear=True):
            candidates = dr.list_sets(config, args.restic, 1)['recovery_sets']
            if len(candidates) != 1 or not candidates[0]['snapshot'].startswith(saved['snapshot']):
                raise RuntimeError('catalog did not return the committed recovery point')
            snapshot = candidates[0]['snapshot']
            dr.restore(config, args.restic, snapshot, destination, required_components=COMPONENTS)

        with ExitStack() as replacement:
            pg = database(args.pg_bin, pg_root, 'replacement', 'restore_superuser', replacement)
            with (destination / 'postgres').open('rb') as payload:
                command(psql, *pg, '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', stdin=payload)
            idp = identity(args, root, replacement, env, pg[3], identity_port)
            if identity_login(idp, password) != owner_id:
                raise RuntimeError('owner identity changed during recovery')
            print('Restored owner authenticated with the original identity', flush=True)

            restored_bao = bao(args, root / 'replacement-bao', replacement, env)
            temporary_keys = init_bao(restored_bao)
            api(restored_bao, '/v1/sys/storage/raft/snapshot-force', method='POST',
                headers={'X-Vault-Token': temporary_keys['root_token']},
                data=(destination / 'secret-manager').read_bytes())
            wait_for(lambda: api(restored_bao, '/v1/sys/seal-status')['sealed'], 'restored Raft seal')
            unseal(restored_bao, keys['keys_base64'][:2])
            item = wait_for(lambda: api(restored_bao, '/v1/secret/data/restore-probe', headers=root_header),
                            'restored secret')
            if item['data']['data']['marker'] != marker:
                raise RuntimeError('restored secret did not match')
            print('Restored OpenBao data unsealed with two original shares', flush=True)

            workspace_home.mkdir(mode=0o700)
            with tarfile.open(destination / 'coder-home') as archive:
                archive.extractall(workspace_home, filter='data')
            coder_origin = coder(args, root, replacement, env, pg[3], coder_port)
            session = coder_login(coder_origin, password)
            if workspace_id(coder_origin, session) != original_workspace:
                raise RuntimeError('original Coder workspace identity was not restored')
            cli('start', WORKSPACE, '--yes')
            agent = launch(replacement, root / 'agent.log', args.coder, 'agent',
                           env={**env, 'CODER_AGENT_URL': coder_origin, 'CODER_AGENT_TOKEN_FILE': str(agent_file)},
                           cwd=workspace_home)
            wait_for(lambda: proof_file.read_text() == marker, 'restored workspace startup script',
                     process=agent, timeout=60)
            elapsed = round(time.monotonic() - started, 2)

    return {'passed': True, 'scope': 'isolated_synthetic_service_recovery',
            'storage': 'https_s3', 'source_stopped_and_removed': True,
            'verified': ['owner_login', 'secret_kv', 'original_workspace_started', 'workspace_agent_read_home'],
            'recovery_seconds': elapsed,
            'capture_to_restore_start_seconds': restore_started_at - candidates[0]['capture_started_at']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('restic', 'garage', 'socat', 'keycloak', 'java-home', 'bao', 'coder', 'terraform'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--pg-bin', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('the disposable PostgreSQL fixture uses runuser')
    os.umask(0o077)
    identity_user = pwd.getpwnam('nobody')
    with tempfile.TemporaryDirectory(prefix='hc-dr-stack-') as private, \
            tempfile.TemporaryDirectory(prefix='hc-dr-stack-pg-') as database_root:
        os.chown(database_root, identity_user.pw_uid, identity_user.pw_gid)
        print(json.dumps(run(args, Path(private), Path(database_root)), sort_keys=True))


if __name__ == '__main__':
    main()
