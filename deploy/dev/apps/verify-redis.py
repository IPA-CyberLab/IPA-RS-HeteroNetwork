#!/usr/bin/env python3
"""Verify actual DEV Redis placement, Sentinel agreement and replicated writes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import uuid

sys.dont_write_bytecode = True
NS = 'heterocloud-flow-dev'
PREFIX = 'heterocloud-flow-dev-redis-node-'


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    pods = json.loads(helper.run(['get', 'pods', '-n', NS, '-l',
                                 'app.kubernetes.io/name=redis,app.kubernetes.io/instance=heterocloud-flow-dev', '-o', 'json']))['items']
    helper.require(len(pods) == 3 and {p['metadata']['name'] for p in pods} == {PREFIX + str(i) for i in range(3)}
                   and {p['spec']['nodeName'] for p in pods} == {'hetero-dev-' + str(i) for i in range(1, 4)})
    for pod in pods:
        helper.require(not pod['metadata'].get('deletionTimestamp') and any(
            c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', [])))

    def cli(pod, arguments, container='redis'):
        script = 'export REDISCLI_AUTH="$(cat /opt/bitnami/redis/secrets/redis-password)"; exec ' + shlex.join(
            ['redis-cli', '--no-auth-warning', '--raw', *arguments])
        return helper.run(['exec', '-n', NS, pod, '-c', container, '--', '/bin/bash', '-ec', script]).decode().strip()

    rows, masters = [], set()
    for pod in sorted(pods, key=lambda p: p['metadata']['name']):
        name = pod['metadata']['name']
        helper.require(cli(name, ['PING']) == 'PONG')
        address = cli(name, ['-p', '26379', 'SENTINEL', 'get-master-addr-by-name', 'flowmaster'], 'sentinel').splitlines()
        helper.require(len(address) == 2 and address[1] == '6379')
        masters.add(tuple(address))
        quorum = cli(name, ['-p', '26379', 'SENTINEL', 'ckquorum', 'flowmaster'], 'sentinel')
        helper.require(quorum.startswith('OK'))
        info = dict(line.split(':', 1) for line in cli(name, ['INFO', 'replication']).splitlines() if ':' in line)
        helper.require(info.get('role') in ('master', 'slave'))
        if info['role'] == 'slave':
            helper.require(info.get('master_link_status') == 'up')
        rows.append({'pod': name, 'node': pod['spec']['nodeName'], 'role': info['role'], 'quorum': quorum})
    helper.require(len(masters) == 1 and sum(row['role'] == 'master' for row in rows) == 1)
    master_host, master_port = next(iter(masters))
    writer = next(row['pod'] for row in rows if row['role'] == 'master')
    observer = next(row['pod'] for row in rows if row['pod'] != writer)
    # Resolve and contact the actual address returned by Sentinel from a different pod.
    helper.require(cli(observer, ['-h', master_host, '-p', master_port, 'ROLE']).splitlines()[0] == 'master')
    key = 'heteronetwork:dev:redis-probe:' + uuid.uuid4().hex
    value = uuid.uuid4().hex
    script = ('export REDISCLI_AUTH="$(cat /opt/bitnami/redis/secrets/redis-password)"; '
              + 'printf %s ' + shlex.quote(f'SET {key} {value} EX 60 NX\nWAIT 2 5000\n')
              + ' | redis-cli --no-auth-warning --raw')
    try:
        result = helper.run(['exec', '-n', NS, writer, '-c', 'redis', '--', '/bin/bash', '-ec', script]).decode().strip().splitlines()
        helper.require(result == ['OK', '2'])
        helper.require(all(cli(row['pod'], ['GET', key]) == value for row in rows))
    finally:
        helper.require(cli(writer, ['DEL', key]) in ('0', '1'))
    print(json.dumps({'ready_replicas': 3, 'sentinel_agreement': True, 'replicated_write': True,
                      'replicas_acknowledged': 2, 'rows': rows, 'failure_tested': False}), flush=True)


if __name__ == '__main__':
    main()
