#!/usr/bin/env python3
"""CAS update of DEV Keycloak JDBC timeouts, preserving strict TLS and secrets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
OLD = ('jdbc:postgresql://dev-identity-postgres-rw.hetero-dev-identity.svc.cluster.local:5432/keycloak'
       '?sslmode=verify-full&sslrootcert=/var/run/postgres-ca/ca.crt')
NEW = OLD + '&connectTimeout=5&loginTimeout=10&socketTimeout=30&tcpKeepAlive=true'


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    get = ['get', 'deployment', 'dev-keycloak', '-n', 'hetero-dev-identity', '-o', 'json']
    document = json.loads(helper.run(get))
    containers = document['spec']['template']['spec']['containers']
    helper.require(len(containers) == 1 and containers[0]['name'] == 'keycloak'
                   and containers[0]['image'] == 'quay.io/keycloak/keycloak:26.7.3@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54'
                   and document['spec']['replicas'] == 3)
    matches = [(i, e) for i, e in enumerate(containers[0]['env']) if e['name'] == 'KC_DB_URL']
    helper.require(len(matches) == 1 and matches[0][1].get('value') in (OLD, NEW))
    index, entry = matches[0]
    env = containers[0]['env']
    transactions = [e for e in env if e['name'] == 'KC_TRANSACTION_DEFAULT_TIMEOUT']
    helper.require(not transactions or transactions == [{'name': 'KC_TRANSACTION_DEFAULT_TIMEOUT', 'value': '30s'}])
    changed = entry['value'] == OLD or not transactions
    if changed:
        # Keycloak 26.7 overrides the JDBC socket timeout when acquiring a connection.
        desired = [dict(e) for e in env]
        desired[index]['value'] = NEW
        if not transactions:
            desired.append({'name': 'KC_TRANSACTION_DEFAULT_TIMEOUT', 'value': '30s'})
        pointer = '/spec/template/spec/containers/0/env'
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': document['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': document['metadata']['resourceVersion']},
                 {'op': 'test', 'path': pointer, 'value': env},
                 {'op': 'replace', 'path': pointer, 'value': desired}]
        command = ['patch', 'deployment', 'dev-keycloak', '-n', 'hetero-dev-identity',
                   '--type=json', '--patch', json.dumps(patch)]
        helper.run([*command, '--dry-run=server'])
        helper.guard()
        helper.run(command)
    after = json.loads(helper.run(get))
    helper.require(after['spec']['template']['spec']['containers'][0]['env'][index]['value'] == NEW)
    helper.require({'name': 'KC_TRANSACTION_DEFAULT_TIMEOUT', 'value': '30s'}
                   in after['spec']['template']['spec']['containers'][0]['env'])
    print(json.dumps({'changed': changed, 'tls_verification': 'verify-full',
                      'rollout_complete': False, 'secrets_changed': False}))


if __name__ == '__main__':
    main()
