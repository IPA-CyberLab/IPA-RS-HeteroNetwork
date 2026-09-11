#!/usr/bin/env python3
"""Create only the scoped DEV Cloud-to-Keycloak ingress permission."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
NAME = 'dev-keycloak-cloud-clients'
NAMESPACE = 'hetero-dev-identity'


def policy():
    return {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': NAME, 'namespace': NAMESPACE,
                         'annotations': {'heteronetwork.dev.cluster-uid': UID},
                         'labels': {'app.kubernetes.io/managed-by': 'heteronetwork-dev-identity'}},
            'spec': {'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'keycloak'}},
                     'policyTypes': ['Ingress'], 'ingress': [{
                         'from': [{'namespaceSelector': {'matchLabels': {
                             'kubernetes.io/metadata.name': 'heterocloud-dev',
                             'release.heteronetwork.io/channel': 'dev'}},
                             'podSelector': {'matchLabels': {
                                 'app.kubernetes.io/name': 'heterocloud',
                                 'app.kubernetes.io/instance': 'heterocloud-dev'},
                                 'matchExpressions': [{'key': 'app.kubernetes.io/component',
                                                       'operator': 'In', 'values': ['api', 'owner-console']}]}}],
                         'ports': [{'protocol': 'TCP', 'port': 8443}]}]}}


def verify(actual):
    desired = policy()
    if (actual.get('spec') != desired['spec']
            or any(actual.get(key) != desired[key] for key in ('apiVersion', 'kind'))
            or any(actual['metadata'].get(key) != desired['metadata'][key]
                   for key in ('name', 'namespace', 'annotations', 'labels'))
            or actual['metadata'].get('deletionTimestamp')):
        raise ValueError('Existing DEV identity access policy differs; refusing overwrite')


def main():
    if len(sys.argv) != 1:
        raise ValueError('No arguments supported')
    source = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(source.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    helper.require(helper.UID == UID)
    namespace = json.loads(helper.run(['get', 'namespace', 'heterocloud-dev', '-o', 'json']))
    labels = namespace['metadata'].get('labels', {})
    helper.require(labels.get('release.heteronetwork.io/channel') == 'dev'
                   and labels.get('heteronetwork.dev/identity-client') != 'true')
    get = ['get', 'networkpolicy', NAME, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json']
    current = helper.run(get).strip()
    if current:
        verify(json.loads(current))
    else:
        data = json.dumps(policy()).encode()
        helper.run(['create', '--dry-run=server', '-f', '-'], data)
        helper.guard()
        helper.run(['create', '-f', '-'], data)
    verify(json.loads(helper.run(get)))
    print(json.dumps({'created': not bool(current), 'policy': NAME,
                      'namespace_labels_changed': False, 'application_https_verified': False}))


if __name__ == '__main__':
    main()
