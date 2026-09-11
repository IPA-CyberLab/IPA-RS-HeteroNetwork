#!/usr/bin/env python3
"""DEV Flash process readiness, authentication rejection and RBAC boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import urllib.request

sys.dont_write_bytecode = True
NS = 'heterocloud-flash-dev'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:0.1.30-dev.2@sha256:191c9c68251f7b578490b12fb18797f5f364b1124ae80fd14f457c42eb252cb2'


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    placements = {}
    for component, replicas in [('api', 3), ('controller', 2)]:
        deployment = json.loads(helper.run(['get', 'deployment', NS + '-' + component, '-n', NS, '-o', 'json']))
        helper.require(deployment['status'].get('availableReplicas') == replicas
                       and deployment['status'].get('updatedReplicas') == replicas
                       and deployment['status'].get('observedGeneration') == deployment['metadata']['generation'])
        pods = json.loads(helper.run(['get', 'pods', '-n', NS, '-l',
            'app.kubernetes.io/name=heterocloud-flash,app.kubernetes.io/component=' + component, '-o', 'json']))['items']
        helper.require(len(pods) == replicas and len({p['spec']['nodeName'] for p in pods}) == replicas
                       and {p['spec']['nodeName'] for p in pods}.issubset({f'hetero-dev-{i}' for i in range(1, 4)}))
        placements[component] = []
        for pod in pods:
            helper.require(pod['spec']['containers'][0]['image'] == IMAGE
                           and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status']['conditions']))
            if component == 'api':
                origin = 'http://' + pod['status']['podIP'] + ':8080'
                for path, expected in [('/health/live', 'ok'), ('/health/ready', 'ready')]:
                    with opener.open(origin + path, timeout=5) as response:
                        helper.require(response.status == 200 and json.loads(response.read(4096)) == {'status': expected})
                try:
                    opener.open(origin + '/internal/v1/service-instances/00000000-0000-4000-8000-000000000001?generation=1', timeout=5)
                except urllib.error.HTTPError as error:
                    helper.require(error.code == 401)
                else:
                    raise ValueError('Unauthenticated Flash request was not rejected')
            placements[component].append({'pod': pod['metadata']['name'], 'node': pod['spec']['nodeName'],
                                          'uid': pod['metadata']['uid']})
    checks = [('get', 'nodes', None, True), ('create', 'deployments.apps', NS + '-workloads', True),
              ('create', 'pods/exec', NS + '-workloads', True),
              ('get', 'secrets', 'heterocloud-dev', False), ('create', 'deployments.apps', 'heterocloud-dev', False),
              ('create', 'clusterrolebindings', None, False)]
    # SelfSubjectAccessReview gives a structured allow/deny result without command exit-code ambiguity.
    for verb, resource, namespace, allowed in checks:
        group = 'apps' if resource == 'deployments.apps' else 'rbac.authorization.k8s.io' if resource == 'clusterrolebindings' else ''
        attributes = {'verb': verb, 'group': group, 'resource': resource.split('.')[0].split('/')[0]}
        if '/' in resource:
            attributes['subresource'] = resource.split('/')[1]
        if namespace:
            attributes['namespace'] = namespace
        review = {'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SelfSubjectAccessReview',
                  'spec': {'resourceAttributes': attributes}}
        result = json.loads(helper.run(['create', '--as=system:serviceaccount:' + NS + ':' + NS,
                                        '--as-group=system:authenticated', '--as-group=system:serviceaccounts',
                                        '--as-group=system:serviceaccounts:' + NS,
                                        '--raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',
                                        '-f', '-'], json.dumps(review).encode()))
        helper.require(result['status']['allowed'] is allowed)
    print(json.dumps({'placements': placements, 'api_health_checks': 6, 'unauthenticated_401_checks': 3,
                      'rbac_checks': len(checks), 'controller_operations_verified': False,
                      'tenant_isolation_verified': False}), flush=True)


if __name__ == '__main__':
    main()
