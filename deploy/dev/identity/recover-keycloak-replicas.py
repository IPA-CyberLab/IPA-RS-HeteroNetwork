#!/usr/bin/env python3
"""Explicit DEV-only recovery of unready Keycloak pods, one at a time."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
NAMESPACE = 'hetero-dev-identity'
IMAGE = 'quay.io/keycloak/keycloak:26.7.3@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54'


def ready(pod):
    return not pod['metadata'].get('deletionTimestamp') and any(
        c['type'] == 'Ready' and c['status'] == 'True'
        for c in pod['status'].get('conditions', []))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)

    def inventory():
        helper.guard()
        deployment = json.loads(helper.run(['get', 'deployment', 'dev-keycloak', '-n', NAMESPACE, '-o', 'json']))
        helper.require(deployment['spec']['replicas'] == 3)
        replicas = json.loads(helper.run(['get', 'replicasets', '-n', NAMESPACE, '-o', 'json']))['items']
        owned = {r['metadata']['uid'] for r in replicas if any(
            o['uid'] == deployment['metadata']['uid'] and o.get('controller')
            for o in r['metadata'].get('ownerReferences', []))}
        pods = json.loads(helper.run(['get', 'pods', '-n', NAMESPACE, '-l',
                                     'app.kubernetes.io/name=keycloak', '-o', 'json']))['items']
        helper.require(len(pods) == 3 and len({p['spec']['nodeName'] for p in pods}) == 3)
        for pod in pods:
            helper.require(not pod['metadata'].get('deletionTimestamp')
                           and len(pod['spec']['containers']) == 1
                           and pod['spec']['containers'][0]['image'] == IMAGE
                           and any(o['uid'] in owned and o.get('controller')
                                   for o in pod['metadata'].get('ownerReferences', [])))
        return pods

    initial = inventory()
    candidates = [p['metadata']['uid'] for p in initial if not ready(p)]
    helper.require(any(ready(p) for p in initial))
    print(json.dumps({'unready_replicas': len(candidates), 'apply': args.apply}), flush=True)
    if not args.apply:
        return
    for uid in candidates:
        pods = inventory()
        candidate = next((p for p in pods if p['metadata']['uid'] == uid), None)
        if candidate is None or ready(candidate):
            continue
        healthy = sum(ready(p) for p in pods)
        helper.require(healthy >= 1)
        name = candidate['metadata']['name']
        # Both UID and resourceVersion prevent deleting a replaced/recovered pod.
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                   'preconditions': {'uid': uid, 'resourceVersion': candidate['metadata']['resourceVersion']}}
        helper.run(['delete', '--raw', f'/api/v1/namespaces/{NAMESPACE}/pods/{name}', '-f', '-'],
                   data=json.dumps(options).encode())
        print(json.dumps({'recreating': name, 'healthy_replicas_retained': healthy}), flush=True)
        deadline = time.monotonic() + 360
        while True:
            helper.guard()
            current = json.loads(helper.run(['get', 'pods', '-n', NAMESPACE, '-l',
                                            'app.kubernetes.io/name=keycloak', '-o', 'json']))['items']
            if not any(p['metadata']['uid'] == uid for p in current) and sum(ready(p) for p in current) >= healthy + 1:
                break
            helper.require(time.monotonic() < deadline)
            time.sleep(5)
    final = inventory()
    helper.require(all(ready(p) for p in final))
    print(json.dumps({'ready_replicas': 3, 'automatic_failover_proven': False}), flush=True)


if __name__ == '__main__':
    main()
