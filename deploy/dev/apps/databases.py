"""Fresh DEV database bootstrap using the same renderer as the release environment."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('app_postgres', ROOT / 'deploy/gitops/environments/app_postgres.py')
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

NAMESPACES = ('heterocloud-dev', 'heterocloud-flow-dev', 'heterocloud-syouyu-dev')
CLUSTER_UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
IMAGE = ('ghcr.io/cloudnative-pg/postgresql:18.6-standard-trixie@sha256:'
         '71eef62330076deb985c8ffb1abeb957d86779c3911a8057c0b97f3c5a30b50b')
SITE = {'storage_class': 'dev-app-local', 'service_cidrs': ['172.30.0.1/32'],
        'kubernetes_api_backend_cidrs': ['10.251.0.1/32', '10.251.0.2/32', '10.251.0.3/32']}


def resources(phase):
    rendered = renderer.resources(NAMESPACES, SITE, IMAGE)
    if phase == 'network':
        namespaces = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
            'name': ns, 'labels': {'release.heteronetwork.io/channel': 'dev'}}} for ns in NAMESPACES]
        return namespaces + [item for item in rendered if item['kind'] == 'NetworkPolicy']
    if phase not in NAMESPACES:
        raise ValueError('Unknown DEV database phase')
    return [item for item in rendered if item['kind'] == 'Cluster' and item['metadata']['namespace'] == phase]


if __name__ == '__main__':
    print(json.dumps({'apiVersion': 'v1', 'kind': 'List',
                      'items': resources('network') + [resources(ns)[0] for ns in NAMESPACES]}, indent=2))
