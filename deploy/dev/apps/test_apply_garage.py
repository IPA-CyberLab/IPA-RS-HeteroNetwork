import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location('apply_garage', Path(__file__).with_name('apply-garage.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

NS = 'heterocloud-syouyu-dev'
IMAGE = 'docker.io/dxflrs/garage@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690'
# Independent inventory so changes to the helper's allowlist cannot change the oracle.
INVENTORY = {
    ('CustomResourceDefinition', 'garagenodes.deuxfleurs.fr'),
    ('NetworkPolicy', NS + '-default-deny'),
    ('NetworkPolicy', NS + '-dns'),
    ('NetworkPolicy', NS + '-garage'),
    ('NetworkPolicy', NS + '-layout-bootstrap'),
    ('PodDisruptionBudget', NS + '-garage'),
    ('ServiceAccount', NS),
    ('ServiceAccount', NS + '-garage'),
    ('ConfigMap', NS + '-garage-config'),
    ('ClusterRole', NS + '-garage-discovery'),
    ('ClusterRoleBinding', NS + '-garage-discovery'),
    ('Service', NS + '-garage-headless'),
    ('Service', NS + '-s3'),
    ('Service', NS + '-garage-admin'),
    ('Service', NS + '-garage-admin-bootstrap'),
    ('Service', NS + '-garage-metrics'),
    ('StatefulSet', NS + '-garage'),
    ('Job', NS + '-layout-e97f53f5'),
}
API_INVENTORY = {(kind, NS + '-api') for kind in ('Deployment', 'Service', 'NetworkPolicy')}


def object_key(item):
    return item['kind'], item['metadata']['name']


def statefulset(source):
    return next(item for item in source['items'] if item['kind'] == 'StatefulSet')


def fixture():
    """Public, minimal chart-shaped objects; no runtime files or secret values."""
    labels = {'app.kubernetes.io/name': 'heterocloud-syouyu',
              'app.kubernetes.io/instance': NS}
    items = []
    for kind, name in sorted(INVENTORY | API_INVENTORY):
        metadata = {'name': name, 'labels': dict(labels)}
        if kind not in {'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding'}:
            metadata['namespace'] = NS
        item = {'kind': kind, 'metadata': metadata}
        if kind == 'NetworkPolicy':
            item['spec'] = {'podSelector': {'matchLabels': dict(labels)}}
        items.append(item)
    source = {'apiVersion': 'v1', 'kind': 'List', 'items': items}
    garage_labels = dict(labels, **{'app.kubernetes.io/component': 'garage'})
    statefulset(source)['spec'] = {
        'replicas': 3,
        'template': {
            'metadata': {'labels': garage_labels},
            'spec': {
                'containers': [{'name': 'garage', 'image': IMAGE}],
                'affinity': {'podAntiAffinity': {
                    'requiredDuringSchedulingIgnoredDuringExecution': [{
                        'labelSelector': {'matchLabels': dict(garage_labels)},
                        'topologyKey': 'kubernetes.io/hostname',
                    }],
                }},
            },
        },
        'volumeClaimTemplates': [
            {'metadata': {'name': name}, 'spec': {
                'accessModes': ['ReadWriteOnce'],
                'storageClassName': 'dev-app-local',
                'resources': {'requests': {'storage': size}},
            }} for name, size in [('meta', '2Gi'), ('data', '10Gi')]]
    }
    return source


class GarageAdmission(unittest.TestCase):
    def test_exact_inventory_excludes_api_resources(self):
        source = fixture()
        self.assertEqual(len(source['items']), 21)
        items, pod = app.select(source)
        self.assertEqual(len(items), 18)
        self.assertEqual({object_key(item) for item in items}, INVENTORY)
        self.assertTrue(API_INVENTORY.isdisjoint(map(object_key, items)))
        self.assertIs(pod, statefulset(source)['spec']['template']['spec'])

    def test_crd_first_statefulset_before_job_regardless_of_input_order(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                source = fixture()
                source['items'].sort(key=object_key, reverse=reverse)
                items, _ = app.select(source)
                self.assertEqual(object_key(items[0]),
                                 ('CustomResourceDefinition', 'garagenodes.deuxfleurs.fr'))
                self.assertEqual([item['kind'] for item in items[-2:]], ['StatefulSet', 'Job'])
                self.assertFalse(any(item['kind'] in {'CustomResourceDefinition', 'StatefulSet', 'Job'}
                                     for item in items[1:-2]))

    def test_wrong_namespace_rejected_for_every_selected_object(self):
        for key in sorted(INVENTORY):
            for namespace in ('production', NS, None):
                cluster_scoped = key[0] in {'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding'}
                if namespace == (None if cluster_scoped else NS):
                    continue
                with self.subTest(resource=key, namespace=namespace):
                    source = fixture()
                    item = next(item for item in source['items'] if object_key(item) == key)
                    if namespace is None:
                        item['metadata'].pop('namespace', None)
                    else:
                        item['metadata']['namespace'] = namespace
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_mutable_or_unapproved_image_rejected(self):
        for image in ('docker.io/dxflrs/garage:latest', 'docker.io/dxflrs/garage:v2.0.0',
                      'docker.io/dxflrs/garage@sha256:' + '0' * 64):
            with self.subTest(image=image):
                source = fixture()
                statefulset(source)['spec']['template']['spec']['containers'][0]['image'] = image
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_unsafe_pod_configuration_rejected(self):
        for field, value in (
            ('hostNetwork', True),
            ('initContainers', [{'name': 'init', 'image': IMAGE}]),
            ('containers', []),
            ('containers', [{'name': 'garage', 'image': IMAGE}, {'name': 'extra', 'image': IMAGE}]),
            ('affinity', {'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': []}}),
        ):
            with self.subTest(field=field, value=value):
                source = fixture()
                statefulset(source)['spec']['template']['spec'][field] = value
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_wrong_replica_count_rejected(self):
        for replicas in (0, 1, 2, 4):
            with self.subTest(replicas=replicas):
                source = fixture()
                statefulset(source)['spec']['replicas'] = replicas
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_unsafe_claim_rejected(self):
        for index in (0, 1):
            for change in ('name', 'duplicate-name', 'size', 'storage-class', 'missing', 'extra'):
                with self.subTest(claim=index, change=change):
                    source = fixture()
                    claims = statefulset(source)['spec']['volumeClaimTemplates']
                    claim = claims[index]
                    if change == 'name':
                        claim['metadata']['name'] = 'unexpected'
                    elif change == 'duplicate-name':
                        claim['metadata']['name'] = claims[1 - index]['metadata']['name']
                    elif change == 'size':
                        claim['spec']['resources']['requests']['storage'] = '100Gi'
                    elif change == 'storage-class':
                        claim['spec']['storageClassName'] = 'standard'
                    elif change == 'missing':
                        claims.pop(index)
                    else:
                        claims.append(copy.deepcopy(claim))
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_broad_or_foreign_network_policy_rejected(self):
        for key in sorted(key for key in INVENTORY if key[0] == 'NetworkPolicy'):
            for selector in ({}, {'matchLabels': {}},
                             {'matchLabels': {'app.kubernetes.io/name': 'heterocloud-syouyu'}},
                             {'matchLabels': {'app.kubernetes.io/instance': 'production'}}):
                with self.subTest(resource=key, selector=selector):
                    source = fixture()
                    policy = next(item for item in source['items'] if object_key(item) == key)
                    policy['spec']['podSelector'] = selector
                    # Missing selector keys currently fail closed with KeyError, not ValueError.
                    with self.assertRaises((ValueError, KeyError)):
                        app.select(source)

    def test_duplicate_missing_or_replaced_inventory_rejected(self):
        for key in sorted(INVENTORY):
            for change in ('duplicate', 'missing', 'replace-with-duplicate'):
                with self.subTest(resource=key, change=change):
                    source = fixture()
                    item = next(item for item in source['items'] if object_key(item) == key)
                    if change == 'duplicate':
                        source['items'].append(copy.deepcopy(item))
                    else:
                        source['items'].remove(item)
                        if change == 'replace-with-duplicate':
                            other = next(item for item in source['items'] if object_key(item) in INVENTORY)
                            source['items'].append(copy.deepcopy(other))
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_non_list_document_rejected(self):
        source = fixture()
        source['kind'] = 'Deployment'
        with self.assertRaises(ValueError):
            app.select(source)


if __name__ == '__main__':
    unittest.main()
