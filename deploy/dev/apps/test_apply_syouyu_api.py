import copy
import importlib.util
import itertools
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location('apply_syouyu_api',
                                            Path(__file__).with_name('apply-syouyu-api.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

NS = 'heterocloud-syouyu-dev'
NAME = NS + '-api'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-syouyu:0.1.7-dev.2@sha256:2021bc7161146b212e41ec51ae5f1e127d11cfa03ad03d588e05de2335a0d1d6'
# Independent inventories keep the fixture from inheriting helper allowlist changes.
INVENTORY = {(kind, NAME) for kind in ('Deployment', 'Service', 'NetworkPolicy')}
STORAGE_INVENTORY = {
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


def object_key(item):
    return item['kind'], item['metadata']['name']


def api_object(source, kind):
    return next(item for item in source['items'] if object_key(item) == (kind, NAME))


def pod_spec(source):
    return api_object(source, 'Deployment')['spec']['template']['spec']


def fixture():
    """Public, minimal chart-shaped objects; no runtime files or secret values."""
    labels = {'app.kubernetes.io/name': 'heterocloud-syouyu',
              'app.kubernetes.io/instance': NS,
              'app.kubernetes.io/component': 'api'}
    items = []
    for kind, name in sorted(INVENTORY | STORAGE_INVENTORY):
        metadata = {'name': name}
        if kind not in {'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding'}:
            metadata['namespace'] = NS
        items.append({'kind': kind, 'metadata': metadata})
    source = {'apiVersion': 'v1', 'kind': 'List', 'items': items}
    api_object(source, 'Deployment')['spec'] = {
        'replicas': 3,
        'selector': {'matchLabels': dict(labels)},
        'template': {
            'metadata': {'labels': dict(labels)},
            'spec': {'containers': [{'name': 'api', 'image': IMAGE}],
                     'automountServiceAccountToken': False},
        },
    }
    api_object(source, 'Service')['spec'] = {
        'selector': dict(labels), 'ports': [{'port': 80, 'targetPort': 8080}],
    }
    api_object(source, 'NetworkPolicy')['spec'] = {
        'podSelector': {'matchLabels': dict(labels)},
        'policyTypes': ['Ingress', 'Egress'],
    }
    return source


class SyouyuApiAdmission(unittest.TestCase):
    def test_exact_inventory_excludes_storage_resources(self):
        source = fixture()
        before = copy.deepcopy(source)
        self.assertEqual(len(source['items']), 21)
        items, pod = app.select(source)
        self.assertEqual(len(items), 3)
        self.assertEqual({object_key(item) for item in items}, INVENTORY)
        self.assertTrue(STORAGE_INVENTORY.isdisjoint(map(object_key, items)))
        self.assertIs(pod, pod_spec(source))
        self.assertEqual(source, before)

    def test_deployment_last_regardless_of_input_order(self):
        for order in itertools.permutations(('Deployment', 'Service', 'NetworkPolicy')):
            with self.subTest(order=order):
                source = fixture()
                storage = [item for item in source['items']
                           if object_key(item) in STORAGE_INVENTORY]
                source['items'] = [api_object(source, kind) for kind in order] + storage
                items, _ = app.select(source)
                self.assertEqual(object_key(items[-1]), ('Deployment', NAME))
                self.assertEqual({object_key(item) for item in items[:-1]},
                                 {('Service', NAME), ('NetworkPolicy', NAME)})

    def test_duplicate_missing_or_replaced_inventory_rejected(self):
        for kind, name in sorted(INVENTORY):
            for change in ('duplicate', 'missing', 'replace-with-duplicate', 'rename'):
                with self.subTest(resource=(kind, name), change=change):
                    source = fixture()
                    item = api_object(source, kind)
                    if change == 'duplicate':
                        source['items'].append(copy.deepcopy(item))
                    elif change == 'rename':
                        item['metadata']['name'] = name + '-unexpected'
                    else:
                        source['items'].remove(item)
                        if change == 'replace-with-duplicate':
                            other = next(item for item in source['items']
                                         if object_key(item) in INVENTORY)
                            source['items'].append(copy.deepcopy(other))
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_wrong_or_missing_namespace_rejected_for_every_api_object(self):
        for kind, _ in sorted(INVENTORY):
            for namespace in ('production', '', None):
                with self.subTest(kind=kind, namespace=namespace):
                    source = fixture()
                    metadata = api_object(source, kind)['metadata']
                    if namespace is None:
                        metadata.pop('namespace')
                    else:
                        metadata['namespace'] = namespace
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_mutable_or_unapproved_image_rejected(self):
        repository = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-syouyu'
        for image in (repository + ':latest', repository + ':0.1.7-dev.2',
                      repository + ':0.1.7-dev.2@sha256:' + '0' * 64,
                      'example.com/unapproved/api@' + IMAGE.split('@')[1]):
            with self.subTest(image=image):
                source = fixture()
                pod_spec(source)['containers'][0]['image'] = image
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_wrong_replica_count_rejected(self):
        for replicas in (0, 1, 2, 4, '3', None):
            with self.subTest(replicas=replicas):
                source = fixture()
                api_object(source, 'Deployment')['spec']['replicas'] = replicas
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_unsafe_pod_configuration_rejected(self):
        for field, value in (
            ('hostNetwork', True),
            ('initContainers', [{'name': 'init', 'image': IMAGE}]),
            ('containers', []),
            ('containers', [{'name': 'api', 'image': IMAGE}, {'name': 'extra', 'image': IMAGE}]),
            ('automountServiceAccountToken', True),
            ('automountServiceAccountToken', None),
            ('automountServiceAccountToken', 'false'),
            ('automountServiceAccountToken', 0),
        ):
            with self.subTest(field=field, value=value):
                source = fixture()
                pod_spec(source)[field] = value
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_missing_automount_setting_rejected(self):
        source = fixture()
        pod_spec(source).pop('automountServiceAccountToken')
        with self.assertRaises(ValueError):
            app.select(source)

    def test_explicit_disabled_hostnetwork_and_empty_initcontainers_accepted(self):
        source = fixture()
        pod_spec(source).update(hostNetwork=False, initContainers=[])
        items, pod = app.select(source)
        self.assertEqual({object_key(item) for item in items}, INVENTORY)
        self.assertIs(pod, pod_spec(source))

    def test_broad_or_foreign_network_policy_rejected(self):
        for selector in ({}, {'matchLabels': {}},
                         {'matchLabels': {'app.kubernetes.io/name': 'heterocloud-syouyu'}},
                         {'matchLabels': {'app.kubernetes.io/instance': 'production'}},
                         {'matchExpressions': [{'key': 'app.kubernetes.io/instance',
                                                'operator': 'Exists'}]}):
            with self.subTest(selector=selector):
                source = fixture()
                api_object(source, 'NetworkPolicy')['spec']['podSelector'] = selector
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_non_list_document_rejected(self):
        source = fixture()
        source['kind'] = 'Deployment'
        with self.assertRaises(ValueError):
            app.select(source)


if __name__ == '__main__':
    unittest.main()
