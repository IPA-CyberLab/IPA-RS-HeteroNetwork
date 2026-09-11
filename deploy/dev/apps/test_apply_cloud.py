import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location(
    'apply_cloud', Path(__file__).with_name('apply-cloud.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

NS = 'heterocloud-dev'
NAMES = (NS, NS + '-owner-console', NS + '-worker')
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud:0.1.71-dev.5@sha256:70a41870b9e5c986512f2665bceb5a4d079dd7e1e0958ac36751b95e7928b9b3'
DATABASE_ARG = '--database-url-file=/var/run/secrets/runtime/database-url'
# Keep the oracle independent of the implementation's constants and bundle.
INVENTORY = {
    ('ServiceAccount', NS), ('Service', NS), ('Service', NS + '-owner-console'),
    *((kind, name) for kind in ('Deployment', 'NetworkPolicy', 'PodDisruptionBudget')
      for name in NAMES),
}


def key(item):
    return item['kind'], item['metadata']['name']


def resource(source, kind, name):
    return next(item for item in source['items'] if key(item) == (kind, name))


def fixture():
    """Minimal public admission fixture, with no runtime files or secret values."""
    items = []
    for kind, name in sorted(INVENTORY):
        item = {'kind': kind, 'metadata': {'name': name, 'namespace': NS}}
        if kind == 'Deployment':
            item['spec'] = {'replicas': 3, 'template': {'spec': {
                'containers': [{'name': 'cloud', 'image': IMAGE, 'args': [DATABASE_ARG]}],
                'serviceAccountName': NS,
                'automountServiceAccountToken': False,
                'securityContext': {'runAsNonRoot': True},
                'affinity': {'podAntiAffinity': {
                    'requiredDuringSchedulingIgnoredDuringExecution': [{
                        'labelSelector': {'matchLabels': {'app.kubernetes.io/instance': NS}},
                        'topologyKey': 'kubernetes.io/hostname',
                    }],
                }},
            }}}
        elif kind == 'ServiceAccount':
            item['automountServiceAccountToken'] = False
        elif kind == 'Service':
            item['spec'] = {'type': 'ClusterIP'}
        elif kind == 'NetworkPolicy':
            item['spec'] = {'podSelector': {
                'matchLabels': {'app.kubernetes.io/instance': NS},
            }}
        items.append(item)
    return {'apiVersion': 'v1', 'kind': 'List', 'items': items}


class CloudAdmission(unittest.TestCase):
    def test_readback_accepts_only_omitted_false_host_network(self):
        wanted = resource(fixture(), 'Deployment', NS)
        wanted['spec']['template']['spec']['hostNetwork'] = False
        actual = copy.deepcopy(wanted)
        actual['spec']['template']['spec'].pop('hostNetwork')
        before = copy.deepcopy(actual)
        self.assertTrue(app.runtime_contains(actual, wanted, lambda a, b: a == b))
        self.assertEqual(actual, before)
        actual['spec']['template']['spec']['hostNetwork'] = True
        self.assertFalse(app.runtime_contains(actual, wanted, lambda a, b: a == b))
        actual = copy.deepcopy(before)
        actual['spec']['template']['spec'].pop('automountServiceAccountToken')
        self.assertFalse(app.runtime_contains(actual, wanted, lambda a, b: a == b))

    def reject(self, source):
        with self.assertRaises(ValueError):
            app.select(source)

    def test_exact_12_resources_without_mutating_input(self):
        source = fixture()
        before = copy.deepcopy(source)
        selected = app.select(source)
        self.assertEqual(len(selected), 12)
        self.assertEqual({key(item) for item in selected}, INVENTORY)
        self.assertEqual(source, before)

    def test_list_required(self):
        for kind in ('Deployment', 'ConfigMap', None):
            with self.subTest(kind=kind):
                source = fixture()
                source['kind'] = kind
                self.reject(source)

    def test_missing_duplicate_extra_and_replaced_resources(self):
        for kind, name in sorted(INVENTORY):
            for change in ('missing', 'duplicate', 'extra', 'replace-with-duplicate', 'rename'):
                with self.subTest(kind=kind, name=name, change=change):
                    source = fixture()
                    item = resource(source, kind, name)
                    if change == 'missing':
                        source['items'].remove(item)
                    elif change == 'duplicate':
                        source['items'].append(copy.deepcopy(item))
                    elif change == 'extra':
                        source['items'].append({
                            'kind': 'ConfigMap', 'metadata': {'name': 'unexpected', 'namespace': NS},
                        })
                    elif change == 'replace-with-duplicate':
                        source['items'].remove(item)
                        source['items'].append(copy.deepcopy(source['items'][0]))
                    else:
                        item['metadata']['name'] += '-unexpected'
                    self.reject(source)

    def test_every_resource_requires_dev_namespace(self):
        for kind, name in sorted(INVENTORY):
            for namespace in ('production', '', None):
                with self.subTest(kind=kind, name=name, namespace=namespace):
                    source = fixture()
                    metadata = resource(source, kind, name)['metadata']
                    if namespace is None:
                        metadata.pop('namespace')
                    else:
                        metadata['namespace'] = namespace
                    self.reject(source)

    def test_every_deployment_requires_exact_pinned_image(self):
        tagged, digest = IMAGE.split('@')
        for name in NAMES:
            for image in (tagged, tagged.rsplit(':', 1)[0] + ':latest',
                          tagged + '@sha256:' + '0' * 64,
                          'example.invalid/cloud@' + digest):
                with self.subTest(name=name, image=image):
                    source = fixture()
                    pod = resource(source, 'Deployment', name)['spec']['template']['spec']
                    pod['containers'][0]['image'] = image
                    self.reject(source)

    def test_every_deployment_requires_three_replicas(self):
        for name in NAMES:
            for replicas in (0, 1, 2, 4, '3', None):
                with self.subTest(name=name, replicas=replicas):
                    source = fixture()
                    resource(source, 'Deployment', name)['spec']['replicas'] = replicas
                    self.reject(source)

    def test_every_deployment_rejects_host_network_and_init_containers(self):
        for name in NAMES:
            for field, value in (('hostNetwork', True), ('initContainers', [{
                    'name': 'init', 'image': IMAGE}])):
                with self.subTest(name=name, field=field):
                    source = fixture()
                    pod = resource(source, 'Deployment', name)['spec']['template']['spec']
                    pod[field] = value
                    self.reject(source)

    def test_token_mounting_must_be_explicitly_disabled(self):
        for kind, name in [('ServiceAccount', NS), *(('Deployment', n) for n in NAMES)]:
            for setting in (True, 'false', None, 'missing'):
                with self.subTest(kind=kind, name=name, setting=setting):
                    source = fixture()
                    target = resource(source, kind, name)
                    if kind == 'Deployment':
                        target = target['spec']['template']['spec']
                    if setting == 'missing':
                        target.pop('automountServiceAccountToken')
                    else:
                        target['automountServiceAccountToken'] = setting
                    self.reject(source)

    def test_bootstrap_flags_rejected_for_every_deployment(self):
        for name in NAMES:
            for flag in ('--bootstrap-admin', '--bootstrap-admin=false',
                         '--bootstrap-owner=public-placeholder', '--bootstrap-unknown'):
                for position in (0, 1):
                    with self.subTest(name=name, flag=flag, position=position):
                        source = fixture()
                        pod = resource(source, 'Deployment', name)['spec']['template']['spec']
                        pod['containers'][0]['args'].insert(position, flag)
                        self.reject(source)

    def test_database_file_argument_required(self):
        for name in NAMES:
            with self.subTest(name=name):
                source = fixture()
                pod = resource(source, 'Deployment', name)['spec']['template']['spec']
                pod['containers'][0]['args'] = []
                self.reject(source)

    def test_services_are_clusterip_only_without_external_ips(self):
        for name in NAMES[:2]:
            for field, value in (('type', 'NodePort'), ('type', 'LoadBalancer'),
                                 ('type', 'ExternalName'), ('externalIPs', ['192.0.2.1'])):
                with self.subTest(name=name, field=field, value=value):
                    source = fixture()
                    resource(source, 'Service', name)['spec'][field] = value
                    self.reject(source)

    def test_network_policies_require_dev_instance_scope(self):
        for name in NAMES:
            for instance in ('production', '', None):
                with self.subTest(name=name, instance=instance):
                    source = fixture()
                    labels = resource(source, 'NetworkPolicy', name)['spec']['podSelector']['matchLabels']
                    labels['app.kubernetes.io/instance'] = instance
                    self.reject(source)

    def test_support_resources_then_api_then_owner_then_worker(self):
        original = fixture()['items']
        for reverse in (False, True):
            for offset in range(len(original)):
                with self.subTest(reverse=reverse, offset=offset):
                    ordered = list(reversed(original)) if reverse else list(original)
                    selected = app.select({'kind': 'List', 'items': ordered[offset:] + ordered[:offset]})
                    self.assertEqual(len(selected), 12)
                    self.assertTrue(all(item['kind'] != 'Deployment' for item in selected[:9]))
                    self.assertEqual([key(item) for item in selected[9:]],
                                     [('Deployment', name) for name in NAMES])


if __name__ == '__main__':
    unittest.main()
