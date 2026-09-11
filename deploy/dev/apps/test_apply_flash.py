import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location('apply_flash', Path(__file__).with_name('apply-flash.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

NS = 'heterocloud-flash-dev'
WORKLOADS = 'heterocloud-flash-dev-workloads'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:0.1.30-dev.1@sha256:cd4150194ff1133ec6faf04567110dab14e905cd436744b02a4892ee1809357b'
# Keep the admission oracle independent of the helper's constants.
INVENTORY = {
    ('CustomResourceDefinition', 'flashservices.flash.heterocloud.io'),
    ('Namespace', WORKLOADS),
    ('ServiceAccount', NS),
    ('Service', NS + '-api'),
    ('ClusterRole', NS + '-node-reader'),
    ('ClusterRoleBinding', NS + '-node-reader'),
    ('Role', NS),
    ('RoleBinding', NS),
    ('Deployment', NS + '-api'),
    ('Deployment', NS + '-controller'),
    ('PodDisruptionBudget', NS + '-api'),
    ('PodDisruptionBudget', NS + '-controller'),
}
CLUSTER_SCOPED = {'Namespace', 'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding'}


def resource(source, kind, name):
    return next(item for item in source['items']
                if (item['kind'], item['metadata']['name']) == (kind, name))


def pod_spec(source, component):
    return resource(source, 'Deployment', NS + '-' + component)['spec']['template']['spec']


def fixture():
    """Public, minimal admission fixture; no runtime bundles or secret values."""
    items = []
    for kind, name in sorted(INVENTORY):
        item = {'kind': kind, 'metadata': {'name': name}}
        if kind not in CLUSTER_SCOPED:
            item['metadata']['namespace'] = WORKLOADS if kind in ('Role', 'RoleBinding') else NS
        if kind == 'Deployment':
            component = name.removeprefix(NS + '-')
            item['spec'] = {
                'replicas': {'api': 3, 'controller': 2}[component],
                'template': {'spec': {
                    'serviceAccountName': NS,
                    'securityContext': {'runAsNonRoot': True},
                    'containers': [{'name': component, 'image': IMAGE, 'env': [
                        {'name': 'FLASH_WORKLOAD_NAMESPACE', 'value': WORKLOADS},
                    ]}],
                    'affinity': {'podAntiAffinity': {
                        'requiredDuringSchedulingIgnoredDuringExecution': [{
                            'labelSelector': {'matchLabels': {'app': name}},
                            'topologyKey': 'kubernetes.io/hostname',
                        }],
                    }},
                }},
            }
        elif kind == 'ClusterRole':
            item['rules'] = [{'apiGroups': [''], 'resources': ['nodes'],
                              'verbs': ['get', 'list', 'watch']}]
        elif kind in ('RoleBinding', 'ClusterRoleBinding'):
            item['subjects'] = [{'kind': 'ServiceAccount', 'name': NS, 'namespace': NS}]
        elif kind == 'Service':
            item['spec'] = {'type': 'ClusterIP'}
        items.append(item)
    return {'apiVersion': 'v1', 'kind': 'List', 'items': items}


class FlashAdmission(unittest.TestCase):
    def test_crd_status_is_server_owned_without_mutating_bundle(self):
        source = {'kind': 'CustomResourceDefinition', 'spec': {'group': 'example.test'},
                  'status': {'acceptedNames': {'kind': ''}, 'storedVersions': None}}
        before = copy.deepcopy(source)
        self.assertEqual(app.desired_crd(source), {'kind': source['kind'], 'spec': source['spec']})
        self.assertEqual(source, before)
        with self.assertRaises(ValueError):
            app.desired_crd({'kind': 'Deployment'})

    def assert_rejected(self, source):
        with self.assertRaisesRegex(ValueError, 'DEV Flash admission rejected'):
            app.select(source)

    def test_exact_12_resources_without_mutating_input(self):
        source = fixture()
        before = copy.deepcopy(source)
        selected = app.select(source)
        self.assertEqual(len(selected), 12)
        self.assertEqual({(x['kind'], x['metadata']['name']) for x in selected}, INVENTORY)
        self.assertEqual(source, before)

    def test_list_required(self):
        for kind in ('Deployment', '', None):
            with self.subTest(kind=kind):
                source = fixture()
                source['kind'] = kind
                self.assert_rejected(source)

    def test_exact_inventory_required(self):
        for kind, name in sorted(INVENTORY):
            for change in ('missing', 'duplicate', 'rename', 'wrong-kind', 'replace-with-duplicate'):
                with self.subTest(kind=kind, name=name, change=change):
                    source = fixture()
                    item = resource(source, kind, name)
                    if change == 'missing':
                        source['items'].remove(item)
                    elif change == 'duplicate':
                        source['items'].append(copy.deepcopy(item))
                    elif change == 'rename':
                        item['metadata']['name'] += '-unexpected'
                    elif change == 'wrong-kind':
                        item['kind'] = 'ConfigMap'
                    else:
                        source['items'].remove(item)
                        source['items'].append(copy.deepcopy(source['items'][0]))
                    self.assert_rejected(source)

    def test_namespace_identity_for_every_resource(self):
        for kind, name in sorted(INVENTORY):
            expected = (None if kind in CLUSTER_SCOPED else
                        WORKLOADS if kind in ('Role', 'RoleBinding') else NS)
            for namespace in (None, '', 'production', NS, WORKLOADS):
                if namespace == expected:
                    continue
                with self.subTest(kind=kind, name=name, namespace=namespace):
                    source = fixture()
                    metadata = resource(source, kind, name)['metadata']
                    if namespace is None:
                        metadata.pop('namespace')
                    else:
                        metadata['namespace'] = namespace
                    self.assert_rejected(source)

    def test_fixed_image_for_both_deployments(self):
        for component in ('api', 'controller'):
            for image in (IMAGE.split('@')[0], 'flash:latest',
                          IMAGE.split('@')[0] + '@sha256:' + '0' * 64,
                          'example.com/flash@' + IMAGE.split('@')[1]):
                with self.subTest(component=component, image=image):
                    source = fixture()
                    pod_spec(source, component)['containers'][0]['image'] = image
                    self.assert_rejected(source)

    def test_api_three_controller_two_replicas(self):
        for component, expected in (('api', 3), ('controller', 2)):
            for replicas in (0, 1, 2, 3, 4, str(expected), None):
                if replicas == expected:
                    continue
                with self.subTest(component=component, replicas=replicas):
                    source = fixture()
                    resource(source, 'Deployment', NS + '-' + component)['spec']['replicas'] = replicas
                    self.assert_rejected(source)

    def test_node_reader_rules_are_exactly_scoped(self):
        changes = [('apiGroups', ['*']), ('apiGroups', ['apps']),
                   ('resources', ['*']), ('resources', ['nodes', 'pods']),
                   ('verbs', ['*']), ('verbs', ['get', 'list', 'watch', 'create']),
                   ('verbs', ['get'])]
        for field, value in changes + [('empty', None), ('extra-rule', None)]:
            with self.subTest(field=field, value=value):
                source = fixture()
                role = resource(source, 'ClusterRole', NS + '-node-reader')
                if field == 'empty':
                    role['rules'] = []
                elif field == 'extra-rule':
                    role['rules'].append(copy.deepcopy(role['rules'][0]))
                else:
                    role['rules'][0][field] = value
                self.assert_rejected(source)

    def test_binding_subjects_use_control_plane_service_account(self):
        for kind, name in (('RoleBinding', NS), ('ClusterRoleBinding', NS + '-node-reader')):
            for field, value in (('kind', 'User'), ('name', 'default'),
                                 ('namespace', WORKLOADS), ('namespace', 'production'),
                                 ('missing-namespace', None), ('empty', None), ('extra', None)):
                with self.subTest(kind=kind, field=field, value=value):
                    source = fixture()
                    binding = resource(source, kind, name)
                    if field == 'empty':
                        binding['subjects'] = []
                    elif field == 'extra':
                        binding['subjects'].append(copy.deepcopy(binding['subjects'][0]))
                    elif field == 'missing-namespace':
                        binding['subjects'][0].pop('namespace')
                    else:
                        binding['subjects'][0][field] = value
                    self.assert_rejected(source)

    def test_workload_namespace_env_for_both_deployments(self):
        for component in ('api', 'controller'):
            for env in ([], [{'name': 'OTHER_NAMESPACE', 'value': WORKLOADS}],
                        [{'name': 'FLASH_WORKLOAD_NAMESPACE', 'value': NS}],
                        [{'name': 'FLASH_WORKLOAD_NAMESPACE', 'value': 'production'}],
                        [{'name': 'FLASH_WORKLOAD_NAMESPACE', 'valueFrom': {
                            'fieldRef': {'fieldPath': 'metadata.namespace'}}}]):
                with self.subTest(component=component, env=env):
                    source = fixture()
                    pod_spec(source, component)['containers'][0]['env'] = env
                    self.assert_rejected(source)

    def test_pod_safety_for_both_deployments(self):
        for component in ('api', 'controller'):
            for field, value in (
                ('hostNetwork', True),
                ('initContainers', [{'name': 'init', 'image': IMAGE}]),
                ('containers', []),
                ('containers', [{'image': IMAGE}, {'image': IMAGE}]),
                ('serviceAccountName', 'default'),
                ('securityContext', {'runAsNonRoot': False}),
                ('securityContext', {'runAsNonRoot': 'true'}),
                ('affinity', {'podAntiAffinity': {
                    'requiredDuringSchedulingIgnoredDuringExecution': []}}),
            ):
                with self.subTest(component=component, field=field):
                    source = fixture()
                    pod_spec(source, component)[field] = value
                    self.assert_rejected(source)

    def test_explicit_disabled_hostnetwork_and_empty_initcontainers_allowed(self):
        source = fixture()
        for component in ('api', 'controller'):
            pod_spec(source, component).update(hostNetwork=False, initContainers=[])
        self.assertEqual(len(app.select(source)), 12)

    def test_service_is_internal_clusterip(self):
        for field, value in (('type', 'NodePort'), ('type', 'LoadBalancer'),
                             ('type', 'ExternalName'), ('type', None),
                             ('externalIPs', ['192.0.2.1'])):
            with self.subTest(field=field, value=value):
                source = fixture()
                resource(source, 'Service', NS + '-api')['spec'][field] = value
                self.assert_rejected(source)

    def test_namespace_then_crd_then_support_before_deployments(self):
        original = fixture()['items']
        for reverse in (False, True):
            for offset in range(len(original)):
                with self.subTest(reverse=reverse, offset=offset):
                    items = list(reversed(original)) if reverse else original[:]
                    selected = app.select({'kind': 'List', 'items': items[offset:] + items[:offset]})
                    self.assertEqual([x['kind'] for x in selected[:2]],
                                     ['Namespace', 'CustomResourceDefinition'])
                    self.assertFalse(any(x['kind'] == 'Deployment' for x in selected[:-2]))
                    self.assertEqual([x['metadata']['name'] for x in selected[-2:]],
                                     [NS + '-api', NS + '-controller'])
                    self.assertEqual([x['kind'] for x in selected[-2:]], ['Deployment'] * 2)


if __name__ == '__main__':
    unittest.main()
