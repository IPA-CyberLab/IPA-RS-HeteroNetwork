import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location('apply_flow', Path(__file__).with_name('apply-flow.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

NS = 'heterocloud-flow-dev'
COMPONENTS = ('api', 'matchmaker', 'signaling', 'livekit', 'coturn')
FLOW_IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow:0.1.21-dev.6@sha256:e768fe4d5846e1c7a4e86199a97684aa87dfd75a7ea431550a8e1dcb2470721b'
IMAGES = {
    **{name: FLOW_IMAGE for name in ('api', 'matchmaker', 'signaling', 'migrate')},
    'livekit': 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit:0.1.21-dev.6@sha256:02920c1d1d5dc4957105692fa236c11abba8a7825e3bf3153e3cbddd69ea949b',
    'coturn': 'docker.io/coturn/coturn:4.16.0@sha256:01fc8655e7c262fa4ccfb8dca74ff80fb372b0ee021e80370a4d3e3dd01a951e',
}
# Independent inventories and images keep helper changes from changing the oracle.
INVENTORY = {
    ('ServiceAccount', NS),
    ('Job', NS + '-migrate'),
    *(('Deployment', NS + '-' + name) for name in COMPONENTS),
    *(('PodDisruptionBudget', NS + '-' + name) for name in COMPONENTS),
    *(('NetworkPolicy', NS + '-' + name)
      for name in ('default-deny', 'control-plane', 'media-plane')),
    *(('Service', NS + '-' + name)
      for name in ('api', 'turn', 'coturn-metrics', 'livekit', 'livekit-signal',
                   'livekit-rtc', 'signaling')),
}
REDIS_INVENTORY = {
    ('NetworkPolicy', NS + '-redis'),
    ('PodDisruptionBudget', NS + '-redis-node'),
    ('ServiceAccount', NS + '-redis'),
    ('StatefulSet', NS + '-redis-node'),
    ('Service', NS + '-redis'),
    ('Service', NS + '-redis-headless'),
    *(('ConfigMap', NS + '-redis-' + name)
      for name in ('configuration', 'health', 'scripts')),
}
WORKLOADS = sorted(key for key in INVENTORY if key[0] in ('Deployment', 'Job'))


def object_key(item):
    return item['kind'], item['metadata']['name']


def resource(source, key):
    return next(item for item in source['items'] if object_key(item) == key)


def pod_spec(source, key):
    return resource(source, key)['spec']['template']['spec']


def fixture():
    """Public, minimal chart-shaped objects; no runtime files or secret values."""
    items = []
    for kind, name in sorted(INVENTORY | REDIS_INVENTORY):
        item = {'kind': kind, 'metadata': {'name': name, 'namespace': NS}}
        if (kind, name) in REDIS_INVENTORY:
            item['metadata']['labels'] = {'app.kubernetes.io/name': 'redis',
                                          'app.kubernetes.io/instance': NS}
        if (kind, name) in WORKLOADS:
            component = name.removeprefix(NS + '-')
            container = {'name': component, 'image': IMAGES[component]}
            pod = {'containers': [container], 'automountServiceAccountToken': False}
            if component == 'coturn':
                pod['hostNetwork'] = True
            item['spec'] = {'template': {'spec': pod}}
            if kind == 'Deployment':
                item['spec']['replicas'] = 3
            else:
                container['command'] = ['/usr/local/bin/flow-api', 'migrate']
        items.append(item)
    return {'apiVersion': 'v1', 'kind': 'List', 'items': items}


class FlowAdmission(unittest.TestCase):
    def test_exact_22_inventory_excludes_redis_without_mutating_input(self):
        source = fixture()
        before = copy.deepcopy(source)
        self.assertEqual(len(source['items']), 31)
        items = app.select(source)
        self.assertEqual(len(items), 22)
        self.assertEqual({object_key(item) for item in items}, INVENTORY)
        self.assertTrue(REDIS_INVENTORY.isdisjoint(map(object_key, items)))
        self.assertEqual(source, before)

    def test_support_then_migration_then_five_deployments(self):
        original = fixture()['items']
        for reverse in (False, True):
            for offset in range(len(original)):
                with self.subTest(reverse=reverse, offset=offset):
                    ordered = list(reversed(original)) if reverse else list(original)
                    source = {'kind': 'List', 'items': ordered[offset:] + ordered[:offset]}
                    items = app.select(source)
                    self.assertEqual(len(items[:16]), 16)
                    self.assertFalse(any(item['kind'] in ('Job', 'Deployment')
                                         for item in items[:16]))
                    self.assertEqual(object_key(items[16]), ('Job', NS + '-migrate'))
                    self.assertEqual([item['kind'] for item in items[17:]], ['Deployment'] * 5)
                    self.assertEqual({object_key(item) for item in items[17:]},
                                     {('Deployment', NS + '-' + name) for name in COMPONENTS})

    def test_duplicate_missing_renamed_or_replaced_inventory_rejected(self):
        for key in sorted(INVENTORY):
            for change in ('duplicate', 'missing', 'rename', 'replace-with-duplicate'):
                with self.subTest(resource=key, change=change):
                    source = fixture()
                    item = resource(source, key)
                    if change == 'duplicate':
                        source['items'].append(copy.deepcopy(item))
                    elif change == 'rename':
                        item['metadata']['name'] += '-unexpected'
                    else:
                        source['items'].remove(item)
                        if change == 'replace-with-duplicate':
                            other = next(item for item in source['items']
                                         if object_key(item) in INVENTORY)
                            source['items'].append(copy.deepcopy(other))
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_wrong_or_missing_namespace_rejected_for_every_selected_object(self):
        for key in sorted(INVENTORY):
            for namespace in ('production', '', None):
                with self.subTest(resource=key, namespace=namespace):
                    source = fixture()
                    metadata = resource(source, key)['metadata']
                    if namespace is None:
                        metadata.pop('namespace')
                    else:
                        metadata['namespace'] = namespace
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_mutable_or_unapproved_image_rejected_for_every_workload(self):
        for key in WORKLOADS:
            approved = IMAGES[key[1].removeprefix(NS + '-')]
            tagged = approved.split('@')[0]
            for image in (tagged, tagged.rsplit(':', 1)[0] + ':latest',
                          tagged + '@sha256:' + '0' * 64,
                          'example.com/unapproved/image@' + approved.split('@')[1]):
                with self.subTest(resource=key, image=image):
                    source = fixture()
                    pod_spec(source, key)['containers'][0]['image'] = image
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_migration_command_must_match_exactly(self):
        for command in ([], ['migrate'], ['/usr/local/bin/flow-api'],
                        ['/usr/local/bin/flow-api', 'serve'],
                        ['/usr/local/bin/flow-api', 'migrate', '--extra'],
                        ['/bin/sh', '-c', '/usr/local/bin/flow-api migrate'],
                        '/usr/local/bin/flow-api migrate', None):
            with self.subTest(command=command):
                source = fixture()
                pod_spec(source, ('Job', NS + '-migrate'))['containers'][0]['command'] = command
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_wrong_replica_count_rejected_for_every_deployment(self):
        for key in WORKLOADS:
            if key[0] != 'Deployment':
                continue
            for replicas in (0, 1, 2, 4, '3', None):
                with self.subTest(resource=key, replicas=replicas):
                    source = fixture()
                    resource(source, key)['spec']['replicas'] = replicas
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_hostnetwork_required_only_for_coturn(self):
        for key in WORKLOADS:
            coturn = key == ('Deployment', NS + '-coturn')
            for setting in ('missing', False, True):
                with self.subTest(resource=key, hostnetwork=setting):
                    source = fixture()
                    pod = pod_spec(source, key)
                    if setting == 'missing':
                        pod.pop('hostNetwork', None)
                    else:
                        pod['hostNetwork'] = setting
                    if (setting is True) == coturn:
                        self.assertEqual(len(app.select(source)), 22)
                    else:
                        with self.assertRaises(ValueError):
                            app.select(source)

    def test_unsafe_pod_configuration_rejected_for_every_workload(self):
        for key in WORKLOADS:
            for field, value in (
                ('initContainers', [{'name': 'init', 'image': FLOW_IMAGE}]),
                ('containers', []),
                ('containers', [{'name': 'first', 'image': FLOW_IMAGE},
                                {'name': 'extra', 'image': FLOW_IMAGE}]),
                ('automountServiceAccountToken', True),
                ('automountServiceAccountToken', None),
                ('automountServiceAccountToken', 'false'),
                ('automountServiceAccountToken', 0),
            ):
                with self.subTest(resource=key, field=field, value=value):
                    source = fixture()
                    pod_spec(source, key)[field] = value
                    with self.assertRaises(ValueError):
                        app.select(source)

    def test_missing_automount_setting_rejected_for_every_workload(self):
        for key in WORKLOADS:
            with self.subTest(resource=key):
                source = fixture()
                pod_spec(source, key).pop('automountServiceAccountToken')
                with self.assertRaises(ValueError):
                    app.select(source)

    def test_empty_initcontainers_accepted(self):
        source = fixture()
        for key in WORKLOADS:
            pod_spec(source, key)['initContainers'] = []
        self.assertEqual({object_key(item) for item in app.select(source)}, INVENTORY)

    def test_non_list_document_rejected(self):
        source = fixture()
        source['kind'] = 'Deployment'
        with self.assertRaises(ValueError):
            app.select(source)


class FlowAnnotations(unittest.TestCase):
    def test_missing_null_or_empty_annotations_normalized(self):
        for metadata in ({'name': NS}, {'name': NS, 'annotations': None},
                         {'name': NS, 'annotations': {}}):
            with self.subTest(metadata=metadata):
                item = {'kind': 'ServiceAccount', 'metadata': copy.deepcopy(metadata)}
                app.annotate(item)
                self.assertEqual(item, {
                    'kind': 'ServiceAccount',
                    'metadata': {'name': NS, 'annotations': {app.ANNOTATION: app.STAMP}},
                })

    def test_existing_hook_annotations_retained_and_stamp_updated(self):
        item = resource(fixture(), ('Job', NS + '-migrate'))
        hooks = {'helm.sh/hook': 'pre-install,pre-upgrade',
                 'helm.sh/hook-weight': '-5',
                 'helm.sh/hook-delete-policy': 'before-hook-creation'}
        item['metadata']['annotations'] = {**hooks, app.ANNOTATION: 'old-stamp'}
        expected = copy.deepcopy(item)
        expected['metadata']['annotations'][app.ANNOTATION] = app.STAMP
        app.annotate(item)
        self.assertEqual(item, expected)
        app.annotate(item)
        self.assertEqual(item, expected)

    def test_non_dict_annotations_rejected_without_mutating_item(self):
        for annotations in ('', 'annotation', [], ['annotation'], False, 0, 1):
            with self.subTest(annotations=annotations):
                item = {'kind': 'ServiceAccount',
                        'metadata': {'name': NS, 'annotations': annotations}}
                before = copy.deepcopy(item)
                with self.assertRaises(ValueError):
                    app.annotate(item)
                self.assertEqual(item, before)


if __name__ == '__main__':
    unittest.main()
