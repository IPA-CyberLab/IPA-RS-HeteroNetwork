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
garage_spec = importlib.util.spec_from_file_location(
    'apply_garage', Path(__file__).with_name('apply-garage.py'))
garage = importlib.util.module_from_spec(garage_spec)
garage_spec.loader.exec_module(garage)

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
    def test_custom_stamp_preserves_annotations_and_is_idempotent(self):
        for annotations in (None, {}, {'helm.sh/hook': 'pre-install',
                                       app.ANNOTATION: app.STAMP}):
            with self.subTest(annotations=annotations):
                item = {'kind': 'Job', 'metadata': {'name': NS + '-migrate',
                                                   'annotations': annotations}}
                expected = copy.deepcopy(item)
                expected['metadata']['annotations'] = {
                    **(annotations or {}), app.ANNOTATION: 'new-release-stamp'}
                for _ in range(2):
                    app.annotate(item, 'new-release-stamp')
                    self.assertEqual(item, expected)

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


class FlowExistingState(unittest.TestCase):
    STAMP = 'new-release-stamp'
    LEGACY_UID = 'b8f31a23-d5b8-4a27-bcd0-e3af56c552b1'

    def objects(self, key, legacy=False):
        old = copy.deepcopy(resource(fixture(), key))
        app.annotate(old)
        desired = copy.deepcopy(old)
        app.annotate(desired, self.STAMP)
        if key[0] in ('Job', 'Deployment'):
            desired['spec']['template']['spec']['containers'][0]['image'] = (
                'example.invalid/flow:new@sha256:' + '1' * 64)
        actual = copy.deepcopy(old if legacy else desired)
        actual['metadata'].update({
            'uid': self.LEGACY_UID if legacy else 'new-resource-uid',
            'resourceVersion': '123',
            'managedFields': [{'manager': 'kube-controller-manager'},
                              {'manager': app.MANAGER}],
        })
        if legacy and key[0] == 'Job':
            actual['spec']['suspend'] = True
        return actual, desired, old

    def check_state(self, expected, actual, desired, old):
        before = copy.deepcopy((actual, desired, old))
        if expected is None:
            with self.assertRaises(ValueError):
                app.existing_state(actual, desired, old, self.STAMP, garage.contains)
        else:
            self.assertEqual(
                app.existing_state(actual, desired, old, self.STAMP, garage.contains),
                expected)
        self.assertEqual((actual, desired, old), before)

    def test_new_matching_resources_present_without_previous_bundle(self):
        for key in sorted(INVENTORY):
            with self.subTest(resource=key):
                actual, desired, _ = self.objects(key)
                self.check_state('present', actual, desired, None)

    def test_old_support_resources_restamp(self):
        for key in sorted(INVENTORY):
            if key[0] not in ('Job', 'Deployment'):
                with self.subTest(resource=key):
                    self.check_state('restamp', *self.objects(key, legacy=True))

    def test_exact_suspended_legacy_job_replaced(self):
        for status in (None, {}, {'active': 0, 'succeeded': 0}):
            with self.subTest(status=status):
                actual, desired, old = self.objects(('Job', NS + '-migrate'), legacy=True)
                if status is not None:
                    actual['status'] = status
                self.check_state('replace', actual, desired, old)

    def test_legacy_job_replacement_guards(self):
        for change in ('active', 'succeeded', 'unsuspended', 'missing-suspend',
                       'nonboolean-suspend', 'wrong-uid', 'manifest-drift', 'no-old'):
            with self.subTest(change=change):
                actual, desired, old = self.objects(('Job', NS + '-migrate'), legacy=True)
                if change in ('active', 'succeeded'):
                    actual['status'] = {change: 1}
                elif change == 'unsuspended':
                    actual['spec']['suspend'] = False
                elif change == 'missing-suspend':
                    actual['spec'].pop('suspend')
                elif change == 'nonboolean-suspend':
                    actual['spec']['suspend'] = 1
                elif change == 'wrong-uid':
                    actual['metadata']['uid'] = 'other-job-uid'
                elif change == 'manifest-drift':
                    actual['spec']['template']['spec']['containers'][0]['image'] = 'wrong'
                else:
                    old = None
                self.check_state(None, actual, desired, old)

    def test_ownership_deletion_and_stamp_guards_for_all_states(self):
        for key in (('ServiceAccount', NS), ('Job', NS + '-migrate'),
                    ('Deployment', NS + '-api')):
            for legacy in (False, True):
                for change in ('wrong-manager', 'missing-manager', 'deleting',
                               'foreign-stamp', 'missing-stamp'):
                    with self.subTest(resource=key, legacy=legacy, change=change):
                        actual, desired, old = self.objects(key, legacy=legacy)
                        metadata = actual['metadata']
                        if change == 'wrong-manager':
                            metadata['managedFields'] = [{'manager': 'foreign-manager'}]
                        elif change == 'missing-manager':
                            metadata.pop('managedFields')
                        elif change == 'deleting':
                            metadata['deletionTimestamp'] = '2026-09-11T00:00:00Z'
                        elif change == 'foreign-stamp':
                            metadata['annotations'][app.ANNOTATION] = 'foreign-stamp'
                        else:
                            metadata.pop('annotations')
                        self.check_state(None, actual, desired, old)

    def test_manifest_drift_rejected_for_new_and_old_support(self):
        for key in sorted(INVENTORY):
            for legacy in (False, True):
                with self.subTest(resource=key, legacy=legacy):
                    actual, desired, old = self.objects(key, legacy=legacy)
                    actual['metadata']['namespace'] = 'foreign-namespace'
                    self.check_state(None, actual, desired, old)

    def test_old_support_without_previous_manifest_rejected(self):
        actual, desired, _ = self.objects(('ServiceAccount', NS), legacy=True)
        self.check_state(None, actual, desired, None)

    def test_new_suspended_job_rejected(self):
        actual, desired, old = self.objects(('Job', NS + '-migrate'))
        actual['spec']['suspend'] = True
        self.check_state(None, actual, desired, old)

    def test_old_deployments_rejected(self):
        for component in COMPONENTS:
            with self.subTest(component=component):
                self.check_state(None, *self.objects(
                    ('Deployment', NS + '-' + component), legacy=True))


class RuntimeReadback(unittest.TestCase):
    def test_empty_env_default_only(self):
        desired = {'kind': 'Deployment', 'spec': {'template': {'spec': {'containers': [
            {'name': 'api', 'env': [{'name': 'METRICS_URL', 'value': ''}]}]}}}}
        actual = copy.deepcopy(desired)
        entry = actual['spec']['template']['spec']['containers'][0]['env'][0]
        del entry['value']
        comparator = lambda a, d: a == d
        self.assertTrue(app.runtime_contains(actual, desired, comparator))
        self.assertNotIn('value', entry)
        entry['valueFrom'] = {'secretKeyRef': {'name': 'unexpected', 'key': 'value'}}
        self.assertFalse(app.runtime_contains(actual, desired, comparator))
        del entry['valueFrom']
        entry['value'] = 'changed'
        self.assertFalse(app.runtime_contains(actual, desired, comparator))


if __name__ == '__main__':
    unittest.main()
