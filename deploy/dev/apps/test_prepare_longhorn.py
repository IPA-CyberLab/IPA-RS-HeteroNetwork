"""Offline tests; synthetic digests are fixtures, never real image approvals."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

SPEC = importlib.util.spec_from_file_location(
    'prepare_longhorn', Path(__file__).with_name('prepare-longhorn.py'))
lh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lh)
CHART = Path('/tmp/longhorn-1.12.1.tgz')
HELM = Path('/home/coder/.local/bin/helm')


class PolicyTests(unittest.TestCase):
    def test_installation_excludes_lifecycle_hooks_and_crd_status(self):
        documents = [
            {'kind': 'Job', 'metadata': {'name': 'longhorn-uninstall', 'annotations': {'helm.sh/hook': 'pre-delete'}}},
            {'kind': 'Job', 'metadata': {'name': 'longhorn-post-upgrade', 'annotations': {'helm.sh/hook': 'post-upgrade'}}},
            {'kind': 'CustomResourceDefinition', 'metadata': {'name': 'volumes.longhorn.io'}, 'status': {}},
        ]
        before = copy.deepcopy(documents)
        result = lh.installation_objects(documents)
        self.assertEqual(result['items'], [{'kind': 'CustomResourceDefinition', 'metadata': {'name': 'volumes.longhorn.io'}}])
        self.assertEqual(documents, before)
        with self.assertRaises(ValueError):
            lh.installation_objects([{'kind': 'Job', 'metadata': {'name': 'unexpected'}}])

    def test_chart_hash_fails_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'chart SHA256'):
            lh.chart_inputs(b'not a chart', lh.VALUES.read_bytes())

    def test_unknown_values_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unknown chart value'):
            lh.allowed_values({'csi': {'madeUp': 3}}, {'csi': {}})

    def test_source_namespace_and_container_pin_rejected(self):
        for document, message in [
            ({'metadata': {'namespace': 'prod'}}, 'namespace'),
            ({'subjects': [{'namespace': 'default'}]}, 'namespace'),
            ({'spec': {'image': 'repo:latest'}}, 'Unpinned container'),
        ]:
            with self.subTest(document=document):
                with self.assertRaisesRegex(ValueError, message):
                    lh.validate_render(yaml.safe_dump(document), {})

    def test_runtime_pin_coverage(self):
        source = 'docker.io/repo:v1'
        pins = {'longhorn.engine': source + '@sha256:' + 'a' * 64}
        with self.assertRaisesRegex(ValueError, 'Unpinned runtime'):
            lh.validate_render(yaml.safe_dump({'command': [source]}), pins)
        with self.assertRaisesRegex(ValueError, 'Not all required'):
            lh.validate_render('kind: List\nitems: []\n', pins)


@unittest.skipUnless(CHART.exists(), 'Pinned local Longhorn chart required')
class ChartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.values, self.images, _ = lh.chart_inputs(
            CHART.read_bytes(), lh.VALUES.read_bytes())
        self.pins = {key: self.images[key] + '@sha256:' + f'{i:064x}'
                     for i, key in enumerate(sorted(self.images), 1)}

    def pin_file(self):
        path = self.root / 'pins.json'
        path.write_bytes(lh.encoded(self.pins))
        return path

    def test_exact_profile_required(self):
        mutations = [
            ('namespaceOverride', 'default'),
            ('persistence', {'defaultClass': True}),
            ('defaultSettings', {'createDefaultDiskLabeledNodes': False}),
            ('defaultSettings', {'defaultReplicaCount': '1'}),
            ('csi', {'attacherReplicaCount': 1}),
            ('extraObjects', []),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(self.values)
                changed[key] = value
                with self.assertRaisesRegex(ValueError, 'bounded DEV profile'):
                    lh.chart_inputs(CHART.read_bytes(), yaml.safe_dump(changed).encode())

    def test_missing_extra_mutable_and_wrong_repository_pins(self):
        key = next(iter(self.pins))
        source = self.images[key]
        invalid = [None, {}, {**self.pins, 'unexpected': 'x'}]
        for value in [source, source + '@sha256:abc',
                      'docker.io/other:v1@sha256:' + 'a' * 64]:
            invalid.append({**self.pins, key: value})
        for pins in invalid:
            with self.subTest(pins=pins):
                with self.assertRaises(ValueError):
                    lh.apply_pins(copy.deepcopy(self.values), self.images, pins)

    def test_without_pins_no_helm_no_manifest(self):
        output = self.root / 'inventory'
        with patch.object(lh.subprocess, 'run', side_effect=AssertionError('No Helm')):
            report = lh.prepare(CHART, output)
        self.assertFalse(report['deployable'])
        self.assertFalse(report['image_digests_pinned'])
        self.assertIn('not yet pinned', report['unmet_requirements'][0])
        self.assertFalse((output / 'review-only.yaml').exists())
        self.assertEqual(len(json.loads((output / 'image-inventory.json').read_bytes())), 13)
        for name, digest in report['files_sha256'].items():
            self.assertEqual(lh.sha((output / name).read_bytes()), digest)

    def test_exclusive_output(self):
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            lh.prepare(CHART, self.root)
        link = self.root / 'link'
        link.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            lh.prepare(CHART, link)

    @unittest.skipUnless(HELM.exists(), 'Local Helm required')
    def test_real_chart_render_ha_safety_and_reproducibility(self):
        pins = self.pin_file()
        first, second = self.root / 'first', self.root / 'second'
        report = lh.prepare(CHART, first, pins, HELM)
        lh.prepare(CHART, second, pins, HELM)
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        self.assertTrue(report['image_digests_pinned'])
        self.assertFalse(report['registry_content_validated'])
        self.assertFalse(report['deployable'])
        docs = list(yaml.safe_load_all((first / 'review-only.yaml').read_bytes()))
        docs = [d for d in docs if d]
        by_name = {(d['kind'], d['metadata']['name']): d for d in docs}
        settings = yaml.safe_load(by_name['ConfigMap', 'longhorn-default-setting']
                                  ['data']['default-setting.yaml'])
        self.assertTrue(settings['create-default-disk-labeled-nodes'])
        self.assertTrue(settings['v1-data-engine'])
        self.assertFalse(settings['v2-data-engine'])
        self.assertFalse(settings['replica-soft-anti-affinity'])
        self.assertEqual(json.loads(settings['default-replica-count']), {'v1': '3', 'v2': '3'})
        manager = by_name['DaemonSet', 'longhorn-manager']
        self.assertEqual(manager['spec']['updateStrategy']['rollingUpdate']['maxUnavailable'], 1)
        driver = by_name['Deployment', 'longhorn-driver-deployer']
        env = {e['name']: e.get('value') for e in driver['spec']['template']['spec']['containers'][0]['env']}
        self.assertEqual(env['CSI_POD_ANTI_AFFINITY_PRESET'], 'hard')
        for component in ('ATTACHER', 'PROVISIONER', 'RESIZER', 'SNAPSHOTTER'):
            self.assertEqual(env[f'CSI_{component}_REPLICA_COUNT'], '3')
        self.assertEqual(by_name['Deployment', 'longhorn-ui']['spec']['replicas'], 2)
        self.assertEqual(by_name['PodDisruptionBudget', 'longhorn-ui']['spec']['minAvailable'], 1)
        classes = [d for d in docs if d['kind'] == 'StorageClass']
        self.assertEqual(len(classes), 1)
        sc = classes[0]
        self.assertEqual(sc['metadata']['name'], 'dev-flash-rwx')
        self.assertEqual(sc['reclaimPolicy'], 'Retain')
        self.assertEqual(sc['parameters'], {'numberOfReplicas': '3', 'fsType': 'ext4',
                                            'migratable': 'false', 'dataEngine': 'v1'})
        self.assertEqual(sc['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'], 'false')
        for doc in docs:
            self.assertNotIn(doc['kind'], ('Ingress', 'HTTPRoute', 'Node', 'PersistentVolume', 'PersistentVolumeClaim'))
            if doc['kind'] == 'Service':
                self.assertEqual(doc['spec'].get('type', 'ClusterIP'), 'ClusterIP')
            if doc['kind'] not in ('StorageClass', 'ClusterRole', 'ClusterRoleBinding',
                                   'CustomResourceDefinition', 'PriorityClass'):
                self.assertEqual(doc['metadata']['namespace'], lh.NAMESPACE)
        self.assertNotIn('node.longhorn.io/create-default-disk', (first / 'review-only.yaml').read_text())


if __name__ == '__main__':
    unittest.main()
