import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location('apply_redis', Path(__file__).with_name('apply-redis.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def fixture():
    items = [{'kind': kind, 'metadata': {'name': name, 'namespace': app.NS,
              'labels': {'app.kubernetes.io/name': 'redis', 'app.kubernetes.io/instance': 'heterocloud-flow-dev'}}}
             for kind, name in sorted(app.EXPECTED)]
    sts = next(d for d in items if d['kind'] == 'StatefulSet')
    sts['spec'] = {'replicas': 3, 'template': {'spec': {
        'containers': [{'name': k, 'image': v} for k, v in app.IMAGES.items()],
        'affinity': {'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [{'topologyKey': 'kubernetes.io/hostname'}]}}}},
        'volumeClaimTemplates': [{'metadata': {'name': 'redis-data'}, 'spec': {
            'storageClassName': 'dev-app-local', 'resources': {'requests': {'storage': '8Gi'}}}}]}
    return {'kind': 'List', 'items': items}


class RedisAdmission(unittest.TestCase):
    def test_exact_inventory_statefulset_last(self):
        items, _ = app.select(fixture())
        self.assertEqual(len(items), 9)
        self.assertEqual(items[-1]['kind'], 'StatefulSet')

    def test_foreign_namespace_and_mutable_image_rejected(self):
        source = fixture()
        source['items'][0]['metadata']['namespace'] = 'production'
        with self.assertRaises(ValueError):
            app.select(source)
        source = fixture()
        next(d for d in source['items'] if d['kind'] == 'StatefulSet')['spec']['template']['spec']['containers'][0]['image'] = 'redis:latest'
        with self.assertRaises(ValueError):
            app.select(source)

    def test_duplicate_inventory_rejected(self):
        source = fixture()
        source['items'].append(copy.deepcopy(source['items'][0]))
        with self.assertRaises(ValueError):
            app.select(source)

    def test_server_defaults_preserve_requested_fields(self):
        self.assertTrue(app.contains({'spec': {'replicas': 3, 'revisionHistoryLimit': 10}},
                                     {'spec': {'replicas': 3, 'optional': None}}))
        self.assertFalse(app.contains({'spec': {'replicas': 1}}, {'spec': {'replicas': 3}}))


if __name__ == '__main__':
    unittest.main()
