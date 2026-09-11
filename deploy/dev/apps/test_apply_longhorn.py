import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'gitops/environments'))
spec = importlib.util.spec_from_file_location('apply_longhorn', Path(__file__).with_name('apply-longhorn.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def fixture():
    items = [{'kind': 'ConfigMap', 'metadata': {'name': f'fixture-{i}', 'namespace': 'longhorn-system'}}
             for i in range(50)]
    items.append({'kind': 'StorageClass', 'metadata': {'name': 'dev-flash-rwx', 'annotations': {
        'storageclass.kubernetes.io/is-default-class': 'false'}}, 'provisioner': 'driver.longhorn.io',
        'parameters': {'numberOfReplicas': '3', 'migratable': 'false'}, 'reclaimPolicy': 'Retain'})
    return {'kind': 'List', 'items': items}


class Admission(unittest.TestCase):
    def test_priority_default_normalization_does_not_hide_true(self):
        original = {'kind': 'PriorityClass'}
        self.assertIs(app.normalized(original)['globalDefault'], False)
        self.assertEqual(original, {'kind': 'PriorityClass'})
        self.assertIs(app.normalized({'kind': 'PriorityClass', 'globalDefault': True})['globalDefault'], True)
        self.assertNotIn('globalDefault', app.normalized({'kind': 'ConfigMap'}))

    def test_namespace_and_storage_policy_without_input_mutation(self):
        before = fixture()
        original = copy.deepcopy(before)
        self.assertEqual(len(app.select(before)), 51)
        self.assertEqual(before, original)

    def test_foreign_namespace_hook_job_duplicate_and_size_rejected(self):
        for change in ('namespace', 'hook', 'job', 'duplicate', 'missing'):
            document = fixture()
            if change == 'namespace':
                document['items'][0]['metadata']['namespace'] = 'production'
            elif change == 'hook':
                document['items'][0]['metadata']['annotations'] = {'helm.sh/hook': 'pre-delete'}
            elif change == 'job':
                document['items'][0]['kind'] = 'Job'
            elif change == 'duplicate':
                document['items'][0] = copy.deepcopy(document['items'][1])
            else:
                document['items'].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                app.select(document)

    def test_single_replica_default_class_and_delete_policy_rejected(self):
        for change in ('replicas', 'default', 'reclaim', 'provisioner'):
            document = fixture()
            storage = document['items'][-1]
            if change == 'replicas':
                storage['parameters']['numberOfReplicas'] = '1'
            elif change == 'default':
                storage['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'] = 'true'
            elif change == 'reclaim':
                storage['reclaimPolicy'] = 'Delete'
            else:
                storage['provisioner'] = 'kubernetes.io/no-provisioner'
            with self.subTest(change=change), self.assertRaises(ValueError):
                app.select(document)


if __name__ == '__main__':
    unittest.main()
