import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import databases

spec = importlib.util.spec_from_file_location('db_apply', Path(__file__).with_name('apply-databases.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class DatabaseTests(unittest.TestCase):
    def test_fresh_independent_clusters_and_no_secret_import(self):
        for ns in databases.NAMESPACES:
            item, = databases.resources(ns)
            self.assertEqual(item['metadata'], {'name': 'dev-postgres', 'namespace': ns})
            spec = item['spec']
            self.assertEqual(spec['instances'], 3)
            self.assertEqual(spec['storage']['storageClass'], 'dev-app-local')
            self.assertEqual(spec['storage']['size'], '5Gi')
            self.assertEqual(spec['bootstrap']['initdb']['owner'], ns.replace('-', '_'))
            self.assertEqual(spec['postgresql']['synchronous']['dataDurability'], 'required')
            self.assertTrue(spec['podSecurityContext']['runAsNonRoot'])
            self.assertNotIn('externalClusters', spec)

    def test_only_new_namespaces_and_additive_operator_policy(self):
        objects = databases.resources('network')
        self.assertEqual(len(objects), 7)
        self.assertEqual({o['kind'] for o in objects}, {'Namespace', 'NetworkPolicy'})
        self.assertFalse(any(o['metadata'].get('namespace') == 'hetero-dev-identity' for o in objects))
        operator = [o for o in objects if o['metadata'].get('namespace') == 'cnpg-system']
        self.assertEqual([o['metadata']['name'] for o in operator], ['dev-application-databases'])

    def test_foreign_existing_cluster_never_written(self):
        item = databases.resources('heterocloud-dev')[0]
        with patch.object(app, 'guard'), patch.object(app, 'get', return_value=item), \
                patch.object(app, 'run') as run:
            with self.assertRaises(ValueError):
                app.apply('heterocloud-dev')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
