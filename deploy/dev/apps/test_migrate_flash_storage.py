import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('migration', Path(__file__).with_name('migrate-flash-storage.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Migration(unittest.TestCase):
    def fixture(self):
        return {'kind': 'Deployment', 'metadata': {'name': m.NAME, 'namespace': m.NS},
                'spec': {'replicas': 2, 'template': {'spec': {'containers': [{'name': 'controller',
                'env': [{'name': 'OTHER', 'value': 'untouched'},
                        {'name': 'FLASH_PERSISTENT_STORAGE_CLASS', 'value': 'dev-app-local'}]}]}}}}

    def test_only_storage_changes(self):
        original = self.fixture()
        before = copy.deepcopy(original)
        desired, index = m.transition(original)
        self.assertEqual(index, 1)
        self.assertEqual(original, before)
        desired['spec']['template']['spec']['containers'][0]['env'][index]['value'] = 'dev-app-local'
        self.assertEqual(desired, original)

    def test_unknown_or_duplicate_storage_rejected(self):
        for mode in ('foreign', 'duplicate', 'missing'):
            original = self.fixture()
            env = original['spec']['template']['spec']['containers'][0]['env']
            if mode == 'foreign':
                env[1]['value'] = 'production'
            elif mode == 'duplicate':
                env.append(copy.deepcopy(env[1]))
            else:
                env.pop()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                m.transition(original)


if __name__ == '__main__':
    unittest.main()
