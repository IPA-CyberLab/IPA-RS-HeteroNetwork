import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('upgrade', Path(__file__).with_name('upgrade-flash-dev2.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class Upgrade(unittest.TestCase):
    def test_only_reviewed_image_and_storage_delta(self):
        before = {'items': [{'kind': 'Deployment', 'metadata': {'name': u.NS + '-' + role, 'namespace': u.NS},
                  'spec': {'template': {'spec': {'containers': [{'image': u.OLD, 'env': [
                    {'name': 'FLASH_PERSISTENT_STORAGE_CLASS', 'value': 'dev-app-local'}]}]}}}}
                  for role in ('api', 'controller')]}
        after = copy.deepcopy(before)
        for item in after['items']:
            item['spec']['template']['spec']['containers'][0]['image'] = u.NEW
        after['items'][1]['spec']['template']['spec']['containers'][0]['env'][0]['value'] = 'dev-flash-rwx'
        self.assertEqual(len(u.pair(before, after)), 2)
        changed = copy.deepcopy(after)
        changed['items'][0]['spec']['replicas'] = 99
        with self.assertRaises(ValueError):
            u.pair(before, changed)
        self.assertEqual(before['items'][0]['spec']['template']['spec']['containers'][0]['image'], u.OLD)


if __name__ == '__main__':
    unittest.main()
