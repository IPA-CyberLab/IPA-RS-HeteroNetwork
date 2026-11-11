import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'coder_schedule', ROOT / 'scripts/reconcile-coder-template-scheduling.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
# Keep coverage for several templates independent of the current deployment.
CONFIG = {
    'owner_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    'organization_id': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    'template_ids': [
        'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    ],
    'default_ttl_ms': 0,
    'allow_user_autostop': True,
}


class Client:
    def __init__(self):
        self.owner = CONFIG['owner_id']
        self.templates = {
            identifier: {'id': identifier, 'name': 'template-' + str(i),
                         'organization_id': CONFIG['organization_id'],
                         'default_ttl_ms': 86400000, 'allow_user_autostop': True,
                         'autostop_requirement': {'days_of_week': [], 'weeks': 0},
                         'description': 'preserve this'}
            for i, identifier in enumerate(CONFIG['template_ids'])
        }
        self.writes = []

    def call(self, path, method='GET', body=None, **kwargs):
        if path == '/api/v2/users/me':
            return {'id': self.owner}
        if not path.startswith('/api/v2/templates/'):
            raise AssertionError('Unexpected endpoint: ' + path)
        template = self.templates[path.rsplit('/', 1)[1]]
        if method == 'PATCH':
            self.writes.append((path, copy.deepcopy(body)))
            template.update(body)
        return copy.deepcopy(template)


class SchedulingTests(unittest.TestCase):
    def test_corrects_both_templates_without_touching_workspaces(self):
        client = Client()
        result = module.reconcile(client, CONFIG)
        self.assertEqual(len(result), 2)
        self.assertTrue(all(row['changed'] for row in result))
        self.assertEqual(len(client.writes), 2)
        self.assertTrue(all(t['default_ttl_ms'] == 0 for t in client.templates.values()))
        self.assertTrue(all(t['description'] == 'preserve this' for t in client.templates.values()))
        client.writes.clear()
        self.assertTrue(all(not row['changed'] for row in module.reconcile(client, CONFIG)))
        self.assertEqual(client.writes, [])

    def test_rejects_wrong_owner_before_any_change(self):
        client = Client()
        client.owner = '00000000-0000-4000-8000-000000000000'
        with self.assertRaisesRegex(ValueError, 'credential'):
            module.reconcile(client, CONFIG)
        self.assertEqual(client.writes, [])

    def test_rejects_other_organization_before_any_change(self):
        client = Client()
        client.templates[CONFIG['template_ids'][1]]['organization_id'] = '00000000-0000-4000-8000-000000000000'
        with self.assertRaisesRegex(ValueError, 'organization'):
            module.reconcile(client, CONFIG)
        self.assertEqual(client.writes, [])

    def test_does_not_claim_to_disable_a_mandatory_stop(self):
        client = Client()
        client.templates[CONFIG['template_ids'][1]]['autostop_requirement']['days_of_week'] = ['monday']
        with self.assertRaisesRegex(ValueError, 'mandatory autostop'):
            module.reconcile(client, CONFIG)
        self.assertEqual(client.writes, [])

    def test_default_week_interval_without_required_day_is_disabled(self):
        client = Client()
        client.templates[CONFIG['template_ids'][1]]['autostop_requirement']['weeks'] = 1
        self.assertEqual(len(module.reconcile(client, CONFIG)), 2)

    def test_duplicate_or_unsafe_policy_is_rejected_before_writes(self):
        client = Client()
        config = dict(CONFIG, template_ids=[CONFIG['template_ids'][0]] * 2)
        with self.assertRaises(ValueError):
            module.reconcile(client, config)
        with self.assertRaises(ValueError):
            module.reconcile(client, dict(CONFIG, default_ttl_ms=86400000))
        self.assertEqual(client.writes, [])


if __name__ == '__main__':
    unittest.main()
