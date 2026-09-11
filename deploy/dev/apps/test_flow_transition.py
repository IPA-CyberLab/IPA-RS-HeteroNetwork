import copy
import unittest

import flow_transition as app


def fixture():
    flow = {'commit': app.OLD_COMMIT, 'version': '0.1.21-dev.6',
            'image': app.REPOSITORY + '@sha256:' + '1' * 64,
            'companions': {'livekit': {'image': app.REPOSITORY + '-livekit@sha256:' + '2' * 64}}}
    old = {'schema_version': 1, 'channel': 'dev', 'revision': 15,
           'cluster_uid': 'dev', 'production_cluster_uid': 'prod', 'site_sha256': 'a' * 64,
           'components': {'flow': flow, 'syouyu': {'commit': 'unchanged'}},
           'files': {app.FILE: 'b' * 64, 'heterocloud-syouyu-dev.json': 'c' * 64}}
    new = copy.deepcopy(old)
    new['revision'] = 16
    new['components']['flow'].update(commit=app.NEW_COMMIT, version='0.1.21-dev.7',
                                     image=app.REPOSITORY + '@sha256:' + '3' * 64)
    new['components']['flow']['companions']['livekit']['image'] = app.REPOSITORY + '-livekit@sha256:' + '4' * 64
    redis = [{'name': 'REDIS_SENTINEL_URLS', 'value': 'redis://dev:26379'},
             {'name': 'REDIS_SENTINEL_MASTER', 'value': 'flowmaster'},
             *({'name': name, 'valueFrom': {'secretKeyRef': {'name': 'dev-only', 'key': 'password'}}}
               for name in ('REDIS_PASSWORD', 'REDIS_SENTINEL_PASSWORD'))]
    before = {'kind': 'List', 'items': []}
    for component in ('api', 'matchmaker', 'signaling', 'livekit', 'migrate'):
        env = copy.deepcopy(redis) if component == 'api' else [{'name': 'MIGRATE_ON_START', 'value': 'true'}]
        before['items'].append({'kind': 'Job' if component == 'migrate' else 'Deployment',
            'metadata': {'name': 'heterocloud-flow-dev-' + component},
            'spec': {'template': {'spec': {'containers': [{'image': app.tagged(flow, component == 'livekit'), 'env': env}]}}}})
    after = copy.deepcopy(before)
    for item in after['items']:
        c = item['spec']['template']['spec']['containers'][0]
        c['image'] = app.tagged(new['components']['flow'], item['metadata']['name'].endswith('-livekit'))
        if item['kind'] == 'Job':
            c['env'].extend(copy.deepcopy(redis))
    return old, new, before, after


class TransitionTests(unittest.TestCase):
    def test_exact_migration_repair(self):
        values = fixture()
        unchanged = copy.deepcopy(values)
        self.assertTrue(app.validate(*values)['allowed_transition'])
        self.assertEqual(values, unchanged)

    def test_other_component_or_site_or_cluster_rejected(self):
        for field in ('site_sha256', 'cluster_uid', 'production_cluster_uid', 'channel'):
            old, new, before, after = fixture()
            new[field] = 'other'
            with self.subTest(field=field), self.assertRaises(ValueError):
                app.validate(old, new, before, after)
        old, new, before, after = fixture()
        new['components']['syouyu']['commit'] = 'other'
        with self.assertRaises(ValueError):
            app.validate(old, new, before, after)

    def test_unrelated_resource_or_env_changes_rejected(self):
        for change in ('replicas', 'credential', 'missing-redis'):
            old, new, before, after = fixture()
            if change == 'replicas':
                after['items'][0]['spec']['replicas'] = 1
            elif change == 'credential':
                after['items'][-1]['spec']['template']['spec']['containers'][0]['env'][-1]['valueFrom']['secretKeyRef']['name'] = 'production'
            else:
                after['items'][-1]['spec']['template']['spec']['containers'][0]['env'].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                app.validate(old, new, before, after)

    def test_unselected_release_rejected(self):
        for field, value in (('commit', 'f' * 40), ('version', '0.1.21-dev.8'), ('image', 'redis:latest')):
            old, new, before, after = fixture()
            new['components']['flow'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                app.validate(old, new, before, after)


if __name__ == '__main__':
    unittest.main()
