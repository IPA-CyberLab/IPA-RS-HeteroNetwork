import copy
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest


spec = importlib.util.spec_from_file_location(
    'readiness', Path(__file__).with_name('reconcile-coder-workspace-readiness.py')
)
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def archive(*entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as target:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == 'symlink':
                info.type = tarfile.SYMTYPE
                info.linkname = 'main.tf'
                target.addfile(info)
            else:
                info.size = len(content)
                target.addfile(info, io.BytesIO(content))
    return output.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.original = archive(('main.tf', b'old', 'file'), ('README.md', b'keep', 'file'))

    def test_replaces_only_reviewed_file_and_is_idempotent(self):
        updated = readiness.revised_archive(self.original, readiness.digest(b'old'), b'new', b'wait')
        with tarfile.open(fileobj=io.BytesIO(updated)) as result:
            self.assertEqual({m.name for m in result.getmembers()}, {'main.tf', 'README.md', 'wait-for-flash.sh'})
            self.assertEqual(result.extractfile('README.md').read(), b'keep')
            self.assertEqual(result.extractfile('main.tf').read(), b'new')
            self.assertEqual(result.extractfile('wait-for-flash.sh').read(), b'wait')
        self.assertIsNone(readiness.revised_archive(updated, readiness.digest(b'old'), b'new', b'wait'))

    def test_rejects_unreviewed_or_unsafe_archives(self):
        with self.assertRaisesRegex(ValueError, 'reviewed'):
            readiness.revised_archive(self.original, readiness.digest(b'other'), b'new', b'wait')
        for entries in [
            [('main.tf', b'old', 'file'), ('../escape', b'x', 'file')],
            [('main.tf', b'old', 'file'), ('link', b'', 'symlink')],
            [('main.tf', b'old', 'file'), ('./main.tf', b'old', 'file')],
        ]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                readiness.revised_archive(archive(*entries), readiness.digest(b'old'), b'new', b'wait')

    def test_updates_waiter_when_reviewed_main_is_already_active(self):
        original = archive(('main.tf', b'new', 'file'), ('wait-for-flash.sh', b'old-wait', 'file'),
                           ('README.md', b'keep', 'file'))
        updated = readiness.revised_archive(original, readiness.digest(b'old'), b'new', b'new-wait')
        with tarfile.open(fileobj=io.BytesIO(updated)) as result:
            self.assertEqual(result.extractfile('main.tf').read(), b'new')
            self.assertEqual(result.extractfile('wait-for-flash.sh').read(), b'new-wait')
            self.assertEqual(result.extractfile('README.md').read(), b'keep')

    def test_big_variant_changes_only_reviewed_defaults(self):
        source = (b'workspace_memory_mib = lookup(var.workspace_memory_overrides, data.coder_workspace.me.id, 8192)\n'
                  b'cpu_millis             = 4000\nother = 4000\n')
        result = readiness.variant_main(source, 'big')
        self.assertIn(b'data.coder_workspace.me.id, 16384)', result)
        self.assertIn(b'cpu_millis             = 8000', result)
        self.assertIn(b'other = 4000', result)
        with self.assertRaises(ValueError):
            readiness.variant_main(b'unreviewed', 'big')


class FakeClient:
    owner = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    template_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    workspace_id = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
    old_version = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
    new_version = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
    org_id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'

    def __init__(self):
        self.active = self.old_version
        self.work = {'id': self.workspace_id, 'owner_id': self.owner, 'template_id': self.template_id,
                     'automatic_updates': 'never'}
        self.variables = [{'name': 'workspace_image', 'value': 'image@sha256:good', 'sensitive': False},
                          {'name': 'another_setting', 'value': 'preserved', 'sensitive': False}]
        self.files = {'old-file': archive(('main.tf', b'old', 'file'), ('README.md', b'keep', 'file'))}
        self.mutations = []

    def call(self, path, method='GET', body=None, statuses=(200,), raw=False):
        if method != 'GET':
            self.mutations.append((method, path, body))
        if path == '/api/v2/workspaces/' + self.workspace_id:
            return copy.deepcopy(self.work)
        if path == '/api/v2/workspaces/' + self.workspace_id + '/autoupdates':
            self.work.update(body)
            return None
        if path == '/api/v2/templates/' + self.template_id:
            return {'active_version_id': self.active, 'organization_id': self.org_id}
        if path == '/api/v2/templates/' + self.template_id + '/versions':
            self.active = body['id']
            return None
        if path in ('/api/v2/templateversions/' + self.old_version,
                    '/api/v2/templateversions/' + self.new_version):
            file_id = 'old-file' if path.endswith(self.old_version) else 'new-file'
            return {'id': path.rsplit('/', 1)[1], 'job': {'status': 'succeeded', 'file_id': file_id}}
        if path.endswith('/variables'):
            return copy.deepcopy(self.variables)
        if path == '/api/v2/files' and method == 'POST':
            self.files['new-file'] = body
            return {'id': 'new-file'}
        if path.startswith('/api/v2/files/'):
            return self.files[path.rsplit('/', 1)[1]]
        if path == '/api/v2/organizations/' + self.org_id + '/templateversions':
            return {'id': self.new_version}
        raise AssertionError((method, path))


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.config = {
            'owner_id': self.client.owner,
            'expected_workspace_image': 'image@sha256:good',
            'templates': [{'id': self.client.template_id, 'variant': 'standard',
                           'expected_old_main_sha256': readiness.digest(b'old')}],
            'auto_update_workspaces': [{'id': self.client.workspace_id, 'template_id': self.client.template_id}],
        }

    def run_reconcile(self):
        readiness.reconcile(self.client, self.config, b'new', b'wait')

    def test_preserves_variables_updates_on_next_start_and_is_idempotent(self):
        self.run_reconcile()
        self.assertEqual(self.client.active, self.client.new_version)
        self.assertEqual(self.client.work['automatic_updates'], 'always')
        imports = [body for method, path, body in self.client.mutations if path.endswith('/templateversions')]
        self.assertEqual(imports[0]['user_variable_values'], [
            {'name': 'workspace_image', 'value': 'image@sha256:good'},
            {'name': 'another_setting', 'value': 'preserved'},
        ])
        self.assertFalse(any('/builds' in path for _, path, _ in self.client.mutations))
        self.client.mutations.clear()
        self.run_reconcile()
        self.assertEqual(self.client.mutations, [])

    def test_owner_mismatch_prevents_any_mutation(self):
        self.client.work['owner_id'] = 'another-owner'
        with self.assertRaisesRegex(ValueError, 'owner'):
            self.run_reconcile()
        self.assertEqual(self.client.mutations, [])

    def test_image_mismatch_prevents_import(self):
        self.client.variables[0]['value'] = 'different-image'
        with self.assertRaisesRegex(ValueError, 'image'):
            self.run_reconcile()
        self.assertEqual(self.client.mutations, [])

    def test_sensitive_variables_prevent_import(self):
        self.client.variables[1]['sensitive'] = True
        with self.assertRaisesRegex(ValueError, 'Sensitive'):
            self.run_reconcile()
        self.assertEqual(self.client.mutations, [])


if __name__ == '__main__':
    unittest.main()
