import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('prepare_runtime', Path(__file__).with_name('prepare-runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def application(self, name='heterocloud-dev'):
        return {'metadata': {'name': name}, 'spec': {'destination': {'namespace': name}}}

    def resource(self, kind='Service', api='v1', **metadata):
        return {'apiVersion': api, 'kind': kind, 'metadata': {'name': 'example', **metadata}}

    def test_scopes_and_flash_workload_namespace(self):
        docs = [self.resource(), self.resource('ClusterRole', 'rbac.authorization.k8s.io/v1')]
        result = runtime.normalize(docs, self.application())
        self.assertEqual(result[0]['metadata']['namespace'], 'heterocloud-dev')
        self.assertNotIn('namespace', result[1]['metadata'])
        self.assertNotIn('namespace', docs[0]['metadata'])
        doc = self.resource(namespace='heterocloud-flash-dev-workloads')
        self.assertEqual(runtime.normalize([doc], self.application('heterocloud-flash-dev')), [doc])

    def test_unknown_foreign_duplicate_and_cluster_namespace_refused(self):
        cases = [[self.resource('Unknown')], [self.resource(namespace='production')],
                 [self.resource(), self.resource()],
                 [self.resource('Namespace', namespace='heterocloud-dev')],
                 [self.resource('Namespace', name='production')]]
        for docs in cases:
            with self.subTest(docs=docs), self.assertRaises(ValueError):
                runtime.normalize(docs, self.application())

    def test_exclusive_publication_repeat_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bundle'
            files = {'manifest.json': b'{}\n', 'app.json': b'[]\n'}
            self.assertTrue(runtime.publish(output, files))
            self.assertFalse(runtime.publish(output, files))
            before = {p.name: p.stat().st_mtime_ns for p in output.iterdir()}
            self.assertFalse(runtime.publish(output, files))
            self.assertEqual(before, {p.name: p.stat().st_mtime_ns for p in output.iterdir()})
            with self.assertRaises(ValueError):
                runtime.publish(output, {**files, 'app.json': b'{}\n'})
            self.assertEqual((output / 'app.json').read_bytes(), b'[]\n')
            (output / 'extra').touch()
            with self.assertRaises(ValueError):
                runtime.publish(output, files)

    def test_existing_empty_directory_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'bundle'
            output.mkdir()
            with self.assertRaises(ValueError):
                runtime.publish(output, {'manifest.json': b'{}'})
            link = Path(directory) / 'link'
            link.symlink_to(output, target_is_directory=True)
            with self.assertRaises(ValueError):
                runtime.publish(link, {})

    def test_file_symlink_refused_and_failed_write_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = parent / 'bundle'
            files = {'manifest.json': b'{}'}
            with patch.object(runtime.os, 'fsync', side_effect=OSError('disk failure')):
                with self.assertRaises(OSError):
                    runtime.publish(output, files)
            self.assertEqual(list(parent.iterdir()), [])
            runtime.publish(output, files)
            external = parent / 'external'
            external.write_bytes(files['manifest.json'])
            (output / 'manifest.json').unlink()
            (output / 'manifest.json').symlink_to(external)
            with self.assertRaises(ValueError):
                runtime.publish(output, files)

    def test_callback_then_validation_failure_never_publishes_or_leaks(self):
        with patch.object(runtime, 'prepare', side_effect=ValueError('PRIVATE-MATERIAL')), \
                patch.object(runtime, 'publish') as publish, \
                patch('sys.argv', ['prepare-runtime.py', '--output', '/unused']), \
                patch('sys.stderr') as stderr:
            self.assertEqual(runtime.main(), 1)
            publish.assert_not_called()
            self.assertNotIn('PRIVATE-MATERIAL', str(stderr.write.call_args_list))

    def test_collects_only_after_renderer_completes_with_provenance(self):
        applications, releases = [], {}
        for component, (chart, _) in runtime.render.COMPONENTS.items():
            app = self.application(chart + '-dev')
            app['spec']['source'] = {'targetRevision': 'a' * 40, 'helm': {'releaseName': chart + '-dev'}}
            applications.append(app)
            releases[component] = {'commit': 'a' * 40, 'image': 'example/image@sha256:' + 'b' * 64}
        site = {'cluster_uid': 'dev', 'production_cluster_uid': 'prod'}

        def collect(apps, state, channel, actual_site, root, inspect_documents):
            self.assertEqual(channel, 'dev')
            for app in apps:
                inspect_documents(app, [self.resource()])

        with patch.object(runtime, 'read_input', side_effect=[(site, 'site-hash'), ({'revision': 15}, 'channels-hash')]), \
                patch.object(runtime.render, 'render', return_value=applications), \
                patch.object(runtime.render, 'selected', return_value=releases), \
                patch.object(runtime.render, 'check_helm', side_effect=collect) as check:
            files = runtime.prepare(Path('site'), Path('channels'), Path('root'))
        check.assert_called_once()
        manifest = json.loads(files['manifest.json'])
        self.assertEqual(manifest['site_sha256'], 'site-hash')
        self.assertEqual(manifest['revision'], 15)
        self.assertEqual(manifest['channel'], 'dev')
        self.assertEqual(manifest['components'], releases)
        self.assertEqual(manifest['files'], {name: runtime.digest(raw)
                                           for name, raw in files.items() if name != 'manifest.json'})
        self.assertEqual(len(files), 5)
        for entry in manifest['applications'].values():
            self.assertEqual(entry['sha256'], runtime.digest(files[entry['file']]))
            self.assertEqual(entry['source']['targetRevision'], 'a' * 40)

        def fail_late(*args, **kwargs):
            collect(*args, **kwargs)
            raise ValueError('Image check failed after callback')

        with patch.object(runtime, 'read_input', side_effect=[(site, 'site-hash'), ({'revision': 15}, 'channels-hash')]), \
                patch.object(runtime.render, 'render', return_value=applications), \
                patch.object(runtime.render, 'selected', return_value=releases), \
                patch.object(runtime.render, 'check_helm', side_effect=fail_late), \
                self.assertRaises(ValueError):
            runtime.prepare(Path('site'), Path('channels'), Path('root'))


if __name__ == '__main__':
    unittest.main()
