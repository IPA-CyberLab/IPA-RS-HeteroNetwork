#!/usr/bin/env python3
"""Offline generated-command checks; no cluster access."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pv_apply', Path(__file__).with_name('apply-dev-app-storage.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ApplyTests(unittest.TestCase):
    def execute(self, foreign=False, owned=False, dry_run_error=False, write=True):
        manifest = app.plan.manifest()
        self.commands = []

        def run(args, **kwargs):
            self.commands.append(args)
            command = args[3:]
            result = b''
            code = 0
            if command[:3] == ['get', 'namespace', 'kube-system']:
                result = json.dumps({'metadata': {'uid': app.plan.CLUSTER_UID}}).encode()
            elif command[:2] == ['get', 'persistentvolumes']:
                result = json.dumps({'items': manifest['items'][1:]}).encode()
            elif command[:2] == ['get', 'storageclass']:
                result = json.dumps(manifest['items'][0]).encode()
            elif foreign and command[0] == 'get':
                result = json.dumps(manifest['items'][0]).encode()
            elif owned and command[0] == 'get':
                item = next(item for item in manifest['items'] if item['metadata']['name'] == command[2])
                item = json.loads(json.dumps(item))
                if '--show-managed-fields' in args:
                    item['metadata']['managedFields'] = [{'manager': app.MANAGER}]
                result = json.dumps(item).encode()
            elif dry_run_error and '--dry-run=server' in args:
                code = 1
            return SimpleNamespace(returncode=code, stdout=result)

        with patch.object(app.expansion.health.subprocess, 'run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()):
            exec(compile(app.apply_code(manifest, write), '<generated>', 'exec'), {})

    def test_server_dry_run_precedes_apply(self):
        self.execute()
        writes = [a for a in self.commands if 'apply' in a]
        self.assertEqual(len(writes), 2)
        self.assertIn('--dry-run=server', writes[0])
        self.assertNotIn('--dry-run=server', writes[1])
        self.assertTrue(all('--force-conflicts' not in a for a in self.commands))

    def test_foreign_resource_and_failed_dry_run_never_apply(self):
        for kwargs in ({'foreign': True}, {'dry_run_error': True}):
            with self.assertRaises(AssertionError):
                self.execute(**kwargs)
            self.assertFalse(any('apply' in a and '--dry-run=server' not in a for a in self.commands))

    def test_inspect_does_not_write(self):
        self.execute(write=False)
        self.assertFalse(any('apply' in a and '--dry-run=server' not in a for a in self.commands))

    def test_owned_existing_resources_can_be_reapplied(self):
        self.execute(owned=True)
        ownership_reads = [a for a in self.commands if '--ignore-not-found' in a]
        self.assertEqual(len(ownership_reads), 19)
        self.assertTrue(all('--show-managed-fields' in a for a in ownership_reads))


if __name__ == '__main__':
    unittest.main()
