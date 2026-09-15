"""Failure-path checks for the live onboarding acceptance gate."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('acceptance', Path(__file__).with_name('accept-registered-nodes.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class OnboardingGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.calls = []

    def api(self, *args):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps({
            'metadata': {'uid': 'uid-1', 'resourceVersion': '17'},
            'spec': {'taints': [{'key': acceptance.TAINT, 'value': 'pending', 'effect': 'NoSchedule'},
                                {'key': 'maintenance', 'effect': 'NoExecute'}]}}), '')

    def test_browser_or_storage_failure_cannot_accept_or_release_quarantine(self):
        with patch.object(acceptance, 'kubectl', self.api):
            def failed():
                raise RuntimeError('storage attach failed')
            with self.assertRaises(RuntimeError):
                acceptance.accept(self.work, ['master'], ['standard'], 'revision', failed)
        proof = json.loads((self.work / 'onboarding-acceptance.json').read_text())
        self.assertFalse(proof['accepted'])
        states = [json.loads(c[-1])['metadata']['annotations'][acceptance.STATUS]
                  for c in self.calls if c[0] == 'patch']
        self.assertNotIn('accepted', states)
        self.assertNotIn(('taint', 'node', 'standard', acceptance.TAINT + ':NoSchedule-'), self.calls)

    def test_node_replacement_during_e2e_rejects_passing_result(self):
        replaced = False
        def api(*args):
            if args[0] == 'get':
                return subprocess.CompletedProcess(args, 0, json.dumps({'metadata': {'uid': 'new' if replaced else 'old'}}), '')
            return self.api(*args)
        def verified():
            nonlocal replaced
            replaced = True
            return {'passed': True}
        with patch.object(acceptance, 'kubectl', api), self.assertRaises(RuntimeError):
            acceptance.accept(self.work, [], ['standard'], 'revision', verified)
        self.assertFalse(json.loads((self.work / 'onboarding-acceptance.json').read_text())['accepted'])

    def test_stale_passing_artifact_cannot_hide_command_failure(self):
        output = self.work / 'old.json'
        output.write_text('{"passed":true}')
        with patch.object(acceptance, 'run', side_effect=subprocess.CalledProcessError(1, ['e2e'])):
            with self.assertRaises(subprocess.CalledProcessError):
                acceptance.check(['e2e'], output)
        self.assertFalse(output.exists())

    def test_zero_exit_with_a_failed_report_is_rejected(self):
        output = self.work / 'failed.json'
        def misleading_success(command, **kwargs):
            Path(command[-1]).write_text('{"passed":false}')
            return subprocess.CompletedProcess(command, 0, '', '')
        with patch.object(acceptance, 'run', misleading_success), self.assertRaises(RuntimeError):
            acceptance.check(['e2e'], output)

    def test_passing_e2e_records_acceptance_then_releases_only_onboarding_taint(self):
        with patch.object(acceptance, 'kubectl', self.api):
            proof = acceptance.accept(self.work, ['master'], ['standard'], 'revision', lambda: {'passed': True})
        self.assertTrue(proof['accepted'])
        accepted = [i for i, c in enumerate(self.calls) if c[0] == 'patch' and
                    json.loads(c[-1])['metadata'].get('annotations', {}).get(acceptance.STATUS) == 'accepted']
        release = next(i for i, c in enumerate(self.calls) if c[0] == 'patch' and 'spec' in json.loads(c[-1]))
        self.assertTrue(accepted and max(accepted) < release)
        patch_data = json.loads(self.calls[release][-1])
        self.assertEqual(patch_data['metadata'], {'uid': 'uid-1', 'resourceVersion': '17'})
        self.assertEqual(patch_data['spec']['taints'], [{'key': 'maintenance', 'effect': 'NoExecute'}])

    def test_node_replacement_after_accept_annotation_cannot_release_new_node(self):
        replaced = False
        def api(*args):
            nonlocal replaced
            if args[0] == 'patch' and json.loads(args[-1])['metadata'].get('annotations', {}).get(acceptance.STATUS) == 'accepted':
                replaced = True
            if args[0] == 'get' and replaced:
                return subprocess.CompletedProcess(args, 0, json.dumps({'metadata': {'uid': 'new'}}), '')
            return self.api(*args)
        with patch.object(acceptance, 'kubectl', api), self.assertRaises(RuntimeError):
            acceptance.accept(self.work, [], ['standard'], 'revision', lambda: {'passed': True})
        self.assertFalse(json.loads((self.work / 'onboarding-acceptance.json').read_text())['accepted'])
        self.assertFalse(any(c[0] == 'patch' and 'spec' in json.loads(c[-1]) for c in self.calls))


if __name__ == '__main__':
    unittest.main()
