"""Unit checks for standard-node endpoint readiness and safe diagnostics."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'verify_standard_node', Path(__file__).with_name('verify-standard-node.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class StandardNodeVerifierTest(unittest.TestCase):
    def test_endpoint_requires_matching_usable_address(self):
        slices = {'items': [{'endpoints': [
            {'addresses': ['10.244.1.1'], 'conditions': {'ready': True}},
            {'addresses': ['10.244.1.2'], 'conditions': {'ready': False}},
            {'addresses': ['10.244.1.3'], 'conditions': {'ready': True, 'terminating': True}},
        ]}]}
        self.assertTrue(verifier.endpoint_slice_has_ready_address(slices, '10.244.1.1'))
        self.assertFalse(verifier.endpoint_slice_has_ready_address(slices, '10.244.1.2'))
        self.assertFalse(verifier.endpoint_slice_has_ready_address(slices, '10.244.1.3'))
        self.assertFalse(verifier.endpoint_slice_has_ready_address(slices, '10.244.1.4'))

    def test_waits_until_endpoint_slice_publishes_server_ip(self):
        responses = iter([
            {'items': []},
            {'items': [{'endpoints': [{'addresses': ['10.244.5.8'],
                                       'conditions': {'ready': True}}]}]},
        ])
        with patch.object(verifier, 'get', side_effect=lambda *args: next(responses)) as get_mock, \
                patch.object(verifier.time, 'sleep'):
            verifier.wait_for_service_endpoint('e2e', 'server', '10.244.5.8', timeout=5)
        self.assertEqual(get_mock.call_count, 2)
        self.assertEqual(get_mock.call_args.args[-1], 'kubernetes.io/service-name=server')

    def test_diagnostics_keep_exit_reason_and_redact_log_credentials(self):
        pods = {'items': [{
            'metadata': {'name': 'local-client'},
            'spec': {'nodeName': 'standard-node'},
            'status': {'phase': 'Failed', 'containerStatuses': [{
                'name': 'test', 'ready': False, 'restartCount': 0,
                'state': {'terminated': {'reason': 'Error', 'exitCode': 7, 'signal': 0}},
            }]},
        }]}

        def command(args, obj=None, check=True):
            if args[:2] == ['get', 'pods']:
                return subprocess.CompletedProcess(args, 0, json.dumps(pods), '')
            self.assertEqual(args[0], 'logs')
            return subprocess.CompletedProcess(
                args, 0, ('network failed password=hunter2 token: abc123\n'
                          'Authorization: Bearer external-credential\n'), '')

        with patch.object(verifier, 'k', side_effect=command):
            diagnostics = verifier.pod_diagnostics('e2e')
        client = diagnostics['local-client']
        self.assertEqual(client['phase'], 'Failed')
        self.assertEqual(client['containers'][0]['exit_code'], 7)
        self.assertEqual(client['containers'][0]['reason'], 'Error')
        self.assertIn('password=[redacted]', client['log'])
        self.assertIn('token: [redacted]', client['log'])
        self.assertNotIn('hunter2', client['log'])
        self.assertNotIn('abc123', client['log'])
        self.assertNotIn('external-credential', client['log'])
        self.assertIn('Authorization: [redacted]', client['log'])

    def test_diagnostic_collection_failure_does_not_mask_original_failure(self):
        with patch.object(verifier, 'k', side_effect=subprocess.TimeoutExpired(['kubectl'], 30)):
            diagnostics = verifier.pod_diagnostics('e2e')
        self.assertIn('collection_error', diagnostics)
        self.assertIn('TimeoutExpired', diagnostics['collection_error'])

    def test_failure_report_is_private_and_contains_pod_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(verifier, 'pod_diagnostics', return_value={
                    'local-client': {'phase': 'Failed', 'containers': [{
                        'state': 'terminated', 'reason': 'Error', 'exit_code': 7,
                    }]},
                }):
            output = Path(directory) / 'failure.json'
            verifier.record_failure({}, output, 'e2e', RuntimeError('token=external-value'))
            report = json.loads(output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(report['passed'])
        self.assertEqual(report['pod_diagnostics']['local-client']['phase'], 'Failed')
        self.assertEqual(report['pod_diagnostics']['local-client']['containers'][0]['exit_code'], 7)
        self.assertNotIn('external-value', report['failure']['message'])


if __name__ == '__main__':
    unittest.main()
