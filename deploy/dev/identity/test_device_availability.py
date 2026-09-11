import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('device_probe', Path(__file__).with_name('probe-device-availability.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DeviceProbeTests(unittest.TestCase):
    def test_success_does_not_return_issued_credentials(self):
        context = MagicMock()
        with patch.object(probe.http.client, 'HTTPSConnection') as factory, patch.object(probe.socket, 'create_connection'):
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({'device_code': 'private-device-code',
                                                    'user_code': 'private-user-code',
                                                    'verification_uri': 'https://example.invalid'}).encode()
            result = probe.request(context, '172.30.1.2')
            self.assertTrue(result['ok'])
            self.assertEqual(set(result), {'ok', 'http_status', 'duration_ms'})
            self.assertNotIn('private-', json.dumps(result))
            self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], probe.HOST)
            connection.close.assert_called_once()

    def test_error_response_is_not_success(self):
        with patch.object(probe.http.client, 'HTTPSConnection') as factory, patch.object(probe.socket, 'create_connection'):
            response = factory.return_value.getresponse.return_value
            response.status = 503
            response.read.return_value = b'Unavailable'
            self.assertFalse(probe.request(MagicMock(), '172.30.1.2')['ok'])

    def test_network_error_is_redacted(self):
        with patch.object(probe.http.client, 'HTTPSConnection') as factory, patch.object(
                probe.socket, 'create_connection', side_effect=TimeoutError('sensitive diagnostic')):
            result = probe.request(MagicMock(), '172.30.1.2')
            self.assertFalse(result['ok'])
            self.assertEqual(result['error'], 'TimeoutError')
            self.assertNotIn('sensitive', json.dumps(result))
            factory.return_value.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
