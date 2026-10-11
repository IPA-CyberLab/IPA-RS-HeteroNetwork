import subprocess
import traceback
import unittest
from unittest.mock import patch

import vms


class CredentialRedactionTests(unittest.TestCase):
    def test_timeout_traceback_does_not_expose_bootstrap_argv(self):
        token = 'abcdef.0123456789abcdef'
        command = ['ssh', 'isolated-worker', 'kubeadm join --token ' + token]
        failure = subprocess.TimeoutExpired(command, 1, stderr=token.encode())
        with patch.object(vms.subprocess, 'run', side_effect=failure):
            try:
                vms.run(command)
            except RuntimeError as error:
                self.assertNotIn(token, ''.join(traceback.format_exception(error)))
            else:
                self.fail('Timeout must remain a test failure')

    def test_failed_command_redacts_token_in_diagnostic(self):
        token = 'abcdef.0123456789abcdef'
        failure = subprocess.CompletedProcess(['ssh'], 1, b'', ('invalid token ' + token).encode())
        with patch.object(vms.subprocess, 'run', return_value=failure):
            with self.assertRaisesRegex(RuntimeError, r'\[bootstrap token\]') as caught:
                vms.run(['ssh'])
        self.assertNotIn(token, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
