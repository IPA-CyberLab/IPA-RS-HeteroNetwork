import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).with_name('reconcile-console-issuer.py')
spec = importlib.util.spec_from_file_location('reconcile_console_issuer', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def encoded(value):
    return base64.b64encode(value.encode()).decode()


class ReconcileConsoleIssuerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'bootstrap.env'
        self.calls = []
        self.original = (
            '# preserve comments and other fields\n'
            'HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64=' + encoded(module.OLD_ISSUER) + '\n'
            'HETERONETWORK_PUBLIC_SERVICES_OIDC_CLIENT_ID_B64=' + encoded('ipars-web') + '\n'
            'HETERONETWORK_PUBLIC_SERVICES_OIDC_DEVICE_VERIFICATION_ORIGIN_B64=' + encoded('https://example.test:8443') + '\n'
            'UNRELATED_SECRET=untouched\n'
        ).encode()
        self.path.write_bytes(self.original)
        self.path.chmod(0o600)

    def run_reconcile(self, restart=None):
        return module.reconcile(self.path, os.getuid(), restart or (lambda: self.calls.append('restart')))

    def test_repairs_only_issuer_and_is_idempotent(self):
        self.assertEqual(self.run_reconcile(), 'updated')
        expected = self.original.replace(encoded(module.OLD_ISSUER).encode(), encoded('https://example.test:8443/id/realms/heterocloud').encode())
        self.assertEqual(self.path.read_bytes(), expected)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.calls, ['restart'])
        self.assertEqual(self.run_reconcile(), 'unchanged')
        self.assertEqual(self.calls, ['restart'])

    def test_unrelated_issuer_is_not_rewritten(self):
        self.path.write_bytes(self.original.replace(encoded(module.OLD_ISSUER).encode(), encoded('https://identity.example/realms/other').encode()))
        self.assertEqual(self.run_reconcile(), 'unchanged')
        self.assertFalse(self.calls)

    def test_invalid_origin_and_duplicate_keys_fail_closed(self):
        self.path.write_bytes(self.original.replace(encoded('https://example.test:8443').encode(), encoded('http://bad.example').encode()))
        with self.assertRaises(ValueError): self.run_reconcile()
        self.path.write_bytes(self.original + b'HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64=duplicate\n')
        with self.assertRaises(ValueError): self.run_reconcile()
        self.assertFalse(self.calls)

    def test_unrelated_duplicate_entries_are_preserved(self):
        self.path.write_bytes(self.original + b'UNRELATED_SECRET=another-value\n')
        self.assertEqual(self.run_reconcile(), 'updated')
        self.assertTrue(self.path.read_bytes().endswith(b'UNRELATED_SECRET=another-value\n'))

    def test_restart_failure_restores_previous_configuration(self):
        def failure(): raise RuntimeError('failure')
        with self.assertRaises(RuntimeError): self.run_reconcile(failure)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_unsafe_file_permissions_and_symlinks_are_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): self.run_reconcile()
        target = self.path.with_name('target')
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(OSError): self.run_reconcile()


if __name__ == '__main__':
    unittest.main()
