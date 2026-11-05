import importlib.util
import base64
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('backup_store', Path(__file__).with_name('provision-flash-backup-store.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BackupStoreBoundaries(unittest.TestCase):
    def test_proxy_key_must_be_owned_and_long_and_is_never_rotated(self):
        current = {'metadata': {'labels': {'app.kubernetes.io/managed-by': 'heteronetwork-iac',
                                          'app.kubernetes.io/part-of': 'flash-backups'}},
                   'data': {'hmac-key': base64.b64encode(b'x' * 32).decode()}}
        module.validate_proxy_key(current)
        for invalid in [{'metadata': {}, 'data': current['data']},
                        {'metadata': current['metadata'], 'data': {'hmac-key': base64.b64encode(b'short').decode()}},
                        {'metadata': current['metadata'], 'data': {'hmac-key': '!!!'}}]:
            with self.assertRaises(RuntimeError):
                module.validate_proxy_key(invalid)

        provisioner = module.Provisioner(type('Args', (), {'kubectl': 'test', 'kubeconfig': 'test', 'export_namespace': 'test'})())
        calls = []
        provisioner.kube = lambda *args, **kwargs: calls.append((args, kwargs)) or current
        provisioner.ensure_proxy_key()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][2], 'get')

    def test_target_reconciliation_cannot_redirect_existing_backups(self):
        module.check_target({}, 's3://private@region/', 'limited-key')
        module.check_target({'backupTargetURL': 's3://private@region/', 'credentialSecret': 'limited-key'}, 's3://private@region/', 'limited-key')
        for existing in [{'backupTargetURL': 's3://unrelated@region/'}, {'credentialSecret': 'another-key'}]:
            with self.assertRaises(RuntimeError):
                module.check_target(existing, 's3://private@region/', 'limited-key')

    def test_global_expired_and_cross_bucket_keys_are_rejected(self):
        key = {'secretAccessKey': 'test-only', 'permissions': {'createBucket': False}, 'buckets': [{'id': 'private'}]}
        module.validate_key(key, 'private')
        for patch in [{'permissions': {'createBucket': True}}, {'buckets': [{'id': 'user-data'}]}, {'expired': True}, {'secretAccessKey': None}]:
            with self.assertRaises(RuntimeError):
                module.validate_key(dict(key, **patch), 'private')


if __name__ == '__main__':
    unittest.main()
