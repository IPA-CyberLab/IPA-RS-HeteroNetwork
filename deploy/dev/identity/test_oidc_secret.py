import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('oidc_secret', Path(__file__).with_name('provision-oidc-secret.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OidcSecretTests(unittest.TestCase):
    def fixture(self):
        return m.desired_secret('fixture-dev-uid', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'fixture-credential-only-1234')

    def test_exact_existing_secret_is_idempotent(self):
        expected = self.fixture()
        actual = copy.deepcopy(expected)
        actual['metadata']['resourceVersion'] = '1'
        m.verify_secret(actual, expected)
        self.assertEqual(set(expected['data']), {'client-secret'})

    def test_foreign_or_changed_secret_is_rejected(self):
        expected = self.fixture()
        for field, value in (('namespace', 'heterocloud'), ('name', 'other'),
                             ('annotations', {}), ('labels', {}), ('deletionTimestamp', 'now')):
            actual = copy.deepcopy(expected)
            actual['metadata'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.verify_secret(actual, expected)
        actual = copy.deepcopy(expected)
        actual['data']['client-secret'] = 'different'
        with self.assertRaises(ValueError):
            m.verify_secret(actual, expected)

    def test_invalid_credentials_are_not_echoed(self):
        for value in ('short', 'x' * 4097, 'credential-with-newline\n'):
            with self.assertRaises(ValueError) as caught:
                m.desired_secret('fixture', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', value)
            self.assertNotIn(value, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
