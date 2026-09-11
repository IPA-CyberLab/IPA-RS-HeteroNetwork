import importlib.util
from pathlib import Path
import unittest
from urllib.parse import urlencode

spec = importlib.util.spec_from_file_location('verify_cloud', Path(__file__).with_name('verify-cloud.py'))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def headers():
    query = {'client_id': 'heterocloud-dev-web', 'response_type': 'code',
             'redirect_uri': 'https://dev.heterocloud.mizuame.app/api/v1/auth/oidc/callback',
             'code_challenge_method': 'S256', 'state': 'test-state', 'nonce': 'test-nonce',
             'code_challenge': 'test-challenge'}
    return {'location': 'https://id.dev.heterocloud.mizuame.app/realms/heterocloud-dev/protocol/openid-connect/auth?' + urlencode(query),
            'set-cookie': 'hc_oidc_transaction=fixture; Secure; HttpOnly; SameSite=Lax'}


class InitiationChecks(unittest.TestCase):
    def test_expected_redirect(self):
        verify.validate_start(303, headers())

    def test_failures_are_not_readiness(self):
        for status in (200, 401, 503, 504):
            with self.assertRaises(ValueError):
                verify.validate_start(status, headers())

    def test_foreign_issuer_callback_and_missing_pkce(self):
        for before, after in [('id.dev.', 'id.prod.'), ('heterocloud-dev-web', 'foreign'),
                              ('code_challenge_method=S256', 'code_challenge_method=plain'),
                              ('state=test-state', 'state='),
                              ('redirect_uri=https', 'redirect_uri=http')]:
            value = headers()
            value['location'] = value['location'].replace(before, after)
            with self.assertRaises(ValueError):
                verify.validate_start(303, value)

    def test_cookie_protection_required(self):
        for field in ('Secure', 'HttpOnly', 'SameSite=Lax'):
            value = headers()
            value['set-cookie'] = value['set-cookie'].replace('; ' + field, '')
            with self.assertRaises(ValueError):
                verify.validate_start(303, value)


if __name__ == '__main__':
    unittest.main()
