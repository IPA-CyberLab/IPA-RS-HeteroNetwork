import base64
import json
import unittest

import app_secrets
import livekit_config as m


class LivekitConfigTests(unittest.TestCase):
    def test_authenticated_three_sentinels_without_static_master(self):
        seeds = app_secrets.generate_seeds()
        config = m.configuration(seeds)
        redis = config['redis']
        self.assertEqual(redis['sentinel_master_name'], 'flowmaster')
        self.assertEqual(len(set(redis['sentinel_addresses'])), 3)
        self.assertTrue(all(address.endswith('.heterocloud-flow-dev.svc.cluster.local:26379')
                            for address in redis['sentinel_addresses']))
        self.assertNotIn('address', redis)
        self.assertEqual(redis['password'], seeds['redis'])
        self.assertEqual(redis['sentinel_password'], seeds['redis'])

    def test_dev_turn_and_no_embedded_private_signing_keys(self):
        config = m.configuration(app_secrets.generate_seeds())
        self.assertEqual(config['rtc']['stun_servers'], ['turn.dev.heterocloud.mizuame.app:13478'])
        for server in config['rtc']['turn_servers']:
            self.assertEqual(server['port'], 13478)
            self.assertEqual(server['secret_file'], '/etc/livekit-turn/turn-shared-secret')
            self.assertNotIn('secret', server)
        self.assertNotIn('PRIVATE KEY', json.dumps(config))

    def test_secret_is_deterministic_and_private(self):
        seeds = app_secrets.generate_seeds()
        obj = m.secret(seeds)
        self.assertEqual(obj, m.secret(seeds))
        self.assertEqual(obj['kind'], 'Secret')
        self.assertEqual(obj['metadata']['namespace'], m.NAMESPACE)
        self.assertEqual(json.loads(base64.b64decode(obj['data']['livekit.yaml'])), m.configuration(seeds))


if __name__ == '__main__':
    unittest.main()
