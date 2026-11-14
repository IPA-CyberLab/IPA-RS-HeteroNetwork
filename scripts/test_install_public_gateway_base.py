import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name('install-public-gateway-base.py')
spec = importlib.util.spec_from_file_location('install_gateway_base', SOURCE)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
BASE = b'(heterocloud_envoy) { respond ok }\nhttp://heterocloud.mizuame.app {\n respond ok\n}\n'
TLS = gateway.TLS_BEGIN + b'(heterocloud_public_tls) { tls cert key }\n' + gateway.TLS_END
CUSTOM = gateway.CUSTOM_BEGIN + b'https://example.net { respond ok }\n' + gateway.CUSTOM_END


@unittest.skipUnless(os.geteuid() == 0, 'requires root ownership checks')
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/run')
        self.host = Path(self.temp.name)
        self.candidate = self.host / 'public-gateway-base.candidate.Caddyfile'
        self.base = self.host / 'public-gateway-base.Caddyfile'
        self.extra = self.host / 'public-gateway-extra.Caddyfile'
        self.candidate.write_bytes(BASE)

    def tearDown(self):
        self.temp.cleanup()

    def test_initial_seed_is_not_served_before_tls_sync(self):
        self.assertTrue(gateway.install(self.host))
        self.assertEqual(self.base.read_bytes(), BASE)
        self.assertEqual(self.extra.read_bytes(), BASE)
        self.candidate.write_bytes(BASE + b'# change\n')
        with self.assertRaises(ValueError):
            gateway.install(self.host)
        self.assertEqual(self.base.read_bytes(), BASE)

    def test_validates_generated_tls_and_custom_routes_before_atomic_publish(self):
        self.base.write_bytes(BASE)
        self.extra.write_bytes(BASE.replace(gateway.ANCHOR, TLS + CUSTOM + gateway.ANCHOR))
        new = BASE + b'# new base\n'
        self.candidate.write_bytes(new)
        def validate(argv, **kwargs):
            test_config = Path(argv[3]).read_bytes()
            self.assertIn(TLS, test_config)
            self.assertIn(CUSTOM, test_config)
            self.assertIn(b'# new base', test_config)
            self.assertEqual(self.base.read_bytes(), BASE)
        with patch.object(gateway.subprocess, 'run', side_effect=validate):
            self.assertTrue(gateway.install(self.host))
        self.assertEqual(self.base.read_bytes(), new)
        self.assertNotIn(b'# new base', self.extra.read_bytes())

    def test_invalid_configuration_preserves_live_base(self):
        self.base.write_bytes(BASE)
        self.extra.write_bytes(BASE.replace(gateway.ANCHOR, TLS + gateway.ANCHOR))
        self.candidate.write_bytes(BASE + b'# broken\n')
        with patch.object(gateway.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'caddy')):
            with self.assertRaises(subprocess.CalledProcessError):
                gateway.install(self.host)
        self.assertEqual(self.base.read_bytes(), BASE)
        self.assertEqual(list(self.host.glob('.gateway-validate-*')), [])

    def test_rejects_symlink_or_generated_blocks_in_the_base(self):
        self.candidate.unlink()
        self.candidate.symlink_to('/etc/passwd')
        with self.assertRaises(OSError):
            gateway.install(self.host)
        self.candidate.unlink()
        self.candidate.write_bytes(BASE + TLS)
        with self.assertRaises(ValueError):
            gateway.install(self.host)


if __name__ == '__main__':
    unittest.main()
