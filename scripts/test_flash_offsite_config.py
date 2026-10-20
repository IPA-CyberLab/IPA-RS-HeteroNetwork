import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("offsite_config", Path(__file__).with_name("configure-flash-offsite.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProtectedOffsiteConfiguration(unittest.TestCase):
    def test_credentials_require_private_regular_files_and_https_origins(self):
        config = {"endpoint": "https://example.r2.cloudflarestorage.com", "bucket": "private-test-backups",
                  "access_key": "test-only-access", "secret_key": "test-only-secret"}
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory)/"config.json"
            file.write_text(json.dumps(config));file.chmod(0o600)
            self.assertEqual(module.configuration(file)["region"], "auto")
            file.chmod(0o644)
            with self.assertRaises(ValueError):module.configuration(file)
            file.chmod(0o600)
            link = Path(directory)/"link.json";link.symlink_to(file)
            with self.assertRaises(ValueError):module.configuration(link)
            for endpoint in ("http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test/?credential=x"):
                file.write_text(json.dumps(dict(config,endpoint=endpoint)))
                with self.assertRaises(ValueError):module.configuration(file)
            file.write_text(json.dumps(dict(config,private_source=True)))
            with self.assertRaises(ValueError):module.configuration(file)


if __name__ == "__main__":
    unittest.main()
