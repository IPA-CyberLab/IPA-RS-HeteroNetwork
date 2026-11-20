import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).with_name("private-owner-device-proof.py")
spec = importlib.util.spec_from_file_location("private_owner_device", PATH)
device = importlib.util.module_from_spec(spec)
spec.loader.exec_module(device)


class PrivateOwnerDeviceTests(unittest.TestCase):
    def setUp(self):
        self.issuer = "http://console.heteronetwork.internal:18079/realms/heteronetwork"
        self.response = {
            "verification_uri": self.issuer + "/device",
            "verification_uri_complete": self.issuer + "/device?user_code=ABCD-EFGH",
            "user_code": "ABCD-EFGH", "device_code": "x" * 48, "expires_in": 600, "interval": 5,
        }

    def test_accepts_only_the_expected_private_verification(self):
        device.validate_start(self.response, self.issuer)
        for value in ("https://public.example/device?user_code=ABCD-EFGH",
                      self.issuer + "/device?user_code=OTHER-CODE",
                      self.issuer + "/device?user_code=ABCD-EFGH&extra=1"):
            self.response["verification_uri_complete"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                device.validate_start(self.response, self.issuer)

    def test_rejects_public_or_ambiguous_gateway(self):
        self.assertEqual(device.gateway_origin("http://10.250.0.2:18079"), "http://10.250.0.2:18079")
        for value in ("http://8.8.8.8:18079", "http://user@10.250.0.2:18079",
                      "http://10.250.0.2:18079/path", "https://10.250.0.2:18079"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                device.gateway_origin(value)


if __name__ == "__main__":
    unittest.main()
