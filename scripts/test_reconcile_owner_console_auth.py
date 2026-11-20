import base64
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("reconcile-owner-console-auth.sh")
PREFIX = "HETERONETWORK_PUBLIC_SERVICES_"


def entry(name, value):
    return PREFIX + name + "_B64=" + base64.b64encode(value.encode()).decode() + "\n"


@unittest.skipUnless(os.geteuid() == 0, "the reconciler enforces root ownership")
class PreservePrivateOwnerAuthTests(unittest.TestCase):
    def test_native_release_preserves_existing_private_owner_realm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bootstrap = root / "bootstrap.env"
            autopilot = root / "autopilot"
            systemctl = root / "systemctl"
            marker = root / "called"
            origin = "http://console.heteronetwork.internal:18079"
            original = (entry("OIDC_ISSUER_URL", origin + "/realms/heteronetwork")
                        + entry("OIDC_CLIENT_ID", "ipars-web")
                        + entry("OIDC_REQUIRED_EMAIL", "owner@example.test")
                        + entry("OIDC_DEVICE_VERIFICATION_ORIGIN", origin)
                        + "UNRELATED_SECRET=untouched\n")
            bootstrap.write_text(original)
            bootstrap.chmod(0o600)
            autopilot.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
            autopilot.chmod(0o700)
            systemctl.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 1\n")
            systemctl.chmod(0o700)
            env = os.environ.copy()
            env.update({"HETERONETWORK_PUBLIC_SERVICES_BOOTSTRAP_ENV": str(bootstrap),
                        "HETERONETWORK_PUBLIC_SERVICES_AUTOPILOT": str(autopilot),
                        "HETERONETWORK_OWNER_EMAIL": "owner@example.test",
                        "PATH": str(root) + os.pathsep + env.get("PATH", "")})
            subprocess.run(["bash", str(SCRIPT)], env=env, check=True, capture_output=True)
            self.assertEqual(bootstrap.read_text(), original)
            self.assertFalse(marker.exists())
            env["HETERONETWORK_OWNER_EMAIL"] = "other@example.test"
            result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(bootstrap.read_text(), original)


if __name__ == "__main__":
    unittest.main()
