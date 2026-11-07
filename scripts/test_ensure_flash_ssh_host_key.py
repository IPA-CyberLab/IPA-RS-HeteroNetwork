import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("ensure-flash-ssh-host-key.py")


class HostKeyTest(unittest.TestCase):
    def test_creation_is_idempotent_and_invalid_secret_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "kubectl"
            fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args=sys.argv[1:]; root=pathlib.Path(os.environ["FAKE_KUBE_STORE"])
if args[:2] == ["get","namespace"]:
 print("namespace/heterocloud"); sys.exit(0)
if args[:4] == ["-n","heterocloud","get","secret"]:
 if root.exists(): print(root.read_text())
 sys.exit(0)
if args[:2] == ["create","-f"]:
 if root.exists(): sys.exit(1)
 root.write_text(sys.stdin.read()); sys.exit(0)
sys.exit(1)
''')
            fake.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{root}:{env['PATH']}"
            env["FAKE_KUBE_STORE"] = str(root / "secret.json")
            first = subprocess.run(["python3", str(SCRIPT)], env=env, capture_output=True, check=True, text=True)
            saved = (root / "secret.json").read_bytes()
            second = subprocess.run(["python3", str(SCRIPT)], env=env, capture_output=True, check=True, text=True)
            self.assertEqual(saved, (root / "secret.json").read_bytes())
            self.assertEqual(json.loads(first.stdout)["fingerprint"], json.loads(second.stdout)["fingerprint"])
            self.assertNotIn("PRIVATE KEY", first.stdout + first.stderr + second.stdout + second.stderr)
            (root / "secret.json").write_text(json.dumps({"data":{"host-key":"bm90LWEtcHJpdmF0ZS1rZXk="}}))
            bad = (root / "secret.json").read_bytes()
            refused = subprocess.run(["python3", str(SCRIPT)], env=env, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(bad, (root / "secret.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
