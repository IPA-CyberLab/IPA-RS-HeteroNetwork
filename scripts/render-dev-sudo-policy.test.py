import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/render-dev-sudo-policy.py"
spec = importlib.util.spec_from_file_location("render_dev_sudo_policy", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RenderDevSudoPolicyTests(unittest.TestCase):
    def test_policy_covers_exact_roster_and_owner(self):
        policy = module.render()
        self.assertEqual(policy["schema_version"], 2)
        self.assertEqual(set(policy["hosts"]),
                         {member["node_id"] for member in policy["manifest"]["members"]})
        for host in policy["hosts"].values():
            self.assertEqual(host["callers"], {"1000": {
                "issuer": "https://heterocloud.mizuame.app/id/realms/heterocloud",
                "subject": "4daa569e-635c-49ed-bb17-5fe0a07581b2",
            }})

    def test_renderer_is_deterministic_and_checkable(self):
        first = module.encoded()
        self.assertEqual(first, module.encoded())
        self.assertEqual(json.loads(first), module.render())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            subprocess.run(["python3", SOURCE, "--output", output], check=True)
            subprocess.run(["python3", SOURCE, "--check", output], check=True)
            duplicate = subprocess.run(["python3", SOURCE, "--output", output],
                                       capture_output=True)
            self.assertNotEqual(duplicate.returncode, 0)


if __name__ == "__main__":
    unittest.main()
