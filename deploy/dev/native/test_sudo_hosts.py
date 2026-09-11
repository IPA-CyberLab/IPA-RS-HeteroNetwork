import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


class SudoHostPinsTests(unittest.TestCase):
    def test_exact_inventory_matches_frozen_manifest(self):
        hosts = json.loads((ROOT / "sudo-hosts.json").read_bytes())
        manifest = json.loads((ROOT / "sudo-manifest.json").read_bytes())
        self.assertEqual(set(hosts), {"schema_version", "cluster_id", "manifest_file_sha256", "hosts"})
        self.assertEqual(hosts["schema_version"], 1)
        self.assertEqual(hosts["cluster_id"], manifest["cluster_id"])
        expected = {
            "hetero-dev-1": ("381d1ae16f555c59b738d8d01dd14c94", manifest["members"][0]["node_id"]),
            "hetero-dev-2": ("acc5151b6b245b63864372933dab97da", manifest["members"][1]["node_id"]),
            "hetero-dev-3": ("165a6e8acc3a56fdbf9bef8c90d6cf4d", manifest["members"][2]["node_id"]),
        }
        self.assertEqual({host["guest"] for host in hosts["hosts"]}, set(expected))
        for host in hosts["hosts"]:
            self.assertEqual((host["machine_id"], host["host_node_id"]), expected[host["guest"]])
            self.assertEqual(host["attestation_key_epoch"], 1)

    def test_public_keys_are_bounded_distinct_and_nonzero(self):
        hosts = json.loads((ROOT / "sudo-hosts.json").read_bytes())["hosts"]
        keys = []
        for host in hosts:
            key = host["attestation_public_key"]
            self.assertEqual(len(key), 32)
            self.assertTrue(all(type(value) is int and 0 <= value <= 255 for value in key))
            self.assertNotEqual(key, [0] * 32)
            keys.append(bytes(key))
        self.assertEqual(len(set(keys)), 3)


if __name__ == "__main__":
    unittest.main()
