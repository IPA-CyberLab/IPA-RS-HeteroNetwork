import copy
import json
from pathlib import Path
import tempfile
import unittest

import retire_hn_registration as retirement


class NetworkRegistrationRetirementTests(unittest.TestCase):
    def setUp(self):
        self.target = {"node_id": "node-" + "a" * 32, "hostname": "worker-old",
                       "vpn_ip": "10.250.0.21", "cluster_id": "cluster-a"}
        self.survivor = {"node_id": "node-" + "b" * 32, "hostname": "worker-live",
                         "vpn_ip": "10.250.0.22", "cluster_id": "cluster-a"}
        self.nodes = [copy.deepcopy(self.target), copy.deepcopy(self.survivor)]
        self.calls = []

    def api(self, _base, _token, method, path):
        self.calls.append((method, path))
        if method == "GET":
            return [{"node": copy.deepcopy(node)} for node in self.nodes]
        self.assertEqual(method, "DELETE")
        removed = self.nodes.pop(0)
        return {"node": removed, "removed_path_count": 2}

    def test_checks_then_removes_only_the_exact_registration(self):
        result = retirement.retire("http://127.0.0.1", "token", self.target, True, self.api)
        self.assertEqual(result["result"], "removed")
        self.assertEqual(result["removed_path_count"], 2)
        self.assertEqual(self.nodes, [self.survivor])
        self.assertEqual([method for method, _ in self.calls], ["GET", "DELETE", "GET"])

    def test_preview_is_read_only_and_repeat_is_idempotent(self):
        result = retirement.retire("http://127.0.0.1", "token", self.target, False, self.api)
        self.assertEqual(result["result"], "ready")
        self.assertEqual([method for method, _ in self.calls], ["GET"])
        self.nodes = [self.survivor]
        self.assertEqual(retirement.retire("http://127.0.0.1", "token", self.target, True,
                                           self.api)["result"], "already_absent")

    def test_identity_and_address_mismatches_never_delete(self):
        for field in ("hostname", "vpn_ip", "cluster_id"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.target)
                changed[field] = "wrong"
                self.calls.clear()
                with self.assertRaises(ValueError):
                    retirement.retire("http://127.0.0.1", "token", changed, True, self.api)
                self.assertFalse(any(method == "DELETE" for method, _ in self.calls))
        self.nodes = [dict(self.survivor, vpn_ip=self.target["vpn_ip"])]
        with self.assertRaises(ValueError):
            retirement.retire("http://127.0.0.1", "token", self.target, True, self.api)

    def test_untrusted_identifiers_never_reach_api(self):
        target = dict(self.target, node_id="../unsafe")
        with self.assertRaises(ValueError):
            retirement.retire("http://127.0.0.1", "token", target, True, self.api)
        self.assertFalse(self.calls)

    def test_service_environment_is_parsed_without_shell_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "env"
            path.write_text('HETERONETWORK_CLUSTER_ID="cluster-a"\n'
                            'HETERONETWORK_VALUE="$(touch /tmp/never-run)"\n'
                            'UNRELATED=value\n')
            result = retirement.read_systemd_environment(path)
            self.assertEqual(result["HETERONETWORK_CLUSTER_ID"], "cluster-a")
            self.assertEqual(result["HETERONETWORK_VALUE"], "$(touch /tmp/never-run)")
            self.assertNotIn("UNRELATED", result)


if __name__ == "__main__":
    unittest.main()
