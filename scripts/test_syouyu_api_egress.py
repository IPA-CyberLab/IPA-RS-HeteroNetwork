#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "fix", Path(__file__).with_name("fix-syouyu-api-egress.py"))
fix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "metadata": {"name": fix.POLICY, "namespace": fix.NAMESPACE,
                         "uid": "reviewed", "resourceVersion": "123"},
            "spec": {"podSelector": {"matchLabels": fix.SELECTOR},
                     "egress": [{"to": [{"podSelector": {}}]},
                                {"to": [{"ipBlock": {"cidr": "10.96.0.0/12"}}],
                                 "ports": [{"port": p, "protocol": "TCP"}
                                           for p in (443, 6443, 7443)]}]},
        }
        self.slices = {"items": [{"endpoints": [{"addresses": sorted(fix.ENDPOINTS)}]}]}

    def test_bounded_patch_and_idempotence(self):
        original = copy.deepcopy(self.policy)
        patch = fix.build_patch(self.policy, self.slices)
        self.assertEqual(self.policy, original)
        self.assertEqual([p["op"] for p in patch], ["test", "test", "test", "replace"])
        self.assertEqual(patch[-1]["path"], "/spec/egress/1/to")
        self.assertEqual(len(patch[-1]["value"]), 5)
        self.policy["spec"]["egress"][1]["to"] = patch[-1]["value"]
        self.assertEqual(fix.build_patch(self.policy, self.slices), [])

    def test_changed_endpoints_rejected(self):
        self.slices["items"][0]["endpoints"][0]["addresses"] = ["10.250.0.4"]
        with self.assertRaises(ValueError):
            fix.build_patch(self.policy, self.slices)

    def test_helm_separate_rules_are_idempotent(self):
        for address in fix.ENDPOINTS:
            rule = copy.deepcopy(self.policy["spec"]["egress"][1])
            rule["to"] = [{"ipBlock": {"cidr": address + "/32"}}]
            self.policy["spec"]["egress"].append(rule)
        self.assertEqual(fix.build_patch(self.policy, self.slices), [])

    def test_reviewed_endpoint_temporarily_absent(self):
        self.slices["items"][0]["endpoints"][0]["addresses"] = ["10.250.0.10"]
        self.assertTrue(fix.build_patch(self.policy, self.slices))

    def test_empty_endpoints_rejected(self):
        self.slices["items"] = []
        with self.assertRaises(ValueError):
            fix.build_patch(self.policy, self.slices)

    def test_changed_selector_rejected(self):
        self.policy["spec"]["podSelector"] = {}
        with self.assertRaises(ValueError):
            fix.build_patch(self.policy, self.slices)

    def test_changed_ports_rejected(self):
        self.policy["spec"]["egress"][1]["ports"] = []
        with self.assertRaises(ValueError):
            fix.build_patch(self.policy, self.slices)


if __name__ == "__main__":
    unittest.main()
