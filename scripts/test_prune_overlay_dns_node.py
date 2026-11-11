import unittest

from prune_overlay_dns_node import without_address


class OverlayDnsRetirementTests(unittest.TestCase):
    def test_removes_only_the_retired_address_and_is_idempotent(self):
        zone = {"schema_version": 1, "records": {"svc.internal": ["10.0.0.1", "10.0.0.2"]},
                "gateway_records": {"svc.internal": {"10.0.0.1": ["10.0.0.1", "10.0.0.2"],
                                                      "10.0.0.2": ["10.0.0.2", "10.0.0.1"]}}}
        result = without_address(zone, "10.0.0.1")
        self.assertEqual(result["records"]["svc.internal"], ["10.0.0.2"])
        self.assertEqual(result["gateway_records"]["svc.internal"], {"10.0.0.2": ["10.0.0.2"]})
        self.assertEqual(without_address(result, "10.0.0.1"), result)
        self.assertEqual(len(zone["records"]["svc.internal"]), 2)

    def test_rejects_deleting_the_last_address(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            without_address({"schema_version": 1, "records": {"svc.internal": ["10.0.0.1"]}}, "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
