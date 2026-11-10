"""Check the declared two-worker Flow placement and resource budget."""
import unittest
from pathlib import Path

import yaml


class FlowCapacityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        app = yaml.safe_load((root / "deploy/gitops/applications/heterocloud-flow.yaml").read_text())
        cls.values = yaml.safe_load(app["spec"]["source"]["helm"]["values"])

    def test_component_replica_counts_keep_two_copies(self):
        for component in ("api", "matchmaker", "signaling", "livekit"):
            self.assertEqual(self.values[component]["replicaCount"], 2)
        self.assertEqual(self.values["redis"]["replica"]["replicaCount"], 2)
        self.assertEqual(self.values["redis"]["sentinel"]["quorum"], 2)

    def test_workload_spread_and_worker_database_endpoints(self):
        spread = self.values["topologySpread"]
        self.assertEqual(spread["maxSkew"], 1)
        self.assertEqual(spread["whenUnsatisfiable"], "DoNotSchedule")
        proxy = self.values["database"]["proxy"]
        self.assertIn("10.250.0.2", proxy["addresses"])
        self.assertIn("10.250.0.10", proxy["addresses"])
        self.assertNotIn("10.250.0.8", proxy["addresses"])
        self.assertEqual(proxy["endpointNodeNames"]["10.250.0.2"], "uc-k8sp5")


if __name__ == "__main__":
    unittest.main()
