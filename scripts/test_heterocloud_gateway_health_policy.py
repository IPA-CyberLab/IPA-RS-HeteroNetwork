"""Guard availability and safe OIDC retries during a degraded API rollout."""

from pathlib import Path
import unittest

import yaml


POLICIES = Path(__file__).resolve().parents[1] / "deploy/gitops/envoy-gateway"


def read_policy(filename):
    return yaml.safe_load((POLICIES / filename).read_text())["spec"]


class GatewayHealthPolicyTest(unittest.TestCase):
    def test_a_single_endpoint_is_not_lost_to_one_transient_probe(self):
        for filename in ("backend-traffic-policy.yaml", "oidc-callback-backend-traffic-policy.yaml"):
            with self.subTest(filename=filename):
                health = read_policy(filename)["healthCheck"]
                self.assertEqual(health["panicThreshold"], 50)
                self.assertLessEqual(health["passive"]["maxEjectionPercent"], 50)
                self.assertGreaterEqual(health["active"]["unhealthyThreshold"], 3)
                self.assertGreaterEqual(int(health["active"]["timeout"].removesuffix("s")), 3)
                self.assertIn(503, health["active"]["http"]["retriableStatuses"])

    def test_single_use_oidc_callback_never_retries_an_accepted_request(self):
        retry = read_policy("oidc-callback-backend-traffic-policy.yaml")["retry"]
        self.assertEqual(
            set(retry["retryOn"]["triggers"]),
            {"connect-failure", "reset-before-request", "refused-stream"},
        )


if __name__ == "__main__":
    unittest.main()
