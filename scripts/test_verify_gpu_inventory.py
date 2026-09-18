#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("verify_gpu_inventory.py")
SPEC = importlib.util.spec_from_file_location("verify_gpu_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


PHYSICAL_ID = "GPU-11111111-2222-3333-4444-555555555555"
SUBJECT = "11111111-2222-3333-4444-555555555555"


def snapshot():
    nodes = {
        "items": [{
            "metadata": {"name": "uc-k8sp5", "labels": {
                verify.PRESENT_LABEL: "true",
                verify.COUNT_LABEL: "1",
                verify.TYPE_LABEL: "nvidia-geforce-gtx-1080-ti",
            }}
        }]
    }
    inventory = {
        "items": [{
            "metadata": {"name": verify.hashed_name(PHYSICAL_ID), "labels": {
                verify.MANAGED_BY_LABEL: "heteronetwork-iac",
                verify.INVENTORY_NODE_LABEL: "uc-k8sp5",
                verify.TYPE_LABEL: "nvidia-geforce-gtx-1080-ti",
            }},
            "spec": {
                "node_name": "uc-k8sp5",
                "physical_id": PHYSICAL_ID,
                "gpu_type": "nvidia-geforce-gtx-1080-ti",
                "model": "NVIDIA GeForce GTX 1080 Ti",
                "memory_mib": 11264,
                "visibility": "private",
                "private_assignments": [],
            },
            "status": {"health": "healthy"},
        }]
    }
    return nodes, inventory


class VerifyGpuInventoryTests(unittest.TestCase):
    def test_accepts_private_inventory_with_no_assignments(self):
        nodes, inventory = snapshot()
        result = verify.validate_snapshot(
            nodes,
            inventory,
            {"uc-k8sp5": 1},
            {"uc-k8sp5": "nvidia-geforce-gtx-1080-ti"},
        )
        self.assertEqual(result["uc-k8sp5"]["count"], 1)
        self.assertNotIn("physical_id", result["uc-k8sp5"])

    def test_rejects_identity_that_exposes_or_mismatches_uuid(self):
        nodes, inventory = snapshot()
        inventory["items"][0]["metadata"]["name"] = "gpu-visible-id"
        with self.assertRaisesRegex(RuntimeError, "protected identity"):
            verify.validate_snapshot(nodes, inventory, {}, {})

    def test_rejects_unhealthy_or_invalid_assignments(self):
        nodes, inventory = snapshot()
        inventory["items"][0]["spec"]["private_assignments"] = [SUBJECT, SUBJECT]
        with self.assertRaisesRegex(RuntimeError, "private assignments"):
            verify.validate_snapshot(nodes, inventory, {}, {})
        _, inventory = snapshot()
        inventory["items"][0]["status"]["health"] = "unhealthy"
        with self.assertRaisesRegex(RuntimeError, "not healthy"):
            verify.validate_snapshot(nodes, inventory, {}, {})


if __name__ == "__main__":
    unittest.main()
