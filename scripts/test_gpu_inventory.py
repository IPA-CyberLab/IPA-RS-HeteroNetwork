#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("gpu_inventory.py")
SPEC = importlib.util.spec_from_file_location("gpu_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
gpu_inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gpu_inventory
SPEC.loader.exec_module(gpu_inventory)


SAMPLE = """\
GPU-11111111-2222-3333-4444-555555555555, NVIDIA GeForce GTX 1080 Ti, 00000000:03:00.0, 11264
GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, NVIDIA GeForce GTX 1080 Ti, 00000000:04:00.0, 11264
"""


class GpuInventoryTests(unittest.TestCase):
    def test_playbook_passes_stdin_marker_as_a_string(self):
        playbook = (
            MODULE_PATH.parents[1]
            / "deploy"
            / "terraform"
            / "master-only"
            / "ansible"
            / "gpu-inventory.yaml"
        ).read_text().splitlines()
        stdin_markers = [
            playbook[index + 1].strip()
            for index, line in enumerate(playbook[:-1])
            if line.strip() == "- -f"
        ]
        self.assertEqual(stdin_markers, ['- "-"', '- "-"'])

    def test_renders_hardware_without_owner_access_fields(self):
        inventory = gpu_inventory.render_inventory(
            "uc-k8sp5",
            gpu_inventory.parse_nvidia_smi(SAMPLE),
            expected_count=2,
            expected_type="nvidia-geforce-gtx-1080-ti",
            expected_model="NVIDIA GeForce GTX 1080 Ti",
            expected_memory_mib=11264,
        )
        self.assertEqual(inventory["gpu_type"], "nvidia-geforce-gtx-1080-ti")
        self.assertEqual(inventory["count"], 2)
        self.assertEqual(len({item["metadata"]["name"] for item in inventory["resources"]}), 2)
        for item in inventory["resources"]:
            self.assertRegex(item["metadata"]["name"], r"^gpu-[0-9a-f]{16}$")
            self.assertNotIn("visibility", item["spec"])
            self.assertNotIn("private_assignments", item["spec"])
            self.assertNotIn(item["spec"]["physical_id"], item["metadata"]["name"])

    def test_rejects_declared_hardware_drift(self):
        with self.assertRaisesRegex(gpu_inventory.InventoryError, "count"):
            gpu_inventory.render_inventory(
                "uc-k8sp5",
                gpu_inventory.parse_nvidia_smi(SAMPLE),
                expected_count=1,
            )

    def test_rejects_mixed_models_and_duplicate_ids(self):
        mixed = SAMPLE.replace(
            "NVIDIA GeForce GTX 1080 Ti, 00000000:04:00.0",
            "NVIDIA RTX 6000 Ada, 00000000:04:00.0",
        )
        with self.assertRaisesRegex(gpu_inventory.InventoryError, "one GPU model"):
            gpu_inventory.render_inventory("uc-k8sp5", gpu_inventory.parse_nvidia_smi(mixed))
        duplicate = SAMPLE.replace(
            "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "GPU-11111111-2222-3333-4444-555555555555",
        )
        with self.assertRaisesRegex(gpu_inventory.InventoryError, "duplicate GPU UUID"):
            gpu_inventory.parse_nvidia_smi(duplicate)

    def test_long_model_has_stable_dns_label_type(self):
        model = "NVIDIA " + "Very Long Accelerator Model " * 5
        first = gpu_inventory.canonical_gpu_type(model)
        second = gpu_inventory.canonical_gpu_type(model)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 63)
        self.assertRegex(first, gpu_inventory.DNS_LABEL)


if __name__ == "__main__":
    unittest.main()
