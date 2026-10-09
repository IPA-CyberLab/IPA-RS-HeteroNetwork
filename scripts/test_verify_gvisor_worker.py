import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "gvisor_worker", Path(__file__).with_name("verify-gvisor-worker.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeAcceptanceTests(unittest.TestCase):
    def execute(self, phase="Succeeded", evidence="GVISOR_ACCEPTED", dedicated=False):
        objects, calls = {}, []
        node = {"metadata": {"name": "uc-k8sp4", "labels": {
            "heteronetwork.io/control-plane-only": "true" if dedicated else "false"
        }}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}

        def run(argv, input=None, **kwargs):
            command = argv[3:]
            calls.append(command)
            if command[0] == "get":
                kind, name = command[1:3]
                obj = node if kind == "node" else objects.get((kind, name))
                return subprocess.CompletedProcess(argv, 0, json.dumps(obj) if obj else "", "")
            if command[0] == "create":
                obj = json.loads(input)
                obj["metadata"]["uid"] = obj["metadata"]["name"]
                if obj["kind"] == "Pod":
                    obj["status"] = {"phase": phase}
                objects[(obj["kind"].lower(), obj["metadata"]["name"])] = obj
                return subprocess.CompletedProcess(argv, 0, json.dumps(obj), "")
            if command[0] == "logs":
                return subprocess.CompletedProcess(argv, 0, evidence, "")
            if command[0] == "delete":
                del objects[tuple(command[1:3])]
            return subprocess.CompletedProcess(argv, 0, "", "")

        error = None
        with patch("sys.argv", ["verify", "--node=uc-k8sp4", "--kubeconfig=/test/kube"]), \
                patch.object(module.subprocess, "run", side_effect=run), \
                patch("builtins.print"):
            try:
                module.main()
            except RuntimeError as exc:
                error = str(exc)
        return calls, objects, error

    def test_label_requires_execution_evidence(self):
        calls, objects, error = self.execute()
        self.assertIsNone(error)
        commands = [c[0] for c in calls]
        self.assertGreater(commands.index("patch"), commands.index("logs"))
        self.assertEqual(objects, {})

    def test_failed_sandbox_does_not_publish_capacity(self):
        calls, objects, error = self.execute(phase="Failed")
        self.assertIn("failed the sandbox", error)
        self.assertFalse(any(c[0] == "patch" for c in calls))
        self.assertEqual(objects, {})

    def test_missing_evidence_does_not_publish_capacity(self):
        calls, objects, error = self.execute(evidence="unexpected runtime")
        self.assertIn("evidence is missing", error)
        self.assertFalse(any(c[0] == "patch" for c in calls))
        self.assertEqual(objects, {})

    def test_dedicated_master_is_rejected_before_mutation(self):
        calls, objects, error = self.execute(dedicated=True)
        self.assertIn("workload worker", error)
        self.assertFalse(any(c[0] in ("create", "patch") for c in calls))
        self.assertEqual(objects, {})

    def test_control_plane_taint_is_rejected(self):
        node = {"metadata": {}, "spec": {"taints": [{
            "key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"
        }]}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
        self.assertFalse(module.eligible(node))


if __name__ == "__main__":
    unittest.main()
