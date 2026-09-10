"""Local fixtures only: no kubectl or cluster access."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("verify-dev-network-policy.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
IMAGE = "docker.io/library/busybox@sha256:" + "a" * 64


def nodes():
    return {"items": [{"metadata": {"name": name},
                       "spec": {"podCIDR": f"172.29.{i}.0/24"},
                       "status": {"addresses": [{"type": "InternalIP", "address": address}],
                                  "conditions": [{"type": "Ready", "status": "True"}]}}
                      for i, (name, address) in enumerate(gate.NODES.items())]}


class Tests(unittest.TestCase):
    def test_guard_accepts_exact_dev(self):
        gate.guard({"metadata": {"uid": "expected"}}, nodes(), "expected")

    def test_guard_rejects_wrong_cluster(self):
        with self.assertRaises(ValueError):
            gate.guard({"metadata": {"uid": "production"}}, nodes(), "expected")

    def test_guard_rejects_inventory_address_readiness_cidr(self):
        for mutation in (
            lambda n: n["items"].pop(),
            lambda n: n["items"][0]["metadata"].update(name="production"),
            lambda n: n["items"][0]["status"]["addresses"][0].update(address="10.250.0.1"),
            lambda n: n["items"][0]["status"]["conditions"][0].update(status="False"),
            lambda n: n["items"][0]["spec"].update(podCIDR="10.244.0.0/24"),
            lambda n: n["items"][0]["spec"].update(podCIDR="172.29.1.0/24"),
        ):
            fixture = nodes()
            mutation(fixture)
            with self.assertRaises(ValueError):
                gate.guard({"metadata": {"uid": "expected"}}, fixture, "expected")

    def test_manifest_security_and_exact_image(self):
        cm, ds = gate.manifests("owned", IMAGE)
        pod = ds["spec"]["template"]["spec"]
        self.assertFalse(pod.get("hostNetwork", False))
        self.assertFalse(pod["automountServiceAccountToken"])
        container = pod["containers"][0]
        self.assertEqual(container["image"], IMAGE)
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertTrue(container["volumeMounts"][0]["readOnly"])
        self.assertEqual(cm["data"], {"index.html": "ok\n"})
        self.assertEqual(container["command"], ["/bin/busybox", "httpd", "-f", "-p", "8080", "-h", "/www"])

    def test_mutable_or_non_busybox_images_rejected(self):
        for image in ("busybox:latest", "busybox@sha256:aaa", "nginx@sha256:" + "a" * 64):
            with self.assertRaises(ValueError):
                gate.manifests("owned", image)

    def test_policy_shapes(self):
        self.assertEqual(gate.policy("owned", "deny", "Ingress")["spec"]["ingress"], [])
        self.assertEqual(gate.policy("owned", "deny", "Egress")["spec"]["egress"], [])
        rule = gate.policy("owned", "allow", "Ingress", True)["spec"]["ingress"][0]
        self.assertEqual(rule["from"], [{"podSelector": {"matchLabels": gate.LABEL}}])
        self.assertEqual(rule["ports"], [{"protocol": "TCP", "port": 8080}])

    def test_cleanup_uid_precondition(self):
        runner = gate.Gate("/test/config", "cluster", IMAGE)
        runner.uid = "owned-uid"
        current = {"metadata": {"uid": runner.uid, "labels": {"dev-policy-owner": runner.owner}}}
        with patch.object(runner, "get", return_value=current), patch.object(runner, "checked") as checked:
            runner.cleanup()
        self.assertEqual(checked.call_args_list[0].kwargs["data"]["preconditions"], {"uid": "owned-uid"})
        self.assertNotIn("--force", str(checked.call_args_list))

    def test_cleanup_refuses_foreign_namespace(self):
        runner = gate.Gate("/test/config", "cluster", IMAGE)
        runner.uid = "owned-uid"
        for metadata in ({"uid": "foreign", "labels": {"dev-policy-owner": runner.owner}},
                         {"uid": runner.uid, "labels": {"dev-policy-owner": "foreign"}}):
            with patch.object(runner, "get", return_value={"metadata": metadata}), patch.object(runner, "checked") as checked:
                with self.assertRaises(ValueError):
                    runner.cleanup()
                checked.assert_not_called()

    def test_kubectl_explicit_config_timeout_json(self):
        runner = gate.Gate("/test/config", "cluster", IMAGE)
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            runner.apply({"kind": "ConfigMap"})
        self.assertIn("/test/config", run.call_args.args[0])
        self.assertIn("--request-timeout=15s", run.call_args.args[0])
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"kind": "ConfigMap"})
        self.assertEqual(run.call_args.kwargs["timeout"], 25)

    def test_phase_failure_cleans_created_namespace(self):
        runner = gate.Gate("/test/config", "cluster", IMAGE)
        with patch.object(runner, "get", side_effect=[{"metadata": {"uid": "cluster"}}, nodes()]), \
             patch.object(runner, "checked", return_value=json.dumps({"metadata": {"uid": "owned"}})), \
             patch.object(runner, "apply", side_effect=ValueError("fixture failure")), \
             patch.object(runner, "cleanup") as cleanup:
            with self.assertRaises(ValueError):
                runner.run()
        cleanup.assert_called_once()
        self.assertEqual(runner.uid, "owned")

    def test_create_timeout_recovers_only_own_uid(self):
        runner = gate.Gate("/test/config", "cluster", IMAGE)
        current = {"metadata": {"uid": "owned", "labels": {"dev-policy-owner": runner.owner}}}
        with patch.object(runner, "get", side_effect=[{"metadata": {"uid": "cluster"}}, nodes(), current]), \
             patch.object(runner, "checked", side_effect=subprocess.TimeoutExpired("kubectl", 25)), \
             patch.object(runner, "cleanup") as cleanup:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run()
        self.assertEqual(runner.uid, "owned")
        cleanup.assert_called_once()

    def test_convergence_requires_two_complete_samples(self):
        runner = gate.Gate("/test/config", "cluster", IMAGE)
        with patch.object(runner, "sample", side_effect=[["allowed"] * 6, ["denied"] * 6, ["denied"] * 6]) as sample, \
             patch.object(gate.time, "sleep"):
            evidence = runner.converge(False)
        self.assertEqual(sample.call_count, 3)
        self.assertEqual(evidence["directed_checks"], 6)
        self.assertIsNone(runner.phase_deadline)


if __name__ == "__main__":
    unittest.main()
