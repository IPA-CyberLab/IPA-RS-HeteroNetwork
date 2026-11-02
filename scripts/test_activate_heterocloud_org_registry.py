import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from test_verify_heterocloud_iam_rollout import DIGEST, fixture


spec = importlib.util.spec_from_file_location(
    "activate_heterocloud_org_registry", Path(__file__).with_name("activate_heterocloud_org_registry.py")
)
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)


def worker_fixture():
    data = fixture()
    worker = next(item for item in data["items"] if item.get("kind") == "Deployment"
                  and item["metadata"]["name"] == "heterocloud-heterocloud-worker")
    container = worker["spec"]["template"]["spec"]["containers"][0]
    container["command"] = ["/usr/local/bin/heterocloud-worker"]
    container["args"] = ["--database-url-file=/run/database-url"]
    return data


class RegistryActivationTest(unittest.TestCase):
    def test_refuses_unapproved_or_incomplete_rollouts(self):
        with mock.patch.object(activation, "SUPPORTED_DIGESTS", set()):
            with self.assertRaises(RuntimeError):
                activation.verified_worker(worker_fixture(), DIGEST, 2, 2)
        data = worker_fixture()
        data["items"][1]["status"]["containerStatuses"][0]["imageID"] = "old@sha256:" + "b" * 64
        with mock.patch.object(activation, "SUPPORTED_DIGESTS", {DIGEST}):
            with self.assertRaises(RuntimeError):
                activation.verified_worker(data, DIGEST, 2, 2)

    def test_verified_worker_activates_via_its_mounted_secret(self):
        responses = [
            subprocess.CompletedProcess([], 0, json.dumps(worker_fixture()), ""),
            subprocess.CompletedProcess([], 0, "organization_registry_credentials_enabled=true\n", ""),
        ]
        with mock.patch.object(activation, "SUPPORTED_DIGESTS", {DIGEST}), mock.patch.object(
            activation.sys, "argv", ["activate", "--digest", DIGEST, "--desired-replicas", "2"]
        ), mock.patch.object(activation.subprocess, "run", side_effect=responses) as run:
            self.assertEqual(activation.main(), 0)
            command = run.call_args.args[0]
            self.assertIn("worker-0", command)
            self.assertIn("--enable-organization-registry-credentials", command)
            self.assertNotIn("password", str(run.call_args))

    def test_absent_worker_confirmation_fails(self):
        responses = [
            subprocess.CompletedProcess([], 0, json.dumps(worker_fixture()), ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with mock.patch.object(activation, "SUPPORTED_DIGESTS", {DIGEST}), mock.patch.object(
            activation.sys, "argv", ["activate", "--digest", DIGEST, "--desired-replicas", "2"]
        ), mock.patch.object(activation.subprocess, "run", side_effect=responses):
            self.assertEqual(activation.main(), 1)


if __name__ == "__main__":
    unittest.main()
