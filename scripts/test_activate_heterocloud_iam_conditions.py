import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from test_verify_heterocloud_iam_rollout import DIGEST, fixture


spec = importlib.util.spec_from_file_location(
    "activate_heterocloud_iam_conditions", Path(__file__).with_name("activate_heterocloud_iam_conditions.py")
)
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)
ARGS = ["activate", "--digest", DIGEST, "--ssh-key", "/key", "--known-hosts", "/known", "--jump-host", "user@host"]


class ActivationTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(activation, "SUPPORTED_DIGESTS", {DIGEST})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_refuses_an_unapproved_digest(self):
        with mock.patch.object(activation, "SUPPORTED_DIGESTS", set()):
            with self.assertRaises(RuntimeError):
                activation.verify_rollout(fixture(), DIGEST, 2, None)

    def test_refuses_to_read_credentials_when_any_endpoint_is_old(self):
        data = fixture()
        pod = next(item for item in data["items"] if item.get("kind") == "Pod")
        pod["status"]["containerStatuses"][0]["imageID"] = "old@sha256:" + "b" * 64
        with mock.patch.object(activation.sys, "argv", ARGS), mock.patch.object(
            activation.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(data), "")
        ) as run:
            self.assertEqual(activation.main(), 1)
            self.assertEqual(run.call_count, 1)

    def test_verified_fleet_sends_credential_only_via_stdin(self):
        results = [
            subprocess.CompletedProcess([], 0, json.dumps(fixture()), ""),
            subprocess.CompletedProcess([], 0, "postgres://example:private-password@127.0.0.1:25432/heterocloud", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with mock.patch.object(activation.sys, "argv", ARGS), mock.patch.object(
            activation.subprocess, "run", side_effect=results
        ) as run:
            self.assertEqual(activation.main(), 0)
            args, kwargs = run.call_args
            self.assertNotIn("private-password", str(args))
            self.assertEqual(json.loads(kwargs["input"])["password"], "private-password")
            self.assertIn("iam_conditions_enabled", json.loads(kwargs["input"])["sql"])


if __name__ == "__main__":
    unittest.main()
