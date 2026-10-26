import copy
import json
from pathlib import Path
import tempfile
import unittest
import importlib.util
import shutil
import subprocess
import sys
import yaml

from node_lifecycle import ROSTER, active_peers, gateway_ips, stopped_hosts


class NodeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.roster = json.loads(ROSTER.read_text())

    def test_stopped_host_is_excluded_until_operator_resumes_it(self):
        self.assertEqual(stopped_hosts(self.roster), {"uc-k8sp4"})
        self.assertNotIn("10.250.0.11", {p["vpn_ip"] for p in active_peers(self.roster)})
        self.assertNotIn("10.250.0.11", gateway_ips(ROSTER).split(","))
        self.roster["node_states"]["uc-k8sp4"] = {"state": "active"}
        self.assertIn("10.250.0.11", {p["vpn_ip"] for p in active_peers(self.roster)})

    def test_bad_flags_fail_instead_of_skipping_health_checks(self):
        for value in [{"state": "stoped"}, {"state": "stopped"}, {"state": False}, {"state": "stopped", "reason": "x", "skip": True}]:
            roster = copy.deepcopy(self.roster)
            roster["node_states"]["uc-k8sp4"] = value
            with self.assertRaises(ValueError):
                stopped_hosts(roster)
        self.roster["node_states"]["unknown-host"] = {"state": "stopped", "reason": "test"}
        with self.assertRaises(ValueError):
            stopped_hosts(self.roster)

    def test_no_active_gateways_cannot_pass_e2e(self):
        self.roster["node_states"] = {host: {"state": "stopped", "reason": "test"} for host in self.roster["hosts"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "roster.json"
            path.write_text(json.dumps(self.roster))
            with self.assertRaises(ValueError):
                gateway_ips(path)

    def test_stopped_local_host_cannot_rebuild_a_live_vpn_map(self):
        spec = importlib.util.spec_from_file_location("stopped_boot", Path(__file__).with_name("reconcile-overlay-boot.py"))
        boot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boot)
        peer = next(p for p in self.roster["peers"] if p["vpn_ip"] == "10.250.0.11")
        with self.assertRaisesRegex(RuntimeError, "administratively_stopped"):
            boot.recovery_map({"registered_node": peer}, self.roster, "uc-k8sp4")

    def test_store_rejects_untrusted_identity_before_database_access(self):
        spec = importlib.util.spec_from_file_location("lifecycle_store", Path(__file__).with_name("reconcile-node-lifecycle.py"))
        store = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(store)
        self.roster["hosts"]["uc-k8sp4"] = "node-unsafe'identity"
        with self.assertRaisesRegex(ValueError, "node identity"):
            store.statements(self.roster)

    def test_database_environment_preserves_tls_and_encoded_credentials(self):
        spec = importlib.util.spec_from_file_location("lifecycle_connection", Path(__file__).with_name("reconcile-node-lifecycle.py"))
        store = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(store)
        environment = store.database_environment("postgres://operator:p%40ss%3Aword@db.internal:25432/overlay?sslmode=verify-full&sslrootcert=%2Fprotected%2Fca.crt")
        self.assertEqual(environment["PGSSLMODE"], "verify-full")
        self.assertEqual(environment["PGSSLROOTCERT"], "/protected/ca.crt")
        self.assertEqual(environment["PGPASSWORD"], "p@ss:word")
        self.assertEqual(environment["PGHOST"], "db.internal")

    def test_rendered_placement_follows_stop_and_resume_flag(self):
        root = ROSTER.parents[3]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            module = temporary / "deploy/terraform/master-only"
            module.mkdir(parents=True)
            for name in ["render.py", "nodes.json", "standard-nodes.json", "edge-nodes.json"]:
                shutil.copy2(ROSTER.parent / name, module / name)
            (temporary / "scripts").mkdir()
            shutil.copy2(root / "scripts/node_lifecycle.py", temporary / "scripts/node_lifecycle.py")
            for name in ["control-plane-only", "standard-nodes"]:
                (temporary / "deploy/gitops" / name).mkdir(parents=True)
            (temporary / "deploy/kubernetes").mkdir()
            shutil.copy2(root / "deploy/kubernetes/control-plane-only-policy.yaml", temporary / "deploy/kubernetes/control-plane-only-policy.yaml")
            for state in ["stopped", "active"]:
                self.roster["node_states"]["uc-k8sp4"]["state"] = state
                (module / "overlay-boot-peers.json").write_text(json.dumps(self.roster))
                subprocess.run([sys.executable, str(module / "render.py")], check=True, capture_output=True)
                resources = list(yaml.safe_load_all((temporary / "deploy/gitops/standard-nodes/nodes.yaml").read_text()))
                node = next(r for r in resources if r["apiVersion"] == "v1" and r["metadata"]["name"] == "uc-k8sp4")
                storage = next(r for r in resources if r["apiVersion"].startswith("longhorn.io/") and r["metadata"]["name"] == "uc-k8sp4")
                self.assertEqual(node["spec"]["unschedulable"], state == "stopped")
                self.assertEqual(storage["spec"]["allowScheduling"], state == "active")
