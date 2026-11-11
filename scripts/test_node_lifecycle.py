import copy
import json
from pathlib import Path
import tempfile
import unittest

from node_test_fixtures import roster_with_stopped_node
import importlib.util
import shutil
import subprocess
import sys
import yaml

from node_lifecycle import ROSTER, active_peers, gateway_ips, stopped_hosts


class NodeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.roster = roster_with_stopped_node()

    def test_stopped_host_is_excluded_until_operator_resumes_it(self):
        self.assertEqual(stopped_hosts(self.roster), {"fixture-stopped"})
        self.assertNotIn("10.250.0.250", {p["vpn_ip"] for p in active_peers(self.roster)})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "roster.json"
            path.write_text(json.dumps(self.roster))
            self.assertNotIn("10.250.0.250", gateway_ips(path).split(","))
        self.roster["node_states"]["fixture-stopped"] = {"state": "active"}
        self.assertIn("10.250.0.250", {p["vpn_ip"] for p in active_peers(self.roster)})

    def test_bad_flags_fail_instead_of_skipping_health_checks(self):
        for value in [{"state": "stoped"}, {"state": "stopped"}, {"state": False}, {"state": "stopped", "reason": "x", "skip": True}]:
            roster = copy.deepcopy(self.roster)
            roster["node_states"]["fixture-stopped"] = value
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

    def test_cluster_dns_daemonsets_exclude_declared_stopped_hosts(self):
        directory = ROSTER.parents[3] / "deploy/gitops/cluster-dns"
        for name in ("nodelocaldns.yaml", "postgres-ha-connector.yaml", "keycloak-ha-connector.yaml", "service-route.yaml"):
            with self.subTest(name=name):
                resources = list(yaml.safe_load_all((directory / name).read_text()))
                daemon = next(item for item in resources if item and item.get("kind") == "DaemonSet")
                affinity = daemon["spec"]["template"]["spec"]["affinity"]["nodeAffinity"]
                terms = affinity["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
                self.assertTrue(terms)
                for term in terms:
                    self.assertIn({"key": "heteronetwork.io/lifecycle", "operator": "NotIn", "values": ["stopped"]},
                                  term["matchExpressions"])
                if name == "postgres-ha-connector.yaml":
                    pdb = next(item for item in resources if item and item.get("kind") == "PodDisruptionBudget")
                    self.assertEqual(pdb["spec"]["minAvailable"], 2)

    def test_stopped_local_host_cannot_rebuild_a_live_vpn_map(self):
        spec = importlib.util.spec_from_file_location("stopped_boot", Path(__file__).with_name("reconcile-overlay-boot.py"))
        boot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boot)
        peer = next(p for p in self.roster["peers"] if p["vpn_ip"] == "10.250.0.250")
        with self.assertRaisesRegex(RuntimeError, "administratively_stopped"):
            boot.recovery_map({"registered_node": peer}, self.roster, "fixture-stopped")

    def test_store_rejects_untrusted_identity_before_database_access(self):
        spec = importlib.util.spec_from_file_location("lifecycle_store", Path(__file__).with_name("reconcile-node-lifecycle.py"))
        store = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(store)
        self.roster["hosts"]["fixture-stopped"] = "node-unsafe'identity"
        with self.assertRaisesRegex(ValueError, "node identity"):
            store.statements(self.roster)

    def test_scoped_infrastructure_bundle_contains_stopped_node_fencing(self):
        spec = importlib.util.spec_from_file_location("publish_iac", Path(__file__).with_name("publish-master-only.py"))
        publisher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(publisher)
        expected = {"scripts/reconcile-stopped-wireguard.py", "scripts/reconcile-stopped-overlay-firewall.py",
                    "scripts/verify-heterocloud-iam-rollout.py", "scripts/reconcile-etcd-retirements.py",
                    "scripts/test_reconcile_etcd_retirements.py", "scripts/encrypted-etcd-snapshot.py",
                    "scripts/test_encrypted_etcd_snapshot.py", "scripts/reconcile-github-dr-environment.py",
                    "scripts/test_reconcile_github_dr_environment.py"}
        self.assertTrue(expected.issubset(set(publisher.files())))

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
            standard = json.loads((module / "standard-nodes.json").read_text())
            standard = {name: value for name, value in standard.items() if name in self.roster["hosts"]}
            standard["fixture-stopped"] = {"vpn_ip": "10.250.0.250"}
            (module / "standard-nodes.json").write_text(json.dumps(standard))
            (temporary / "scripts").mkdir()
            shutil.copy2(root / "scripts/node_lifecycle.py", temporary / "scripts/node_lifecycle.py")
            for name in ["control-plane-only", "standard-nodes"]:
                (temporary / "deploy/gitops" / name).mkdir(parents=True)
            (temporary / "deploy/kubernetes").mkdir()
            shutil.copy2(root / "deploy/kubernetes/control-plane-only-policy.yaml", temporary / "deploy/kubernetes/control-plane-only-policy.yaml")
            for state in ["stopped", "active"]:
                self.roster["node_states"]["fixture-stopped"]["state"] = state
                (module / "overlay-boot-peers.json").write_text(json.dumps(self.roster))
                subprocess.run([sys.executable, str(module / "render.py")], check=True, capture_output=True)
                resources = list(yaml.safe_load_all((temporary / "deploy/gitops/standard-nodes/nodes.yaml").read_text()))
                node = next(r for r in resources if r["apiVersion"] == "v1" and r["metadata"]["name"] == "fixture-stopped")
                storage = next(r for r in resources if r["apiVersion"].startswith("longhorn.io/") and r["metadata"]["name"] == "fixture-stopped")
                self.assertEqual(node["spec"]["unschedulable"], state == "stopped")
                self.assertEqual(node["metadata"]["labels"]["heteronetwork.io/lifecycle"], state)
                self.assertEqual(storage["spec"]["allowScheduling"], state == "active")
                if state == "stopped":
                    self.assertEqual(node["metadata"]["labels"]["networking.heteronetwork.io/turn-ingress"], "false")
                    self.assertEqual(node["metadata"]["labels"]["dns.heteronetwork.io/discovery"], "false")
                for name in ("uc-k8sp5", "ichikawap1"):
                    worker = next(r for r in resources if r["apiVersion"] == "v1" and r["metadata"]["name"] == name)
                    self.assertEqual(worker["metadata"]["labels"]["networking.heteronetwork.io/turn-ingress"], "true")
                    self.assertEqual(worker["metadata"]["labels"]["dns.heteronetwork.io/discovery"], "true")

    def test_empty_lifecycle_declaration_needs_no_database_change(self):
        spec = importlib.util.spec_from_file_location("lifecycle_store_empty", Path(__file__).with_name("reconcile-node-lifecycle.py"))
        store = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(store)
        self.roster["node_states"] = {}
        self.assertEqual(store.statements(self.roster), "")
