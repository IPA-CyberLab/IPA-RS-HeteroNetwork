"""Offline renderer/Cluster/NetworkPolicy contracts; requires PyYAML, never kubectl."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

import yaml

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("operator_renderer", HERE / "render-operator.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


def load(name):
    return list(yaml.safe_load_all((HERE / name).read_text()))


def namespace_peer(namespace, labels):
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
            "podSelector": {"matchLabels": labels}}


def allowed_ports(policy, direction, peer):
    field = "from" if direction == "ingress" else "to"
    return {port["port"] for rule in policy["spec"][direction] if peer in rule.get(field, [])
            for port in rule.get("ports", []) if port.get("protocol", "TCP") == "TCP"}


class OperatorTests(unittest.TestCase):
    def fixture(self):
        lock = json.loads((HERE / "operator-lock.json").read_text())
        labels = {"app.kubernetes.io/name": "cloudnative-pg"}
        documents = [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnpg-system"}},
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {
                "labels": labels, "name": "cnpg-controller-manager", "namespace": "cnpg-system"},
             "spec": {"selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels},
                "spec": {"containers": [{"name": "manager", "args": ["controller", "--leader-elect"],
                    "image": "ghcr.io/cloudnative-pg/cloudnative-pg:" + lock["version"],
                    "env": [{"name": "OPERATOR_IMAGE_NAME", "value": "fixture-tag"}],
                    "securityContext": {"allowPrivilegeEscalation": False},
                    "readinessProbe": {"httpGet": {"port": 9443, "path": "/readyz", "scheme": "HTTPS"}}}],
                    "serviceAccountName": "cnpg-manager"}}}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "fixture-webhook"},
             "spec": {"ports": [{"port": 443, "targetPort": 9443}]}}]
        raw = yaml.safe_dump_all(documents).encode()
        return documents, raw, {**lock, "upstream_sha256": hashlib.sha256(raw).hexdigest()}

    def test_renderer_digest_and_topology_image_binding(self):
        original, raw, lock = self.fixture()
        output = renderer.render(raw, lock)
        deployment = next(d for d in output["items"] if d["kind"] == "Deployment")
        spec = deployment["spec"]
        pod = spec["template"]["spec"]
        self.assertEqual(spec["replicas"], 3)
        self.assertEqual(spec["strategy"]["rollingUpdate"], {"maxUnavailable": 1, "maxSurge": 0})
        self.assertIn("--leader-elect", pod["containers"][0]["args"])
        self.assertEqual(pod["containers"][0]["image"], lock["image"])
        self.assertEqual(pod["containers"][0]["env"][0]["value"], lock["image"])
        self.assertEqual(pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                         ["nodeSelectorTerms"][0]["matchExpressions"][0]["values"],
                         ["hetero-dev-1", "hetero-dev-2", "hetero-dev-3"])
        self.assertEqual(pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
                         ["labelSelector"], spec["selector"])
        self.assertEqual(pod["containers"][0]["readinessProbe"],
                         original[1]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"])
        self.assertEqual(output["items"][2], original[2])
        self.assertEqual(output["items"][-1]["spec"]["minAvailable"], 2)

    def test_renderer_rejects_untrusted_bytes_and_changed_operator(self):
        documents, raw, lock = self.fixture()
        with self.assertRaises(ValueError):
            renderer.render(raw + b"\n", lock)
        for mode in ("leader", "image", "duplicate"):
            bad = copy.deepcopy(documents)
            container = bad[1]["spec"]["template"]["spec"]["containers"][0]
            if mode == "leader":
                container["args"].remove("--leader-elect")
            elif mode == "image":
                container["image"] = "untrusted:latest"
            else:
                bad.append(copy.deepcopy(bad[1]))
            payload = yaml.safe_dump_all(bad).encode()
            with self.assertRaises(ValueError):
                renderer.render(payload, {**lock, "upstream_sha256": hashlib.sha256(payload).hexdigest()})

    def test_cluster_fresh_bootstrap_security_and_reserved_storage(self):
        cluster, = load("postgres.yaml")
        spec = cluster["spec"]
        self.assertEqual(cluster["metadata"], {"name": "dev-identity-postgres", "namespace": "hetero-dev-identity"})
        self.assertEqual(spec["instances"], 3)
        self.assertRegex(spec["imageName"], r"^ghcr.io/cloudnative-pg/postgresql:18\.6-standard-trixie@sha256:[0-9a-f]{64}$")
        self.assertFalse(spec["enableSuperuserAccess"])
        self.assertEqual(spec["bootstrap"], {"initdb": {"database": "keycloak", "owner": "keycloak", "dataChecksums": True}})
        self.assertEqual((spec["postgresUID"], spec["postgresGID"]), (26, 26))
        for field in ("runAsUser", "runAsGroup", "fsGroup"):
            self.assertEqual(spec["podSecurityContext"][field], 26)
        storage = spec["storage"]
        self.assertEqual(storage["storageClass"], "dev-identity-local")
        self.assertEqual(storage["size"], "8Gi")
        pv_list = json.loads((HERE / "storage.yaml").read_text())["items"]
        for pv in (p for p in pv_list if p["kind"] == "PersistentVolume"):
            for key, value in storage["pvcTemplate"]["selector"]["matchLabels"].items():
                self.assertEqual(pv["metadata"]["labels"][key], value)

    def test_operator_to_instances_required_ports_in_both_directions(self):
        database, operator = load("network-policy.yaml")
        op_peer = namespace_peer("cnpg-system", {"app.kubernetes.io/name": "cloudnative-pg"})
        db_peer = namespace_peer("hetero-dev-identity", {"cnpg.io/cluster": "dev-identity-postgres"})
        self.assertTrue({8000, 5432} <= allowed_ports(database, "ingress", op_peer), "operator ingress needs 8000 and 5432")
        self.assertTrue({8000, 5432} <= allowed_ports(operator, "egress", db_peer), "operator egress needs 8000 and 5432")

    def test_replication_application_and_dns_paths(self):
        database, operator = load("network-policy.yaml")
        peer = {"podSelector": {"matchLabels": {"cnpg.io/cluster": "dev-identity-postgres"}}}
        for direction in ("ingress", "egress"):
            self.assertIn(5432, allowed_ports(database, direction, peer))
        self.assertIn(5432, allowed_ports(database, "ingress", {"podSelector": {
            "matchLabels": {"app.kubernetes.io/name": "keycloak"}}}))
        dns = namespace_peer("kube-system", {"k8s-app": "kube-dns"})
        for policy in (database, operator):
            self.assertIn(53, allowed_ports(policy, "egress", dns))
            self.assertTrue(any(dns in rule.get("to", []) and {"protocol": "UDP", "port": 53} in rule["ports"]
                                for rule in policy["spec"]["egress"]))

    def test_api_webhook_paths_and_no_world_allow(self):
        database, operator = load("network-policy.yaml")
        for policy in (database, operator):
            self.assertEqual(policy["spec"]["policyTypes"], ["Ingress", "Egress"])
            for ip in ("10.251.0.1/32", "10.251.0.2/32", "10.251.0.3/32"):
                self.assertIn(6443, allowed_ports(policy, "egress", {"ipBlock": {"cidr": ip}}))
            self.assertIn(443, allowed_ports(policy, "egress", {"ipBlock": {"cidr": "172.30.0.1/32"}}))
            self.assertNotIn("0.0.0.0/0", json.dumps(policy))
        for ip in ("10.251.0.1/32", "10.251.0.2/32", "10.251.0.3/32"):
            self.assertIn(9443, allowed_ports(operator, "ingress", {"ipBlock": {"cidr": ip}}))


if __name__ == "__main__":
    unittest.main()
