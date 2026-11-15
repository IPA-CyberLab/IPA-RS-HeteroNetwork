#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml


MODULE_PATH = Path(__file__).with_name("overlay-dns-service-discovery.py")
SPEC = importlib.util.spec_from_file_location("overlay_dns_service_discovery", MODULE_PATH)
assert SPEC and SPEC.loader
discovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = discovery
SPEC.loader.exec_module(discovery)


def node(name, vpn_ip, ready=True):
    return {
        "metadata": {
            "name": name,
            "annotations": {discovery.VPN_IP_ANNOTATION: vpn_ip},
        },
        "status": {
            "conditions": [{
                "type": "Ready",
                "status": "True" if ready else "False",
            }]
        },
    }


def service(namespace, name, dns_name=None):
    annotations = {}
    if dns_name:
        annotations[discovery.DNS_ANNOTATION] = dns_name
    return {
        "metadata": {
            "namespace": namespace,
            "name": name,
            "annotations": annotations,
        }
    }


def endpoint_slice(namespace, service_name, endpoints):
    return {
        "metadata": {
            "namespace": namespace,
            "name": service_name + "-slice",
            "labels": {discovery.SERVICE_NAME_LABEL: service_name},
        },
        "endpoints": endpoints,
    }


class OverlayDnsServiceDiscoveryTests(unittest.TestCase):
    def test_controller_can_move_from_a_stopped_node_without_entering_control_plane(self):
        resources = yaml.safe_load_all(Path(__file__).with_name("overlay-dns-service-discovery.yaml").read_text())
        deployment = next(resource for resource in resources if resource and resource.get("kind") == "Deployment")
        self.assertGreaterEqual(deployment["spec"]["replicas"], 2)
        pod = deployment["spec"]["template"]["spec"]
        self.assertEqual(pod["nodeSelector"]["dns.heteronetwork.io/discovery"], "true")
        anti_affinity = pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
        self.assertTrue(any(entry["topologyKey"] == "kubernetes.io/hostname" and
                            entry["labelSelector"]["matchLabels"].get("app.kubernetes.io/component") == "controller"
                            for entry in anti_affinity))
        tolerations = pod.get("tolerations", [])
        self.assertFalse(any(not entry.get("key") for entry in tolerations))
        for key in ("node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"):
            entries = [entry for entry in tolerations if entry.get("key") == key and entry.get("effect") == "NoExecute"]
            self.assertEqual(len(entries), 1)
            self.assertLessEqual(entries[0].get("tolerationSeconds", float("inf")), 30)

    def setUp(self):
        self.base = {
            "schema_version": 1,
            "records": {
                "argocd.heteronetwork.internal": ["10.250.0.4"],
                # A previous static value must not survive discovery.
                "grafana.heteronetwork.internal": ["10.250.0.5"],
            },
            "gateway_records": {
                "grafana.heteronetwork.internal": {
                    "10.250.0.5": ["10.250.0.5"]
                }
            },
        }
        self.rules = [{
            "dns_name": "grafana.heteronetwork.internal",
            "namespace": "monitoring",
            "service_name": "grafana",
        }]
        self.nodes = [
            node("node-a", "10.250.0.2"),
            node("node-b", "10.250.0.10"),
            node("node-c", "10.250.0.11"),
        ]

    def test_ready_endpoints_replace_static_addresses_and_prefer_local_gateway(self):
        slices = [endpoint_slice("monitoring", "grafana", [
            {"nodeName": "node-b", "conditions": {"ready": True}},
            {"nodeName": "node-a", "conditions": {"ready": True}},
        ])]
        effective, status = discovery.build_effective_zone(
            self.base,
            [service("monitoring", "grafana")],
            slices,
            self.nodes,
            self.rules,
        )
        self.assertEqual(
            effective["records"]["grafana.heteronetwork.internal"],
            ["10.250.0.2", "10.250.0.10"],
        )
        self.assertEqual(
            effective["gateway_records"]["grafana.heteronetwork.internal"]["10.250.0.10"],
            ["10.250.0.10", "10.250.0.2"],
        )
        self.assertEqual(len(status["services"]), 1)
        self.assertIn("argocd.heteronetwork.internal", effective["records"])

    def test_openbao_name_tracks_ready_private_gateway_endpoints(self):
        rule = [{
            "dns_name": "secrets.heteronetwork.internal",
            "namespace": "envoy-gateway-system",
            "service_name": "openbao-vpn-proxy",
        }]
        service_object = service("envoy-gateway-system", "openbao-vpn-proxy")
        slices = [endpoint_slice("envoy-gateway-system", "openbao-vpn-proxy", [
            {"nodeName": "node-b", "conditions": {"ready": True}},
            {"nodeName": "node-c", "conditions": {"ready": True}},
        ])]
        effective, _ = discovery.build_effective_zone(
            self.base, [service_object], slices, self.nodes, rule
        )
        self.assertEqual(
            effective["records"]["secrets.heteronetwork.internal"],
            ["10.250.0.10", "10.250.0.11"],
        )
        effective, _ = discovery.build_effective_zone(
            self.base, [service_object], [], self.nodes, rule
        )
        self.assertNotIn("secrets.heteronetwork.internal", effective["records"])

    def test_administratively_stopped_ready_node_is_not_discovered(self):
        stopped = node("node-stopped", "10.250.0.11")
        stopped["metadata"]["labels"] = {"heteronetwork.io/lifecycle": "stopped"}
        self.assertFalse(discovery.node_is_ready(stopped))

    def test_dns_upstreams_follow_ready_nodes_and_overlay_addresses(self):
        unannotated = node("node-with-internal-ip", "10.250.0.4")
        unannotated["metadata"]["annotations"] = {}
        unannotated["status"]["addresses"] = [
            {"type": "InternalIP", "address": "192.0.2.1"},
            {"type": "InternalIP", "address": "10.250.0.4"},
        ]
        stopped = node("node-stopped", "10.250.0.8")
        stopped["metadata"]["labels"] = {"heteronetwork.io/lifecycle": "stopped"}
        nodes = [self.nodes[0], unannotated, stopped,
                 node("unready", "10.250.0.5", ready=False),
                 node("other-network", "192.0.2.2")]
        self.assertEqual(discovery.ready_overlay_dns_upstreams(nodes, "10.250.0.0/16"),
                         ["10.250.0.2", "10.250.0.4"])
        with self.assertRaises(ValueError):
            discovery.ready_overlay_dns_upstreams(nodes, "not-a-cidr")

    def test_dns_upstream_selection_is_bounded_and_stable_at_1000_nodes(self):
        nodes = [node(f"node-{index}", f"10.250.{index // 250}.{index % 250 + 1}")
                 for index in range(1000)]
        selected = discovery.ready_overlay_dns_upstreams(nodes, "10.250.0.0/16")
        self.assertEqual(len(selected), 15)
        self.assertEqual(selected, discovery.ready_overlay_dns_upstreams(list(reversed(nodes)), "10.250.0.0/16"))
        after = discovery.ready_overlay_dns_upstreams(
            [item for item in nodes if item["metadata"]["annotations"][discovery.VPN_IP_ANNOTATION] != selected[0]],
            "10.250.0.0/16",
        )
        self.assertEqual(len(after), 15)
        self.assertEqual(len(set(selected) & set(after)), 14)

    def test_controller_updates_forwarders_and_preserves_them_when_none_are_ready(self):
        class FakeApi:
            def __init__(self, nodes):
                self.nodes = nodes
                self.data = {}
            def config_map(self, namespace, name):
                if namespace == "heteronetwork-system":
                    return {"data": {"records.json": json.dumps({"schema_version": 1, "records": {}})}}
                return {"data": self.data}
            def list_items(self, path):
                return self.nodes if path == "/api/v1/nodes" else []
            def patch_config_map_data(self, namespace, name, data):
                self.data.update(data)

        api = FakeApi(self.nodes[:2])
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(discovery.os.environ, {"OVERLAY_VPN_CIDR": "10.250.0.0/16"}), \
             patch.object(Path, "touch"):
            rules = Path(directory) / "rules.json"
            rules.write_text('{"services": []}')
            changed, status = discovery.controller_once(api, rules)
            self.assertTrue(changed)
            self.assertEqual(status["upstreams"]["addresses"], ["10.250.0.2", "10.250.0.10"])
            self.assertIn("10.250.0.10", api.data["forward.conf"])
            api.nodes = [self.nodes[0]]
            discovery.controller_once(api, rules)
            self.assertNotIn("10.250.0.10", api.data["forward.conf"])
            previous = api.data["forward.conf"]
            api.nodes = []
            _, status = discovery.controller_once(api, rules)
            self.assertEqual(status["upstreams"]["state"], "no_ready_nodes")
            self.assertEqual(api.data["forward.conf"], previous)

    def test_missing_service_removes_managed_record(self):
        effective, status = discovery.build_effective_zone(
            self.base, [], [], self.nodes, self.rules
        )
        self.assertNotIn("grafana.heteronetwork.internal", effective["records"])
        self.assertNotIn("grafana.heteronetwork.internal", effective["gateway_records"])
        self.assertEqual(status["services"], [])

    def test_annotation_adds_and_removing_annotation_removes_record(self):
        name = "logs.heteronetwork.internal"
        slices = [endpoint_slice("tools", "logs", [
            {"nodeName": "node-c", "conditions": {"ready": True}}
        ])]
        effective, _ = discovery.build_effective_zone(
            self.base,
            [service("tools", "logs", name)],
            slices,
            self.nodes,
            self.rules,
        )
        self.assertEqual(effective["records"][name], ["10.250.0.11"])

        effective, _ = discovery.build_effective_zone(
            self.base,
            [service("tools", "logs")],
            slices,
            self.nodes,
            self.rules,
        )
        self.assertNotIn(name, effective["records"])

    def test_unready_terminating_and_unready_node_endpoints_are_removed(self):
        slices = [endpoint_slice("monitoring", "grafana", [
            {"nodeName": "node-a", "conditions": {"ready": False}},
            {"nodeName": "node-b", "conditions": {"ready": True, "terminating": True}},
            {"nodeName": "node-c", "conditions": {"ready": True}},
        ])]
        nodes = self.nodes[:2] + [node("node-c", "10.250.0.11", ready=False)]
        effective, status = discovery.build_effective_zone(
            self.base,
            [service("monitoring", "grafana")],
            slices,
            nodes,
            self.rules,
        )
        self.assertNotIn("grafana.heteronetwork.internal", effective["records"])
        self.assertEqual(status["services"], [])

    def test_conflicting_registration_is_rejected(self):
        services = [
            service("tools", "one", "logs.heteronetwork.internal"),
            service("tools", "two", "logs.heteronetwork.internal"),
        ]
        with self.assertRaisesRegex(ValueError, "assigned to both"):
            discovery.build_effective_zone(self.base, services, [], self.nodes, self.rules)


if __name__ == "__main__":
    unittest.main()
