#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import sys
import unittest


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
