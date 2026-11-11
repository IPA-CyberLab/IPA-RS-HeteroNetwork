import unittest

from prune_node_declarations import prune, removed_addresses, replacement_hostnames


class NodeDeclarationTests(unittest.TestCase):
    def test_exact_node_and_network_references_are_removed(self):
        identity = {"hostname": "lost", "vpn_ip": "10.250.0.11"}
        removed = removed_addresses(identity, "10.244.5.0/24")
        value = {"hosts": ["lost", "survivor"], "ips": ["10.250.0.11/32", "10.250.0.110/32"],
                 "rules": [{"ipBlock": {"cidr": "10.244.5.0/32"}}, {"ipBlock": {"cidr": "10.244.6.0/32"}}],
                 "gateways": {"10.250.0.11": ["10.250.0.11"], "10.250.0.2": ["10.250.0.2", "10.250.0.11"]}}
        result = prune(value, removed)
        self.assertEqual(result["hosts"], ["survivor"])
        self.assertEqual(result["ips"], ["10.250.0.110/32"])
        self.assertEqual(result["rules"], [{"ipBlock": {"cidr": "10.244.6.0/32"}}])
        self.assertEqual(result["gateways"], {"10.250.0.2": ["10.250.0.2"]})

    def test_custom_domain_placement_requires_two_survivors(self):
        expr = {"key": "kubernetes.io/hostname", "operator": "In", "values": ["lost", "worker-a"]}
        doc = [{"kind": "Deployment", "spec": {"template": {"spec": {"affinity": {"nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [expr]}]}}}}}}}]
        replacement_hostnames(doc, "lost", ["worker-a", "worker-b"])
        self.assertEqual(expr["values"], ["worker-a", "worker-b"])
        expr["values"] = ["lost", "worker-a"]
        with self.assertRaisesRegex(ValueError, "two surviving"):
            replacement_hostnames(doc, "lost", ["worker-a"])


if __name__ == "__main__":
    unittest.main()
