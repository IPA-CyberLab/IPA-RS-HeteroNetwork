import copy
import datetime
import unittest
from unittest.mock import patch

import retire_node_kubernetes as retirement
from retire_node_kubernetes import verify_objects


class KubernetesRetirementTests(unittest.TestCase):
    def setUp(self):
        timestamp = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).isoformat()
        self.identity = {"hostname": "lost", "vpn_ip": "192.0.2.1", "kubernetes_uid": "uid-old"}
        self.node = {"metadata": {"name": "lost", "uid": "uid-old", "labels": {"heteronetwork.io/lifecycle": "stopped"}},
                     "spec": {"unschedulable": True}, "status": {"addresses": [{"type": "InternalIP", "address": "192.0.2.1"}],
                     "conditions": [{"type": "Ready", "status": "Unknown", "lastTransitionTime": timestamp}]}}

    def test_exact_inactive_node_without_storage_is_accepted(self):
        verify_objects(self.node, self.identity, [], [])

    def test_offline_retirement_can_cordon_later_but_never_accepts_a_ready_node(self):
        node = copy.deepcopy(self.node)
        node["spec"]["unschedulable"] = False
        node["metadata"]["labels"] = {}
        verify_objects(node, self.identity, [], [], offline_retirement=True)
        self.assertFalse(node["spec"]["unschedulable"])
        node["status"]["conditions"][0]["status"] = "True"
        with self.assertRaises(ValueError):
            verify_objects(node, self.identity, [], [], offline_retirement=True)

    def test_recreated_or_active_node_and_storage_are_rejected(self):
        mutations = []
        node = copy.deepcopy(self.node); node["metadata"]["uid"] = "new-uid"; mutations.append((node, [], []))
        node = copy.deepcopy(self.node); node["status"]["conditions"][0]["status"] = "True"; mutations.append((node, [], []))
        node = copy.deepcopy(self.node); node["status"]["addresses"][0]["address"] = "192.0.2.2"; mutations.append((node, [], []))
        mutations.append((self.node, [{"spec": {"nodeID": "lost"}}], []))
        mutations.append((self.node, [], [{"spec": {"nodeName": "lost"}}]))
        for node, replicas, attachments in mutations:
            with self.subTest(node=node, replicas=replicas, attachments=attachments), self.assertRaises(ValueError):
                verify_objects(node, self.identity, replicas, attachments)

    def test_offline_voter_is_planned_only_with_three_healthy_survivors(self):
        node = copy.deepcopy(self.node)
        node["metadata"]["labels"] = {}
        node["spec"]["unschedulable"] = False
        voters = [{"name": "lost", "ID": 1, "peerURLs": ["https://192.0.2.1:2380"],
                   "clientURLs": ["https://192.0.2.1:2379"]}]
        voters += [{"name": "survivor-" + str(i), "ID": i,
                    "peerURLs": [f"https://192.0.2.{i}:2380"],
                    "clientURLs": [f"https://192.0.2.{i}:2379"]} for i in range(2, 5)]
        class Kube:
            binary = "kubectl"
            def get(self, resource, *args):
                return {"items": [node] if resource == "nodes" else []}
        with patch.object(retirement.ETCD, "Cluster") as cluster:
            cluster.return_value.members.return_value = {"members": voters}
            result = retirement.kubernetes_preflight(Kube(), "config", "executor", self.identity,
                                                       offline_retirement=True)
            self.assertEqual(result["etcd_member"]["member_id"], "1")
            cluster.return_value.healthy.assert_called_once()
            node["status"]["conditions"][0]["status"] = "True"
            with self.assertRaises(ValueError):
                retirement.kubernetes_preflight(Kube(), "config", "executor", self.identity,
                                                 offline_retirement=True)


if __name__ == "__main__":
    unittest.main()
