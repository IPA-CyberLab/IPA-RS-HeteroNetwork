import copy
import datetime
import unittest

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


if __name__ == "__main__":
    unittest.main()
