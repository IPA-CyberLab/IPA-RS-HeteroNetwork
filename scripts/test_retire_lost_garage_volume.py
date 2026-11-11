import copy
import unittest

from retire_lost_garage_volume import validate_claim


class LostGarageVolumeTests(unittest.TestCase):
    def setUp(self):
        self.pvc = {"metadata": {"name": "data-garage-2", "namespace": "storage", "uid": "claim-uid"},
                    "spec": {"volumeName": "volume-a"}}
        self.pv = {"metadata": {"name": "volume-a", "uid": "pv-uid"}, "spec": {
            "claimRef": {"name": "data-garage-2", "namespace": "storage", "uid": "claim-uid"},
            "persistentVolumeReclaimPolicy": "Retain",
            "csi": {"driver": "driver.longhorn.io", "volumeHandle": "volume-a"},
            "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                {"key": "kubernetes.io/hostname", "operator": "In", "values": ["lost"]}]}]}}}}
        self.volume = {"metadata": {"name": "volume-a"},
                       "status": {"state": "detached", "robustness": "faulted"}}

    def validate(self):
        return validate_claim(self.pvc, self.pv, self.volume, "storage", "data-garage-2", "lost")

    def test_only_exact_faulted_retained_claim_is_selected(self):
        self.assertEqual(self.validate()["uid"], "claim-uid")

    def test_refuses_healthy_volume_wrong_node_or_recreated_claim(self):
        cases = [
            (self.volume["status"], "robustness", "healthy"),
            (self.volume["status"], "state", "attached"),
            (self.pv["spec"], "persistentVolumeReclaimPolicy", "Delete"),
            (self.pv["spec"]["claimRef"], "uid", "new-claim"),
            (self.pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]
             ["matchExpressions"][0], "values", ["healthy"]),
        ]
        for obj, key, value in cases:
            old = copy.deepcopy(obj[key])
            obj[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validate()
            obj[key] = old


if __name__ == "__main__":
    unittest.main()
