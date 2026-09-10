"""Offline contract checks; storage.yaml uses the JSON subset of YAML."""
import json
from pathlib import Path
import unittest


class StorageTests(unittest.TestCase):
    def setUp(self):
        manifest = json.loads(Path(__file__).with_name("storage.yaml").read_text())
        self.assertEqual((manifest["apiVersion"], manifest["kind"]), ("v1", "List"))
        self.items = manifest["items"]
        self.pvs = [item for item in self.items if item["kind"] == "PersistentVolume"]

    def test_only_namespace_storageclass_and_three_pvs(self):
        self.assertEqual([item["kind"] for item in self.items],
                         ["Namespace", "StorageClass"] + ["PersistentVolume"] * 3)
        self.assertEqual(self.items[0]["metadata"]["name"], "hetero-dev-identity")
        self.assertEqual(len({item["metadata"]["name"] for item in self.items}), 5)

    def test_class_is_static_delayed_retained_and_not_default(self):
        sc = self.items[1]
        self.assertEqual(sc["metadata"]["name"], "dev-identity-local")
        self.assertEqual(sc["provisioner"], "kubernetes.io/no-provisioner")
        self.assertEqual(sc["volumeBindingMode"], "WaitForFirstConsumer")
        self.assertEqual(sc["reclaimPolicy"], "Retain")
        self.assertFalse(sc["allowVolumeExpansion"])
        self.assertEqual(sc["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"], "false")

    def test_exact_per_node_affinity_and_fresh_path(self):
        for i, pv in enumerate(self.pvs, 1):
            spec = pv["spec"]
            self.assertEqual(spec["nodeAffinity"], {"required": {"nodeSelectorTerms": [
                {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In",
                                       "values": [f"hetero-dev-{i}"]}]}]}})
            self.assertEqual(spec["local"], {"path": "/var/lib/heteronetwork-dev-storage/identity-postgres"})
            self.assertNotIn("hostPath", spec)
            self.assertEqual(spec["capacity"], {"storage": "8Gi"})
            self.assertEqual(spec["volumeMode"], "Filesystem")
            self.assertEqual(spec["accessModes"], ["ReadWriteOnce"])
            self.assertEqual(spec["persistentVolumeReclaimPolicy"], "Retain")

    def test_claim_reservations_labels_and_cluster_annotation(self):
        for i, pv in enumerate(self.pvs, 1):
            self.assertEqual(pv["spec"]["storageClassName"], "dev-identity-local")
            self.assertEqual(pv["spec"]["claimRef"], {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "namespace": "hetero-dev-identity", "name": f"dev-identity-postgres-{i}"})
            self.assertEqual(pv["metadata"]["labels"]["heteronetwork.dev/storage-purpose"], "identity-postgres")
            self.assertEqual(pv["metadata"]["annotations"]["heteronetwork.dev/kube-system-uid"],
                             "a39281cb-d273-4c5f-b7a7-fca722fb417b")


if __name__ == "__main__":
    unittest.main()
