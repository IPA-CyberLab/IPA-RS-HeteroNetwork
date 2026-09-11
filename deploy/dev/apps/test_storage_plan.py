import unittest

import storage_plan


class StoragePlanTests(unittest.TestCase):
    def test_claim_reservations_and_capacity(self):
        plan = storage_plan.manifest()
        volumes = plan["items"][1:]
        self.assertEqual(len(volumes), 18)
        self.assertEqual(len({v["metadata"]["name"] for v in volumes}), 18)
        self.assertEqual(len({(v["spec"]["claimRef"]["namespace"], v["spec"]["claimRef"]["name"])
                              for v in volumes}), 18)
        totals = {}
        paths = set()
        for v in volumes:
            spec = v["spec"]
            self.assertEqual(spec["persistentVolumeReclaimPolicy"], "Retain")
            self.assertEqual(spec["storageClassName"], storage_plan.CLASS)
            node = spec["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"][0]
            totals[node] = totals.get(node, 0) + int(spec["capacity"]["storage"][:-2])
            self.assertTrue(spec["local"]["path"].startswith(storage_plan.MOUNT + "/"))
            paths.add((node, spec["local"]["path"]))
            self.assertNotIn("identity", str(v))
        self.assertEqual(len(paths), 18)
        self.assertEqual(totals, {"hetero-dev-1": 35, "hetero-dev-2": 35, "hetero-dev-3": 35})
        self.assertEqual(plan, storage_plan.manifest())
        self.assertEqual(plan["items"][0]["volumeBindingMode"], "WaitForFirstConsumer")
        self.assertEqual(plan["items"][0]["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"], "false")


if __name__ == "__main__":
    unittest.main()
