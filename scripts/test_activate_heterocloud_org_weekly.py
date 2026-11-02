import unittest

from activate_heterocloud_org_weekly import FLASH_COMPONENTS, verify_flash, verify_policies

DIGEST = "sha256:" + "a" * 64


def fixture():
    items = []
    endpoints = []
    for component in FLASH_COMPONENTS:
        image = "registry/example@" + DIGEST
        name = "heterocloud-flash-" + component
        items.append({"kind": "Deployment", "metadata": {"name": name, "generation": 1},
                      "spec": {"replicas": 2, "template": {"spec": {"containers": [{"image": image}]}}},
                      "status": {"observedGeneration": 1, "updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2}})
        for n in range(2):
            pod = f"{name}-{n}"
            items.append({"kind": "Pod", "metadata": {"name": pod, "labels": {"app.kubernetes.io/name": "heterocloud-flash", "app.kubernetes.io/component": component}},
                          "spec": {"containers": [{"image": image}]}, "status": {"containerStatuses": [{"ready": True, "imageID": image}], "conditions": [{"type": "Ready", "status": "True"}]}})
            if component == "api":
                endpoints.append({"targetRef": {"name": pod}, "conditions": {"ready": True}})
    items.append({"kind": "EndpointSlice", "metadata": {"labels": {"kubernetes.io/service-name": "heterocloud-flash-api"}}, "endpoints": endpoints})
    crd = {"spec": {"versions": [{"storage": True, "schema": {"openAPIV3Schema": {"properties": {"spec": {"properties": {"policy": {"properties": {"cloud_organization": {}}}}}}}}}]}}
    return {"items": items}, crd


class RolloutTests(unittest.TestCase):
    def test_checks_actual_pods_and_service_endpoints(self):
        data, crd = fixture()
        self.assertEqual(verify_flash(data, crd, DIGEST, 2), [])
        pod = next(p for p in data["items"] if p.get("kind") == "Pod" and p["metadata"]["labels"]["app.kubernetes.io/component"] == "api")
        pod["status"]["containerStatuses"][0]["imageID"] = "registry/example@sha256:" + "b" * 64
        self.assertTrue(verify_flash(data, crd, DIGEST, 2))
        data, crd = fixture()
        data["items"][-1]["endpoints"][0]["targetRef"]["name"] = "unknown"
        self.assertTrue(verify_flash(data, crd, DIGEST, 2))
        data, crd = fixture()
        crd["spec"]["versions"][0]["schema"] = {}
        self.assertTrue(verify_flash(data, crd, DIGEST, 2))

    def test_checks_each_service_account_and_limits_after_queue_drains(self):
        limits = {"max_weekly_cpu_millicore_seconds": 100, "max_weekly_memory_mib_seconds": 200, "max_weekly_gpu_seconds": 300}
        snapshot = {"pending": 0, "services": [{"id": "service", "account_id": "a", "accounts": ["a", "b"], "limits": limits}]}
        provider = {"items": [{"spec": {"service_instance_id": "service", "organization_id": "a", "policy": {"cloud_organization": {"account_ids": ["b", "a"], **limits}}}}]}
        self.assertEqual(verify_policies(snapshot, provider, True), [])
        provider["items"][0]["spec"]["policy"]["cloud_organization"]["account_ids"] = ["a"]
        self.assertTrue(verify_policies(snapshot, provider, True))
        self.assertEqual(verify_policies(snapshot, provider, False), [])
        snapshot["pending"] = 1
        self.assertTrue(verify_policies(snapshot, provider, False))
        snapshot["pending"] = 0
        snapshot["services"][0]["accounts"] = None
        self.assertTrue(verify_policies(snapshot, provider, False))


if __name__ == "__main__":
    unittest.main()
