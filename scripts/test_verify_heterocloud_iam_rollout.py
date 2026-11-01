import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "verify_heterocloud_iam_rollout", Path(__file__).with_name("verify-heterocloud-iam-rollout.py")
)
verify_rollout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_rollout)
DIGEST = "sha256:" + "a" * 64


def fixture():
    items = []
    for component, (deployment, container) in verify_rollout.COMPONENTS.items():
        image = "example.test/heterocloud@" + DIGEST
        items.append({"kind": "Deployment", "metadata": {"name": deployment},
                      "spec": {"replicas": 2, "template": {"spec": {"containers": [{"name": container, "image": image}]}}},
                      "status": {**dict.fromkeys(("replicas", "updatedReplicas", "readyReplicas", "availableReplicas"), 2), "observedGeneration": 1}})
        for index in range(2):
            name = f"{component}-{index}"
            items.append({"kind": "Pod", "metadata": {"name": name, "labels": {
                "app.kubernetes.io/instance": "heterocloud", "app.kubernetes.io/component": component}},
                "spec": {"containers": [{"name": container, "image": image}]},
                "status": {"conditions": [{"type": "Ready", "status": "True"}],
                           "containerStatuses": [{"name": container, "ready": True, "imageID": image}]}})
    for service, component in verify_rollout.SERVICES.items():
        items.append({"kind": "EndpointSlice", "metadata": {"labels": {"kubernetes.io/service-name": service}},
                      "endpoints": [{"conditions": {"ready": True}, "targetRef": {"name": f"{component}-{index}"}}
                                    for index in range(2)]})
    return {"items": items}


class VerifyRolloutTest(unittest.TestCase):
    def test_fully_ready_fleet_passes(self):
        self.assertEqual(verify_rollout.verify(fixture(), DIGEST, 2), [])

    def test_stale_image_is_rejected_even_when_ready(self):
        data = fixture()
        pod = next(item for item in data["items"] if item.get("kind") == "Pod")
        pod["status"]["containerStatuses"][0]["imageID"] = "example.test/old@sha256:" + "b" * 64
        self.assertTrue(verify_rollout.verify(data, DIGEST, 2))

    def test_old_serving_endpoint_is_rejected(self):
        data = fixture()
        endpoint_slice = next(item for item in data["items"] if item.get("kind") == "EndpointSlice")
        endpoint_slice["endpoints"][0]["targetRef"]["name"] = "old-terminating-pod"
        self.assertTrue(verify_rollout.verify(data, DIGEST, 2))

    def test_missing_or_unready_replicas_are_rejected(self):
        data = fixture()
        pod = next(item for item in data["items"] if item.get("kind") == "Pod")
        pod["status"]["conditions"][0]["status"] = "False"
        self.assertTrue(verify_rollout.verify(data, DIGEST, 2))
        self.assertTrue(verify_rollout.verify({"items": []}, DIGEST, 2))

    def test_unobserved_deployment_generation_is_rejected(self):
        data = fixture()
        deployment = next(item for item in data["items"] if item.get("kind") == "Deployment")
        deployment["metadata"]["generation"] = 2
        self.assertTrue(verify_rollout.verify(data, DIGEST, 2))

    def test_invalid_digest_and_count_are_rejected(self):
        with self.assertRaises(ValueError):
            verify_rollout.verify(fixture(), "latest", 2)
        with self.assertRaises(ValueError):
            verify_rollout.verify(fixture(), DIGEST, 0)


if __name__ == "__main__":
    unittest.main()
