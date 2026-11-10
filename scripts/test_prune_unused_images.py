import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("image_cleanup", Path(__file__).with_name("prune-unused-images.py"))
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class ImageCleanupTest(unittest.TestCase):
    def test_docker_aliases_and_digest_references_are_equivalent(self):
        self.assertEqual(cleanup.aliases("docker.io/library/nginx:latest"), {"nginx:latest"})
        self.assertIn("nginx:latest", cleanup.aliases("nginx"))
        self.assertIn("sha256:abc", cleanup.aliases("host/image:tag@sha256:abc"))

    def test_current_container_desired_template_and_pinned_images_are_preserved(self):
        images = [
            {"id": "sha256:" + "1" * 64, "repoTags": ["docker.io/library/nginx:latest"], "size": "1"},
            {"id": "sha256:" + "2" * 64, "repoDigests": ["registry/image@sha256:desired"], "size": "2"},
            {"id": "sha256:" + "3" * 64, "pinned": True, "size": "3"},
            {"id": "sha256:" + "4" * 64, "repoTags": ["old:v1"], "size": "4"},
        ]
        pods = [{"kind": "Deployment", "spec": {"template": {"spec": {
            "containers": [{"image": "registry/image:stable@sha256:desired"}]
        }}}}]
        running = [{"imageId": "sha256:" + "1" * 64, "image": {"image": "nginx"}}]
        result = cleanup.image_candidates(images, running, cleanup.desired_references(pods))
        self.assertEqual([x["id"] for x in result], ["sha256:" + "4" * 64])

    def test_cronjob_images_are_preserved(self):
        items = [{"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {"spec": {
            "containers": [{"image": "example/backup:v1"}]
        }}}}}}]
        self.assertIn("example/backup:v1", cleanup.desired_references(items))

    def test_missing_or_ambiguous_ids_are_never_deleted(self):
        images = [{"id": ""}, {"id": "not-a-digest"}, {"id": "sha256:" + "a" * 64}]
        self.assertEqual([x["id"] for x in cleanup.image_candidates(images, [], set())], ["sha256:" + "a" * 64])

    def test_removed_alias_is_verified_before_treating_runtime_error_as_success(self):
        image = {"id": "sha256:" + "a" * 64, "size": "1"}
        with patch.object(cleanup, "inventory", side_effect=[[image], [image]]), \
                patch.object(cleanup, "read_json", side_effect=[{"containers": []}, {"images": []}]), \
                patch.object(cleanup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
                patch.object(sys, "argv", ["prune-unused-images.py", "--apply"]), \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(cleanup.main(), 0)
        self.assertIn('"already_absent": 1', output.getvalue())


if __name__ == "__main__":
    unittest.main()
