#!/usr/bin/env python3
"""Reclaim CRI images unused by local containers and cluster workload templates."""
import argparse
import json
import re
import subprocess
import sys


CRI = ["crictl", "--runtime-endpoint", "unix:///run/containerd/containerd.sock"]
KUBE = ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "--request-timeout=20s"]


def read_json(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=True)
    return json.loads(result.stdout)


def aliases(reference):
    if not isinstance(reference, str) or not reference:
        return set()
    for prefix in ("docker-pullable://", "containerd://", "docker://"):
        reference = reference.removeprefix(prefix)
    for prefix in ("docker.io/", "index.docker.io/"):
        reference = reference.removeprefix(prefix)
    reference = reference.removeprefix("library/")
    result = {reference}
    if "@sha256:" in reference:
        repository, digest = reference.rsplit("@", 1)
        last = repository.rsplit("/", 1)[-1]
        if ":" in last:
            repository = repository[:-(len(last) - last.rfind(":"))]
        result.update((digest, repository + "@" + digest))
    elif not reference.startswith("sha256:") and ":" not in reference.rsplit("/", 1)[-1]:
        result.add(reference + ":latest")
    return result


def desired_references(items):
    result = set()
    for item in items:
        kind = item.get("kind")
        spec = item.get("spec", {})
        if kind == "CronJob":
            spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
        elif kind != "Pod":
            spec = spec.get("template", {}).get("spec", {})
        for field in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(field, []):
                result.update(aliases(container.get("image")))
        if kind == "Pod":
            for field in ("containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"):
                for container in item.get("status", {}).get(field, []):
                    result.update(aliases(container.get("imageID")))
    return result


def image_candidates(images, containers, desired):
    protected = set(desired)
    for container in containers:
        for ref in (container.get("imageId"), container.get("imageRef"), container.get("image", {}).get("image")):
            protected.update(aliases(ref))
    result = []
    for image in images:
        if image.get("pinned"):
            continue
        image_id = image.get("id", "")
        refs = set()
        for ref in [image_id, *image.get("repoTags", []), *image.get("repoDigests", [])]:
            refs.update(aliases(ref))
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) or not refs or refs & protected:
            continue
        result.append(image)
    return result


def inventory():
    objects = read_json(KUBE + ["get", "pods,deployments,statefulsets,daemonsets,jobs,cronjobs", "-A", "-o", "json"])
    images = read_json(CRI + ["images", "-o", "json"])
    containers = read_json(CRI + ["ps", "-a", "-o", "json"])
    if "items" not in objects or "images" not in images or "containers" not in containers:
        raise ValueError("incomplete Kubernetes or CRI inventory")
    return image_candidates(images["images"], containers["containers"], desired_references(objects["items"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    before = inventory()
    removed = already_absent = failed = 0
    if args.apply:
        # Re-snapshot immediately before deletion to avoid stale plans. Never use
        # --force or remove images still referenced by any local container.
        current = {item["id"] for item in inventory()}
        for item in before:
            if item["id"] not in current:
                continue
            local = read_json(CRI + ["ps", "-a", "-o", "json"])
            if "containers" not in local or not image_candidates([item], local["containers"], set()):
                continue
            result = subprocess.run(CRI + ["rmi", item["id"]], capture_output=True, text=True, timeout=60)
            if result.returncode:
                # Removing one image may remove another listed alias as well.
                # Only treat a failed request as success after checking CRI.
                remaining = read_json(CRI + ["images", "-o", "json"])
                if "images" not in remaining:
                    raise ValueError("incomplete CRI image inventory")
                if any(image.get("id") == item["id"] for image in remaining["images"]):
                    failed += 1
                else:
                    already_absent += 1
            else:
                removed += 1
    print(json.dumps({"eligible": len(before), "logical_bytes": sum(int(x.get("size", 0)) for x in before),
                      "removed": removed, "already_absent": already_absent, "failed": failed,
                      "applied": args.apply}, sort_keys=True))
    return int(failed > 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"image cleanup failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
