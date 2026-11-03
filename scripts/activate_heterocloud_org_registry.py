#!/usr/bin/env python3
"""Activate the shared Registry credential quota after a verified rollout."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


# Add only a release whose tests passed and whose image was built from the
# implementation of organization_registry_credentials_enabled.
SUPPORTED_DIGESTS = {"sha256:f1fa2604777714325289ecf5ee8c743d0dda8f3a424415b2706ac0ee95d1ff16", "sha256:1346a90187cc39926c5df2b36ed9093528e8fe0e1b65f3ab8177a635ec1a729f", "sha256:691e7ed9143b873fd3d7e5bab2d6e777d1ba3ef6b6c9aaf71fc71c6eeed2f137", "sha256:0a5a0c71297f36b56ebde70feb9a36fee68274e42348c974d971683ce99067df"}


def verified_worker(data, digest, replicas, desired_replicas):
    if digest not in SUPPORTED_DIGESTS:
        raise RuntimeError("the release digest is not approved for Registry quotas")
    path = Path(__file__).with_name("verify-heterocloud-iam-rollout.py")
    spec = importlib.util.spec_from_file_location("verify_heterocloud_iam_rollout", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    problems = module.verify(data, digest, replicas, desired_replicas)
    if problems:
        raise RuntimeError("; ".join(problems))
    deployments = [item for item in data["items"] if item.get("kind") == "Deployment"
                   and item["metadata"]["name"] == "heterocloud-heterocloud-worker"]
    containers = deployments[0]["spec"]["template"]["spec"]["containers"]
    worker = next(container for container in containers if container["name"] == "worker")
    command = worker.get("command", []) + worker.get("args", [])
    if not command or command[0] != "/usr/local/bin/heterocloud-worker":
        raise RuntimeError("unexpected worker command")
    pods = [item for item in data["items"] if item.get("kind") == "Pod"
            and not item["metadata"].get("deletionTimestamp")
            and item["metadata"].get("labels", {}).get("app.kubernetes.io/instance") == "heterocloud"
            and item["metadata"].get("labels", {}).get("app.kubernetes.io/component") == "worker"
            and any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in item.get("status", {}).get("conditions", []))]
    if not pods:
        raise RuntimeError("no verified ready worker")
    return pods[0]["metadata"]["name"], command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--replicas", type=int, default=2)
    parser.add_argument("--desired-replicas", type=int, default=3)
    args = parser.parse_args()
    kubectl = os.environ.get("KUBECTL", "kubectl")
    try:
        snapshot = subprocess.run(
            [kubectl, "-n", "heterocloud", "get", "deployments,pods,endpointslices", "-o", "json"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        pod, command = verified_worker(json.loads(snapshot.stdout), args.digest, args.replicas, args.desired_replicas)
        result = subprocess.run(
            [kubectl, "-n", "heterocloud", "exec", pod, "-c", "worker", "--", *command,
             "--enable-organization-registry-credentials"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        if "organization_registry_credentials_enabled=true" not in result.stdout:
            raise RuntimeError("worker did not confirm activation")
        print(f"Enabled Registry organization quotas after verifying {args.replicas} serving replicas per component.")
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError, KeyError, StopIteration, TypeError) as error:
        # Subprocess output can contain credentials; do not echo it.
        if isinstance(error, RuntimeError):
            print(f"Registry quota activation refused: {error}", file=sys.stderr)
        else:
            print(f"Registry quota activation failed: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
