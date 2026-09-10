#!/usr/bin/env python3
"""Render the hash-pinned upstream operator for the dedicated three-node dev cluster."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import yaml


def render(raw, lock):
    if len(raw) > 4 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != lock["upstream_sha256"]:
        raise ValueError("upstream manifest digest mismatch")
    documents = list(yaml.safe_load_all(raw))
    deployments = [d for d in documents if d.get("kind") == "Deployment"]
    if len(deployments) != 1 or deployments[0]["metadata"] != {
        "labels": {"app.kubernetes.io/name": "cloudnative-pg"},
        "name": "cnpg-controller-manager", "namespace": "cnpg-system",
    }:
        raise ValueError("unexpected upstream operator deployment")
    deployment = deployments[0]
    pod = deployment["spec"]["template"]["spec"]
    if len(pod["containers"]) != 1 or "--leader-elect" not in pod["containers"][0]["args"]:
        raise ValueError("operator must retain leader election")
    container = pod["containers"][0]
    if container["image"] != "ghcr.io/cloudnative-pg/cloudnative-pg:" + lock["version"]:
        raise ValueError("unexpected upstream operator image")
    container["image"] = lock["image"]
    container["imagePullPolicy"] = "IfNotPresent"
    image_env = [e for e in container["env"] if e["name"] == "OPERATOR_IMAGE_NAME"]
    if len(image_env) != 1:
        raise ValueError("operator init-container image binding missing")
    image_env[0]["value"] = lock["image"]
    container["resources"] = {"requests": {"cpu": "100m", "memory": "128Mi"},
                              "limits": {"cpu": "500m", "memory": "512Mi"}}
    deployment["spec"]["replicas"] = 3
    deployment["spec"]["strategy"] = {"type": "RollingUpdate", "rollingUpdate": {
        "maxUnavailable": 1, "maxSurge": 0}}
    selector = copy.deepcopy(deployment["spec"]["selector"])
    pod["affinity"] = {
        "nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
            {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In",
                                   "values": [f"hetero-dev-{i}" for i in range(1, 4)]}]}]}},
        "podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [
            {"labelSelector": selector, "topologyKey": "kubernetes.io/hostname"}]},
    }
    pod["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane",
                           "operator": "Exists", "effect": "NoSchedule"}]
    for document in documents:
        if document.get("kind") == "Namespace":
            document["metadata"].setdefault("labels", {}).update({
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "v1.36",
            })
    documents.append({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
                      "metadata": {"name": "cnpg-controller-manager", "namespace": "cnpg-system"},
                      "spec": {"minAvailable": 2, "selector": selector}})
    return {"apiVersion": "v1", "kind": "List", "items": documents}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    lock = json.loads(Path(__file__).with_name("operator-lock.json").read_text())
    result = render(args.upstream.read_bytes(), lock)
    with args.output.open("x") as stream:
        json.dump(result, stream, separators=(",", ":"))
        stream.write("\n")


if __name__ == "__main__":
    main()
