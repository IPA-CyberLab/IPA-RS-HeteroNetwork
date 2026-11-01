#!/usr/bin/env python3
"""Verify actual HeteroCloud pods and endpoints before enabling IAM controls.

Read `kubectl -n heterocloud get deployments,pods,endpointslices -o json` from
stdin. Specify the immutable digest and the deliberately scheduled replica
count. This is a read-only gate; it does not change Kubernetes or PostgreSQL.
"""

import argparse
import json
import sys

COMPONENTS = {
    "api": ("heterocloud-heterocloud", "api"),
    "worker": ("heterocloud-heterocloud-worker", "worker"),
    "owner-console": ("heterocloud-heterocloud-owner-console", "owner-console"),
}
SERVICES = {
    "heterocloud-heterocloud": "api",
    "heterocloud-edge-backend": "api",
    "heterocloud-heterocloud-owner-console": "owner-console",
}


def verify(data, digest, replicas):
    if not digest.startswith("sha256:") or len(digest) != 71 or any(
        char not in "0123456789abcdef" for char in digest[7:]
    ):
        raise ValueError("expected a lowercase sha256 image digest")
    if replicas < 1:
        raise ValueError("replica count must be positive")

    items = data.get("items", [])
    deployments = {item["metadata"]["name"]: item for item in items if item.get("kind") == "Deployment"}
    serving_pods = {component: set() for component in COMPONENTS}
    problems = []

    for component, (name, container) in COMPONENTS.items():
        deployment = deployments.get(name)
        if deployment is None:
            problems.append(f"missing deployment {name}")
            continue
        spec, status = deployment["spec"], deployment.get("status", {})
        images = {c["name"]: c["image"] for c in spec["template"]["spec"]["containers"]}
        if spec.get("replicas") != replicas or any(
            status.get(field, 0) != replicas
            for field in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")
        ):
            problems.append(f"{name} does not have {replicas} fully updated and ready replicas")
        if not images.get(container, "").endswith("@" + digest):
            problems.append(f"{name} does not specify the expected digest")

        pods = [item for item in items if item.get("kind") == "Pod"
                and item["metadata"].get("labels", {}).get("app.kubernetes.io/instance") == "heterocloud"
                and item["metadata"].get("labels", {}).get("app.kubernetes.io/component") == component
                and not item["metadata"].get("deletionTimestamp")]
        if len(pods) != replicas:
            problems.append(f"{component} has {len(pods)} non-terminating pods, expected {replicas}")
        for pod in pods:
            pod_name = pod["metadata"]["name"]
            pod_images = {c["name"]: c["image"] for c in pod["spec"]["containers"]}
            states = {s["name"]: s for s in pod.get("status", {}).get("containerStatuses", [])}
            state = states.get(container, {})
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in pod.get("status", {}).get("conditions", []))
            if not ready or not state.get("ready") or not pod_images.get(container, "").endswith("@" + digest) \
                    or not state.get("imageID", "").endswith("@" + digest):
                problems.append(f"{pod_name} is not ready on the expected image")
            else:
                serving_pods[component].add(pod_name)

    endpoint_slices = [item for item in items if item.get("kind") == "EndpointSlice"]
    for service, component in SERVICES.items():
        endpoints = [endpoint for item in endpoint_slices
                     if item["metadata"].get("labels", {}).get("kubernetes.io/service-name") == service
                     for endpoint in item.get("endpoints", [])
                     if endpoint.get("conditions", {}).get("ready") is True]
        targets = {endpoint.get("targetRef", {}).get("name") for endpoint in endpoints}
        if targets != serving_pods[component] or len(endpoints) != replicas:
            problems.append(f"{service} endpoints do not exactly match the verified {component} pods")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--replicas", required=True, type=int)
    args = parser.parse_args()
    try:
        problems = verify(json.load(sys.stdin), args.digest, args.replicas)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"rollout verification failed: {error}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"verified {args.replicas} replicas for each deployment and all serving endpoints on {args.digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
