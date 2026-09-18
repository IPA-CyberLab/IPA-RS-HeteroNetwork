#!/usr/bin/env python3
"""Accept GPU nodes only after Kubernetes grants one exclusive GPU to a pod."""
import argparse
import json
import re
import subprocess
import sys
import time

PRESENT_LABEL = "nvidia.com/gpu.present"
READY_LABEL = "flash.heterocloud.io/gpu-ready"
COUNT_LABEL = "flash.heterocloud.io/gpu-count"
TYPE_LABEL = "flash.heterocloud.io/gpu-type"
RESOURCE = "nvidia.com/gpu"
APPLICATIONS = ("gpu-runtime", "nvidia-device-plugin")
SMOKE_IMAGE = (
    "nvcr.io/nvidia/cuda:12.6.3-base-ubuntu24.04"
    "@sha256:c87e78933f4c16e3272123bf2f75537306596d0fbaa395a29696a22786e5ee0e"
)


def run(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", *args], input=input_text, text=True, capture_output=True, check=check
    )


def get_json(*args: str) -> dict:
    return json.loads(run(*args, "-o", "json").stdout)


def expected_nodes(
    required: dict[str, int], required_types: dict[str, str]
) -> tuple[dict[str, int], dict[str, str]]:
    nodes = get_json("get", "nodes", "-l", f"{PRESENT_LABEL}=true")
    actual: dict[str, int] = {}
    actual_types: dict[str, str] = {}
    for node in nodes["items"]:
        name = node["metadata"]["name"]
        labels = node["metadata"].get("labels", {})
        raw = labels.get(COUNT_LABEL, "")
        if not re.fullmatch(r"[1-9][0-9]*", raw):
            raise RuntimeError(f"{name} has an invalid {COUNT_LABEL} label")
        gpu_type = labels.get(TYPE_LABEL, "")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", gpu_type):
            raise RuntimeError(f"{name} has an invalid {TYPE_LABEL} label")
        actual[name] = int(raw)
        actual_types[name] = gpu_type
    for name, count in required.items():
        if actual.get(name) != count:
            raise RuntimeError(f"{name} must advertise {count} physical GPUs; observed {actual.get(name)}")
    for name, gpu_type in required_types.items():
        if actual_types.get(name) != gpu_type:
            raise RuntimeError(f"{name} must advertise GPU type {gpu_type}; observed {actual_types.get(name)}")
    return actual, actual_types


def capacity_ready(nodes: dict[str, int], require_acceptance_label: bool) -> tuple[bool, str]:
    for name, count in nodes.items():
        node = get_json("get", "node", name)
        allocatable = node.get("status", {}).get("allocatable", {}).get(RESOURCE)
        if allocatable != str(count):
            return False, f"{name} allocatable {RESOURCE} is {allocatable!r}, expected {count}"
        if require_acceptance_label and node.get("metadata", {}).get("labels", {}).get(READY_LABEL) != "true":
            return False, f"{name} is missing {READY_LABEL}=true"
    return True, "ready"


def wait_for_applications(deadline: float) -> None:
    while time.monotonic() < deadline:
        pending = []
        for name in APPLICATIONS:
            app = get_json("get", "application", name, "-n", "argocd")
            sync = app.get("status", {}).get("sync", {}).get("status")
            health = app.get("status", {}).get("health", {}).get("status")
            if sync != "Synced" or health != "Healthy":
                pending.append(f"{name}:{sync}/{health}")
        if not pending:
            return
        time.sleep(5)
    raise RuntimeError("GPU Argo applications did not converge before the deadline: " + ", ".join(pending))


def wait_for_capacity(nodes: dict[str, int], deadline: float) -> None:
    message = "GPU capacity not observed"
    while time.monotonic() < deadline:
        ready, message = capacity_ready(nodes, False)
        if ready:
            return
        time.sleep(5)
    raise RuntimeError(message)


def smoke_node(name: str, gpu_type: str, namespace: str, deadline: float) -> dict:
    safe_name = re.sub(r"[^a-z0-9-]", "-", name.lower()).strip("-")
    pod_name = f"gpu-exclusive-smoke-{safe_name}"[:63].rstrip("-")
    run("delete", "pod", pod_name, "-n", namespace, "--ignore-not-found=true", "--wait=true")
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": {
            "restartPolicy": "Never",
            "runtimeClassName": "nvidia",
            "nodeSelector": {
                "kubernetes.io/hostname": name,
                TYPE_LABEL: gpu_type,
            },
            "containers": [{
                "name": "probe",
                "image": SMOKE_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-ec"],
                "args": ["nvidia-smi -L; test \"$(nvidia-smi -L | grep -c '^GPU ')\" -eq 1"],
                "resources": {
                    "requests": {RESOURCE: "1"},
                    "limits": {RESOURCE: "1"},
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
            }],
        },
    }
    try:
        run("apply", "-f", "-", input_text=json.dumps(manifest))
        phase = ""
        pod: dict = {}
        while time.monotonic() < deadline:
            pod = get_json("get", "pod", pod_name, "-n", namespace)
            phase = pod.get("status", {}).get("phase", "")
            if phase in {"Succeeded", "Failed"}:
                break
            time.sleep(3)
        logs = run("logs", pod_name, "-n", namespace, check=False).stdout
        if phase != "Succeeded":
            reason = pod.get("status", {}).get("message", "")
            raise RuntimeError(f"GPU smoke pod on {name} ended as {phase or 'timeout'}: {reason}")
        lines = [line for line in logs.splitlines() if line.startswith("GPU ")]
        if len(lines) != 1:
            raise RuntimeError(f"GPU smoke pod on {name} observed {len(lines)} GPUs instead of one")
        return {"node": name, "visible_gpus": 1, "pod": pod_name}
    finally:
        run("delete", "pod", pod_name, "-n", namespace, "--ignore-not-found=true", "--wait=true", check=False)


def parse_required(values: list[str]) -> dict[str, int]:
    required: dict[str, int] = {}
    for value in values:
        name, separator, raw = value.partition("=")
        if not separator or not name or not raw.isdigit() or int(raw) < 1:
            raise ValueError(f"invalid --require-node value: {value!r}")
        required[name] = int(raw)
    return required


def parse_required_types(values: list[str]) -> dict[str, str]:
    required: dict[str, str] = {}
    for value in values:
        name, separator, gpu_type = value.partition("=")
        if (
            not separator
            or not name
            or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", gpu_type)
        ):
            raise ValueError(f"invalid --require-type value: {value!r}")
        required[name] = gpu_type
    return required


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default="nvidia-device-plugin")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--require-node", action="append", default=[])
    parser.add_argument("--require-type", action="append", default=[])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    required = parse_required(args.require_node)
    required_types = parse_required_types(args.require_type)
    if args.check:
        try:
            nodes, gpu_types = expected_nodes(required, required_types)
        except RuntimeError as error:
            print(json.dumps({"ready": False, "nodes": {}, "message": str(error)}, sort_keys=True))
            return 2
    else:
        nodes, gpu_types = expected_nodes(required, required_types)
    if not nodes:
        if args.check:
            print(json.dumps({"ready": False, "nodes": {}, "message": "no eligible GPU node was discovered"}, sort_keys=True))
            return 2
        raise RuntimeError("no eligible GPU node was discovered")
    ready, message = capacity_ready(nodes, args.check)
    if args.check:
        print(json.dumps({"ready": ready, "nodes": nodes, "gpu_types": gpu_types, "message": message}, sort_keys=True))
        return 0 if ready else 2

    deadline = time.monotonic() + args.timeout_seconds
    wait_for_applications(deadline)
    wait_for_capacity(nodes, deadline)
    results = [smoke_node(name, gpu_types[name], args.namespace, deadline) for name in sorted(nodes)]
    for name in sorted(nodes):
        run("label", "node", name, f"{READY_LABEL}=true", "--overwrite")
    ready, message = capacity_ready(nodes, True)
    if not ready:
        raise RuntimeError(message)
    print(json.dumps({"ready": True, "nodes": nodes, "gpu_types": gpu_types, "smoke": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
