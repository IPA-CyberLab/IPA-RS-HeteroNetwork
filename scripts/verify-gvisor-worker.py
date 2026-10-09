#!/usr/bin/env python3
"""Advertise a worker only after a bounded sandbox execution succeeds."""
import argparse
import json
import re
import subprocess
import time


OWNER = "heteronetwork-gvisor-iac"
LABEL = "flash.heterocloud.io/gvisor-ready"
ANNOTATION = "infrastructure.heteronetwork.io/owner"
IMAGE = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"


def eligible(node):
    return (
        node.get("metadata", {}).get("labels", {}).get(
            "heteronetwork.io/control-plane-only"
        ) != "true"
        and not node.get("spec", {}).get("unschedulable", False)
        and not any(
            taint["key"] in (
                "heteronetwork.io/control-plane-only",
                "node-role.kubernetes.io/control-plane",
            )
            for taint in node.get("spec", {}).get("taints", [])
        )
        and any(
            condition["type"] == "Ready" and condition["status"] == "True"
            for condition in node.get("status", {}).get("conditions", [])
        )
    )


def probe(node, runtime):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "hnn-gvisor-probe-" + node,
            "namespace": "kube-system",
            "annotations": {ANNOTATION: OWNER},
        },
        "spec": {
            "nodeName": node,
            "runtimeClassName": runtime,
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 120,
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "probe",
                "image": IMAGE,
                "command": ["/bin/sh", "-ec",
                            "dmesg | grep -q 'Starting gVisor'; echo GVISOR_ACCEPTED"],
                "resources": {
                    "requests": {"cpu": "10m", "memory": "32Mi"},
                    "limits": {"cpu": "100m", "memory": "64Mi"},
                },
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 65532,
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    parser.add_argument("--kubeconfig", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", args.node):
        raise RuntimeError("Invalid worker name")
    base = ["kubectl", "--kubeconfig=" + args.kubeconfig, "--request-timeout=15s"]

    def run(*command, body=None):
        result = subprocess.run(
            base + list(command), input=body, text=True, capture_output=True, timeout=25
        )
        if result.returncode:
            raise RuntimeError("Kubernetes runtime acceptance operation failed: " + result.stderr[:300])
        return result.stdout

    def get(kind, name, namespace=None):
        command = ["get", kind, name, "--ignore-not-found", "-o", "json"]
        if namespace:
            command += ["-n", namespace]
        output = run(*command)
        return json.loads(output) if output.strip() else None

    node = get("node", args.node)
    if node is None or not eligible(node):
        raise RuntimeError("Runtime acceptance requires a ready, schedulable workload worker")
    runtime = "hnn-gvisor-acceptance-" + args.node
    pod = "hnn-gvisor-probe-" + args.node
    resources = [("runtimeclass", runtime, None), ("pod", pod, "kube-system")]
    for kind, name, namespace in resources:
        existing = get(kind, name, namespace)
        if existing is not None:
            raise RuntimeError("A runtime acceptance resource already exists; inspect it before retrying")
    created = []
    try:
        runtime_spec = {
            "apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
            "metadata": {"name": runtime, "annotations": {ANNOTATION: OWNER}},
            "handler": "runsc",
        }
        for manifest in (runtime_spec, probe(args.node, runtime)):
            resource = json.loads(run("create", "-f", "-", "-o", "json", body=json.dumps(manifest)))
            created.append((resource["kind"].lower(), resource["metadata"]["name"],
                            resource["metadata"].get("namespace"), resource["metadata"]["uid"]))
        deadline = time.monotonic() + 140
        while time.monotonic() < deadline:
            current = get("pod", pod, "kube-system")
            phase = (current or {}).get("status", {}).get("phase")
            if phase == "Succeeded":
                break
            if phase == "Failed":
                raise RuntimeError("The worker failed the sandbox execution probe")
            time.sleep(2)
        else:
            raise RuntimeError("The worker did not complete the sandbox execution probe")
        if run("logs", pod, "-n", "kube-system").strip() != "GVISOR_ACCEPTED":
            raise RuntimeError("Sandbox execution evidence is missing")
        if not eligible(get("node", args.node) or {}):
            raise RuntimeError("Worker health changed during runtime acceptance")
        run("patch", "node", args.node, "--type=merge",
            "--field-manager=" + OWNER, "-p",
            json.dumps({"metadata": {"labels": {LABEL: "true"}}}))
        print(json.dumps({"node": args.node, "runtime_class": "gvisor",
                          "sandbox_executed": True, "scheduling_label_published": True}))
    finally:
        for kind, name, namespace, uid in reversed(created):
            existing = get(kind, name, namespace)
            if (existing is None or existing["metadata"]["uid"] != uid
                    or existing["metadata"].get("annotations", {}).get(ANNOTATION) != OWNER):
                continue
            command = ["delete", kind, name, "--wait=false"]
            if namespace:
                command += ["-n", namespace]
            run(*command)


if __name__ == "__main__":
    main()
