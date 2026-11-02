#!/usr/bin/env python3
"""Exercise quota patch fencing against the configured Kubernetes API.

Creates a stopped FlashService in a new namespace outside the workload
namespace, validates stale and current resource versions, then deletes it.
Set KUBECONFIG and optionally KUBECTL before running.
"""
import json
import os
import subprocess
import sys
import uuid


def main():
    kubectl = os.environ.get("KUBECTL", "kubectl")
    namespace = "hetero-quota-cas-test-" + uuid.uuid4().hex[:8]
    service_id = str(uuid.uuid4())
    name = "flash-" + service_id
    created = False
    success = False

    def run(*args, data=None, check=True, timeout=30):
        return subprocess.run([kubectl, *args], input=data, capture_output=True, text=True,
                              timeout=timeout, check=check)

    try:
        run("create", "namespace", namespace)
        created = True
        obj = {"apiVersion": "flash.heterocloud.io/v1alpha1", "kind": "FlashService",
               "metadata": {"name": name, "namespace": namespace},
               "spec": {"desired_generation": 1, "display_name": "quota-cas-test",
                        "organization_id": str(uuid.uuid4()), "project_id": str(uuid.uuid4()),
                        "service_instance_id": service_id,
                        "workload": {"stopped": True, "region": "heteronet-global",
                                     "image": "example.invalid/quota-test:unused", "replicas": 1,
                                     "cpu_millis": 100, "memory_mib": 128, "ports": [],
                                     "exposure": {"type": "internal", "traffic_mode": "forwarded",
                                                  "allowed_source_cidrs": [], "denied_source_cidrs": []}}}}
        run("create", "-f", "-", data=json.dumps(obj))
        first = json.loads(run("-n", namespace, "get", "flashservice", name, "-o", "json").stdout)
        old_version = first["metadata"]["resourceVersion"]
        run("-n", namespace, "label", "flashservice", name, "quota-e2e-revision=changed")
        patch = {"metadata": {"resourceVersion": old_version},
                 "spec": {"policy": {"max_weekly_cpu_millicore_seconds": 1}}}
        stale = run("-n", namespace, "patch", "flashservice", name, "--type=merge", "-p",
                    json.dumps(patch), check=False)
        if stale.returncode == 0 or "Conflict" not in stale.stderr:
            raise RuntimeError("a stale resource version was not rejected")
        current = json.loads(run("-n", namespace, "get", "flashservice", name, "-o", "json").stdout)
        patch["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
        run("-n", namespace, "patch", "flashservice", name, "--type=merge", "-p", json.dumps(patch))
        result = json.loads(run("-n", namespace, "get", "flashservice", name, "-o", "json").stdout)
        if (result["spec"]["desired_generation"] != 1 or result["spec"]["workload"]["stopped"] is not True
                or result["spec"]["policy"]["max_weekly_cpu_millicore_seconds"] != 1):
            raise RuntimeError("quota update changed the workload or failed to apply")
        pods = json.loads(run("-n", namespace, "get", "pods", "-o", "json").stdout)
        if pods.get("items"):
            raise RuntimeError("unexpected workload created in the isolated test namespace")
        print("Kubernetes E2E: stale quota update rejected; current update applied without changing the workload.")
        success = True
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, RuntimeError) as error:
        print(f"Kubernetes E2E failed: {error}", file=sys.stderr)
    finally:
        if created:
            try:
                run("delete", "namespace", namespace, "--wait=true", "--timeout=60s", timeout=75)
                print("Temporary test namespace deleted.")
            except (OSError, subprocess.SubprocessError):
                print(f"Failed to delete temporary namespace {namespace}.", file=sys.stderr)
                success = False
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
