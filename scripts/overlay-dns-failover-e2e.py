#!/usr/bin/env python3
"""Exercise real controller eviction and DNS reconciliation in a disposable kind cluster."""

import json
import os
from pathlib import Path
import subprocess
import time

import yaml

CLUSTER = "hnn-dns-failover-e2e"
CONTEXT = "kind-" + CLUSTER
ROOT = Path("/tmp/hnn-dns-failover-e2e")
WORKERS = (CLUSTER + "-worker", CLUSTER + "-worker2")
SELECTOR = "app.kubernetes.io/name=overlay-dns-service-discovery,app.kubernetes.io/component=controller"
DNS_NAME = "probe.heteronetwork.internal"
REPORT = {"result": "failed", "checks": []}


def run(command, *, data=None, timeout=30):
    result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed: {result.stderr[-1200:]}")
    return result.stdout


def kube(*arguments, data=None):
    return run(["kubectl", "--context", CONTEXT, "--request-timeout=10s", *arguments], data=data)


def apply(*objects):
    return kube("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}))


def get(kind, name=None, namespace=None, selector=None):
    arguments = ["get", kind]
    if name:
        arguments.append(name)
    if namespace:
        arguments += ["-n", namespace]
    if selector:
        arguments += ["-l", selector]
    return json.loads(kube(*arguments, "-o", "json"))


def wait_for(description, predicate, timeout):
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (RuntimeError, KeyError, IndexError, json.JSONDecodeError) as error:
            last = str(error)
        time.sleep(2)
    raise AssertionError(f"timed out waiting for {description}: {last}")


def ready(pod):
    return (not pod["metadata"].get("deletionTimestamp") and
            any(c["type"] == "Ready" and c["status"] == "True"
                for c in pod.get("status", {}).get("conditions", [])))


def pods():
    return get("pods", namespace="kube-system", selector=SELECTOR)["items"]


def spread():
    running = [pod for pod in pods() if ready(pod)]
    return running if len(running) == 2 and {pod["spec"]["nodeName"] for pod in running} == set(WORKERS) else None


def records():
    config = get("configmap", "heteronetwork-overlay-dns-effective", "kube-system")
    return json.loads(config["data"]["records.json"])["records"]


def record_check(description):
    REPORT["checks"].append(description)
    print(description, flush=True)


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("HNN_DNS_FAULT_E2E") != "kind-only" or
            os.environ.get("KUBECONFIG") != str(ROOT / "kubeconfig")):
        raise RuntimeError("refusing to run outside the dedicated GitHub Actions kind fixture")
    if run(["kubectl", "config", "current-context"]).strip() != CONTEXT:
        raise RuntimeError("unexpected Kubernetes context")
    expected = {CLUSTER + "-control-plane", *WORKERS}
    actual = {node["metadata"]["name"] for node in get("nodes")["items"]}
    if actual != expected:
        raise RuntimeError("unexpected nodes in the test cluster")
    for node in expected:
        inspection = json.loads(run(["docker", "inspect", node]))[0]
        if inspection["Config"]["Labels"].get("io.x-k8s.kind.cluster") != CLUSTER:
            raise RuntimeError("refusing to pause an unowned container")

    source = Path("deploy/gitops/cluster-dns")
    resources = []
    for resource in yaml.safe_load_all((source / "overlay-dns-service-discovery.yaml").read_text()):
        if resource:
            resources.append(resource)
        if resource and resource["kind"] == "PodDisruptionBudget":
            break
    for index, node in enumerate(WORKERS, start=1):
        kube("label", "node", node, "dns.heteronetwork.io/discovery=true", "--overwrite")
        kube("annotate", "node", node, f"networking.heteronetwork.io/vpn-ip=10.250.0.{200 + index}", "--overwrite")
    apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "heteronetwork-system"}},
          {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "heteronetwork-system", "name": "heteronetwork-overlay-dns"},
           "data": {"records.json": json.dumps({"schema_version": 1, "records": {}, "gateway_records": {}})}},
          {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "kube-system", "name": "overlay-dns-service-discovery"},
           "data": {"controller.py": (source / "overlay-dns-service-discovery.py").read_text(),
                    "services.json": (source / "overlay-dns-services.json").read_text()}},
          *resources)
    initial = wait_for("two ready controllers on different worker nodes", spread, 180)
    record_check("two controllers became ready on separate eligible workers")

    failed = initial[0]["spec"]["nodeName"]
    survivor = next(node for node in WORKERS if node != failed)
    survivor_ip = f"10.250.0.{201 + WORKERS.index(survivor)}"
    paused = False
    try:
        run(["docker", "pause", failed])
        paused = True
        wait_for("node readiness to be lost", lambda: not any(
            condition["type"] == "Ready" and condition["status"] == "True"
            for condition in get("node", failed).get("status", {}).get("conditions", [])), 150)
        record_check("the paused worker was detected as unavailable")

        def replacement_pending():
            active = [pod for pod in pods() if not pod["metadata"].get("deletionTimestamp")]
            running = [pod for pod in active if ready(pod)]
            pending = [pod for pod in active if pod.get("status", {}).get("phase") == "Pending"]
            return len(running) == 1 and running[0]["spec"]["nodeName"] == survivor and len(pending) == 1

        wait_for("eviction and a replacement waiting for a separate worker", replacement_pending, 210)
        record_check("the failed controller was evicted and its replacement did not colocate")

        apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "dns-failover-probe", "namespace": "default",
               "annotations": {"networking.heteronetwork.io/overlay-dns-name": DNS_NAME}},
               "spec": {"ports": [{"name": "http", "port": 80, "protocol": "TCP"}]}},
              {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "metadata": {"name": "dns-failover-probe", "namespace": "default",
               "labels": {"kubernetes.io/service-name": "dns-failover-probe"}}, "addressType": "IPv4",
               "endpoints": [{"addresses": ["192.0.2.10"], "nodeName": survivor, "conditions": {"ready": True}}],
               "ports": [{"name": "http", "port": 80, "protocol": "TCP"}]})
        wait_for("the surviving controller to add a service DNS record", lambda: records().get(DNS_NAME) == [survivor_ip], 60)
        record_check("the surviving controller discovered a new service during node loss")
    finally:
        if paused:
            run(["docker", "unpause", failed])

    wait_for("both controllers to return on separate workers", spread, 180)
    record_check("node recovery restored two controllers on separate workers")
    kube("delete", "service", "dns-failover-probe", "-n", "default", "--wait=false")
    wait_for("the removed service DNS record to disappear", lambda: DNS_NAME not in records(), 60)
    record_check("removing a service removed its DNS record")
    REPORT["result"] = "passed"


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        REPORT["failure"] = str(error)
        raise
    finally:
        ROOT.joinpath("results").mkdir(parents=True, exist_ok=True)
        ROOT.joinpath("results", "report.json").write_text(json.dumps(REPORT, indent=2) + "\n")
