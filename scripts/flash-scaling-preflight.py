#!/usr/bin/env python3
"""Read-only checks for Flash HPA and domain endpoint prerequisites.

Run on an operator host with kubectl access. With --service-id, also checks the
service's HPA, current resource metrics, and DNS target set. This is not a load
test and does not prove TCP/UDP delivery or automatic scale-out under load.
"""

import argparse
import json
import os
import socket
import subprocess
import time
import uuid


def kube(*args):
    server = os.environ.get("KUBERNETES_API_SERVER")
    override = [f"--server={server}"] if server else []
    return json.loads(subprocess.check_output(
        ["kubectl", *override, "--request-timeout=15s", *args, "-o", "json"],
        timeout=20,
    ))


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-id", type=uuid.UUID)
    parser.add_argument("--stable-for", type=int, default=0,
                        help="Observe NetworkPolicy generation stability for 0..60 seconds")
    args = parser.parse_args()
    if not 0 <= args.stable_for <= 60 or (args.stable_for and not args.service_id):
        parser.error("stable-for requires a service-id and must be 0..60 seconds")
    api = kube("get", "apiservice", "v1beta1.metrics.k8s.io")
    require(any(c["type"] == "Available" and c["status"] == "True"
                for c in api.get("status", {}).get("conditions", [])),
            "Metrics API is unavailable")
    metrics = kube("-n", "kube-system", "get", "deployment", "metrics-server")
    require(metrics.get("status", {}).get("availableReplicas", 0) >= 2,
            "Metrics Server has fewer than two available replicas")
    dns = kube("-n", "heterocloud-dns", "get", "deployment", "heterocloud-dns")
    dns_args = dns["spec"]["template"]["spec"]["containers"][0]["args"]
    require("--source=service" in dns_args, "ExternalDNS does not watch Services")
    require(dns.get("status", {}).get("availableReplicas", 0) >= 1,
            "ExternalDNS is unavailable")
    print("Metrics API available; two Metrics Server replicas; ExternalDNS Service source enabled")
    if args.service_id is None:
        return

    namespace = "heterocloud-flash-workloads"
    name = f"flash-{args.service_id}"
    resource = kube("-n", namespace, "get", "flashservice", name)
    workload = resource["spec"]["workload"]
    autoscaling = workload.get("autoscaling")
    if autoscaling:
        hpa = kube("-n", namespace, "get", "hpa", name)
        require(hpa["spec"]["minReplicas"] == autoscaling["min_replicas"] and
                hpa["spec"]["maxReplicas"] == autoscaling["max_replicas"],
                "HPA bounds differ from the Flash configuration")
        for kind in ("cpu", "memory"):
            target = autoscaling.get(f"target_{kind}_utilization_percent")
            configured = [m["resource"]["target"].get("averageUtilization")
                          for m in hpa["spec"].get("metrics", [])
                          if m.get("type") == "Resource" and
                          m.get("resource", {}).get("name") == kind]
            require(configured == ([] if target is None else [target]),
                    f"HPA {kind} target differs from Flash configuration")
        require(any(c["type"] == "ScalingActive" and c["status"] == "True"
                    for c in hpa.get("status", {}).get("conditions", [])),
                "HPA is not actively computing recommendations")
        print(json.dumps({"hpa": name, "current": hpa["status"].get("currentReplicas"),
                          "desired": hpa["status"].get("desiredReplicas")}))

    if workload["exposure"].get("endpoint_mode", "ip") == "load_balancer":
        service = kube("-n", namespace, "get", "service", name)
        annotations = service["metadata"].get("annotations", {})
        hostname = annotations.get("external-dns.alpha.kubernetes.io/hostname")
        require(hostname, "Load balancer DNS annotation is missing")
        require(service["metadata"].get("labels", {}).get("dns.heterocloud.io/publish") == "true",
                "Load balancer is excluded by the DNS publication label filter")
        expected = {entry["ip"] for entry in
                    service.get("status", {}).get("loadBalancer", {}).get("ingress", [])
                    if entry.get("ip") and ":" not in entry["ip"]}
        require(expected, "Load balancer has no IPv4 targets")
        actual = {entry[4][0] for entry in socket.getaddrinfo(hostname, None, socket.AF_INET)}
        require(actual == expected, f"DNS targets not converged: expected {sorted(expected)}, got {sorted(actual)}")
        print(json.dumps({"hostname": hostname, "addresses": sorted(actual)}))

    if args.stable_for:
        before = kube("-n", namespace, "get", "networkpolicy", name)["metadata"]
        time.sleep(args.stable_for)
        after = kube("-n", namespace, "get", "networkpolicy", name)["metadata"]
        require(before["uid"] == after["uid"] and before["generation"] == after["generation"],
                "NetworkPolicy spec did not remain stable during the observation")
        print(json.dumps({"network_policy_generation": after["generation"],
                          "stable_seconds": args.stable_for,
                          "resource_version_unchanged": before["resourceVersion"] == after["resourceVersion"]}))


if __name__ == "__main__":
    main()
