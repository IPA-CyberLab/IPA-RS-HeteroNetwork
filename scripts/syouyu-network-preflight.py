#!/usr/bin/env python3
"""Check Syouyu's live DB/host-network policy contract without mutating resources."""

import ipaddress
import json
import subprocess


def get(namespace, resource, name=None, selector=None):
    args = ["kubectl", "--request-timeout=15s"]
    if namespace:
        args += ["-n", namespace]
    args += ["get", resource]
    if name:
        args.append(name)
    if selector:
        args += ["-l", selector]
    args += ["-o", "json"]
    return json.loads(subprocess.check_output(args, timeout=20))


def allows_ip(rules, direction, address, port):
    for rule in rules:
        ports = rule.get("ports", [])
        if ports and not any(
            p.get("protocol", "TCP") == "TCP"
            and ("port" not in p or p["port"] == port)
            for p in ports
        ):
            continue
        peers = rule.get(direction, [])
        if not peers:
            return True
        for peer in peers:
            block = peer.get("ipBlock")
            if block and address in ipaddress.ip_network(block["cidr"]):
                if not any(address in ipaddress.ip_network(cidr) for cidr in block.get("except", [])):
                    return True
    return False


def main():
    policy = get("heterocloud-syouyu", "networkpolicy", "heterocloud-syouyu-api")["spec"]
    slices = get("kube-system", "endpointslices", selector="kubernetes.io/service-name=postgres-ha-connector")
    failures = []
    db_targets = set()
    for item in slices["items"]:
        for endpoint in item["endpoints"]:
            if endpoint.get("conditions", {}).get("ready") is False:
                continue
            for address in endpoint["addresses"]:
                for port in item["ports"]:
                    if port.get("protocol", "TCP") == "TCP":
                        db_targets.add((address, port["port"]))
    if not db_targets:
        failures.append("PostgreSQL connector has no ready endpoints")
    for address, port in sorted(db_targets):
        if not allows_ip(policy.get("egress", []), "to", ipaddress.ip_address(address), port):
            failures.append(f"DB target {address}:{port} is missing from IP-based egress allowances")

    workers = get("heterocloud", "pods", selector="app.kubernetes.io/component=worker")
    nodes = {node["metadata"]["name"]: node for node in get(None, "nodes")["items"]}
    worker_nodes = {
        pod["spec"]["nodeName"] for pod in workers["items"]
        if pod["spec"].get("hostNetwork") and pod["spec"].get("nodeName")
    }
    if not workers["items"]:
        failures.append("No HeteroCloud workers found")
    for name in sorted(worker_nodes):
        cidr = nodes[name]["spec"].get("podCIDR")
        if not cidr:
            failures.append(f"Node {name} has no PodCIDR")
            continue
        # This deployment uses Flannel VXLAN: the subnet base is its host interface.
        source = ipaddress.ip_network(cidr).network_address
        if not allows_ip(policy.get("ingress", []), "from", source, 8080):
            failures.append(f"Worker node {name} Flannel source {source}:8080 is not allowed")

    api_slices = get("heterocloud-syouyu", "endpointslices", selector="kubernetes.io/service-name=heterocloud-syouyu-api")
    ready_api = sum(
        len(endpoint["addresses"])
        for item in api_slices["items"] for endpoint in item["endpoints"]
        if endpoint.get("conditions", {}).get("ready") is not False
    )
    if not ready_api:
        failures.append("Syouyu API has no ready endpoints")
    print(json.dumps({"database_targets": len(db_targets), "worker_nodes": len(worker_nodes),
                      "ready_api_endpoints": ready_api, "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
