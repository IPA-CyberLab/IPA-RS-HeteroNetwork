#!/usr/bin/env python3
"""Dry-run by default: allow the recovered API endpoints in Garage's API rule.

Does not restart workloads, alter membership, or touch volumes. Apply only after
reviewing current default/kubernetes EndpointSlices and the printed patch.
"""

import argparse
import copy
import json
import subprocess


NAMESPACE = "heterocloud-syouyu"
POLICY = "heterocloud-syouyu-garage"
ENDPOINTS = {"10.250.0.10", "10.250.0.5", "10.250.0.6", "10.250.0.8"}
SELECTOR = {
    "app.kubernetes.io/component": "garage",
    "app.kubernetes.io/instance": "heterocloud-syouyu",
    "app.kubernetes.io/name": "heterocloud-syouyu",
}


def build_patch(policy, slices):
    addresses = {address for item in slices["items"] for endpoint in item["endpoints"]
                 for address in endpoint["addresses"]}
    if not addresses or not addresses <= ENDPOINTS:
        raise ValueError("API endpoint set is empty or contains unreviewed endpoints")
    spec = policy["spec"]
    if (policy["metadata"]["name"] != POLICY or
            policy["metadata"]["namespace"] != NAMESPACE or
            spec["podSelector"] != {"matchLabels": SELECTOR}):
        raise ValueError("unexpected NetworkPolicy identity or selector")
    indices = [index for index, rule in enumerate(spec["egress"])
               if {"ipBlock": {"cidr": "10.96.0.0/12"}} in rule.get("to", [])
               and rule.get("ports") == [{"port": port, "protocol": "TCP"}
                                        for port in (443, 6443, 7443)]]
    if len(indices) != 1:
        raise ValueError("expected exactly one existing Kubernetes API egress rule")
    index = indices[0]
    peers = copy.deepcopy(spec["egress"][index]["to"])
    # Helm emits one rule per CIDR; consider those equivalent to a combined rule.
    covered = [peer for rule in spec["egress"]
               if rule.get("ports") == spec["egress"][index]["ports"]
               for peer in rule.get("to", [])]
    for address in sorted(ENDPOINTS):
        peer = {"ipBlock": {"cidr": address + "/32"}}
        if peer not in covered:
            peers.append(peer)
    if peers == spec["egress"][index]["to"]:
        return []
    return [
        {"op": "test", "path": "/metadata/uid", "value": policy["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion",
         "value": policy["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec", "value": spec},
        {"op": "replace", "path": f"/spec/egress/{index}/to", "value": peers},
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--update-application", action="store_true",
                        help="also update the Argo Application Helm value (requires PyYAML)")
    args = parser.parse_args()
    base = ["kubectl", f"--kubeconfig={args.kubeconfig}", f"--server={args.server}",
            "--request-timeout=20s"]

    def get(*command):
        return json.loads(subprocess.check_output(base + list(command) + ["-o", "json"],
                                                  timeout=30))

    policy = get("-n", NAMESPACE, "get", "networkpolicy", POLICY)
    slices = get("-n", "default", "get", "endpointslice", "-l",
                 "kubernetes.io/service-name=kubernetes")
    patch = build_patch(policy, slices)
    if args.update_application:
        import yaml

        app = get("-n", "argocd", "get", "application", "heterocloud-syouyu")
        source = app["spec"]["source"]
        if source["repoURL"] != "https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Syouyu.git":
            raise ValueError("unexpected Application source")
        original = source["helm"]["values"]
        values = yaml.safe_load(original)
        cidrs = values["networkPolicy"]["kubernetesApiCidrs"]
        if "10.96.0.0/12" not in cidrs:
            raise ValueError("unexpected Application API CIDRs")
        desired = list(dict.fromkeys(cidrs + [address + "/32" for address in sorted(ENDPOINTS)]))
        if cidrs != desired:
            values["networkPolicy"]["kubernetesApiCidrs"] = desired
            app_patch = [
                {"op": "test", "path": "/metadata/resourceVersion",
                 "value": app["metadata"]["resourceVersion"]},
                {"op": "test", "path": "/spec/source", "value": source},
                {"op": "replace", "path": "/spec/source/helm/values",
                 "value": yaml.safe_dump(values, sort_keys=False)},
            ]
            print("Application API CIDRs: " + ", ".join(desired), flush=True)
            if args.apply:
                subprocess.run(base + ["-n", "argocd", "patch", "application",
                                       "heterocloud-syouyu", "--type=json", "-p",
                                       json.dumps(app_patch)], timeout=30, check=True)
                # Argo may already have reconciled the policy after the value update.
                policy = get("-n", NAMESPACE, "get", "networkpolicy", POLICY)
                patch = build_patch(policy, slices)
    if not patch:
        print("Already configured; no changes")
        return
    print(json.dumps(patch, indent=2), flush=True)
    if args.apply:
        subprocess.run(base + ["-n", NAMESPACE, "patch", "networkpolicy", POLICY,
                               "--type=json", "-p", json.dumps(patch)],
                       timeout=30, check=True)
    else:
        print("Dry run only. Review before --apply.")


if __name__ == "__main__":
    main()
