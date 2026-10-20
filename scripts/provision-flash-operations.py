#!/usr/bin/env python3
"""Reconcile the explicitly selected worker's disposable restore-verification tag."""
import argparse
import json
import subprocess


def kubectl(*args):
    return json.loads(subprocess.check_output(
        ["kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", *args], text=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    node = kubectl("get", "node", args.node, "-o", "json")
    if node["metadata"].get("labels", {}).get("heteronetwork.io/control-plane-only") == "true":
        raise SystemExit("A dedicated master cannot host backup verification")
    if not any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]):
        raise SystemExit("Verification worker must be Ready")
    storage = kubectl("-n", "longhorn-system", "get", "nodes.longhorn.io", args.node, "-o", "json")
    if not storage.get("spec", {}).get("allowScheduling"):
        raise SystemExit("Verification storage node must allow scheduling")
    tags = set(storage["spec"].get("tags", []))
    changed = "flash-backup-verification" not in tags
    if changed:
        tags.add("flash-backup-verification")
        kubectl("-n", "longhorn-system", "patch", "nodes.longhorn.io", args.node, "--type=merge", "-p",
                json.dumps({"metadata": {"resourceVersion": storage["metadata"]["resourceVersion"]},
                            "spec": {"tags": sorted(tags)}}), "-o", "json")
    print(json.dumps({"configured": True, "worker": args.node, "changed": changed,
                      "existing_workloads_modified": False}))


if __name__ == "__main__":
    main()
