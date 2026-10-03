#!/usr/bin/env python3
"""Recover only the two lost Garage claims from the 2026-10-03 incident.

Dry run by default. Requires an independently copied archive of Garage-0's data
and its native metadata snapshot. Keeps Garage-0 running and retains every old
PV/Longhorn volume. Stops before changing Garage's layout: review the new node
IDs, replace the two lost IDs, and wait for replication before restoring Argo.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


NS = "heterocloud-syouyu"
NAME = "heterocloud-syouyu-garage"
OLD = {
    "data-" + NAME + "-1": "pvc-00ec0e25-f87e-4db6-b87f-f2ba1735b907",
    "meta-" + NAME + "-1": "pvc-14cdba1c-7969-47e9-9a95-32bb9ba4b212",
    "data-" + NAME + "-2": "pvc-258ed439-88ed-42f0-9f31-a4132291ae70",
    "meta-" + NAME + "-2": "pvc-df8b47c4-d7f8-4c2d-92de-cf9f86b32900",
}
WORKERS = ["ichikawap1", "uc-k8sp4", "uc-k8sp5"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    base = [args.kubectl, "--kubeconfig=" + args.kubeconfig, "--request-timeout=30s"]

    def run(*command):
        return subprocess.check_output(base + list(command), text=True, timeout=55)

    def get(kind, name, namespace=None):
        return json.loads(run("get", kind, name, *(["-n", namespace] if namespace else []), "-o", "json"))

    backup = args.backup_dir / "surviving-data.tar.gz"
    expected_hash = (args.backup_dir / "backup-sha256.txt").read_text().split()[0]
    with backup.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == expected_hash, "Backup checksum mismatch")
    with tarfile.open(backup, "r:gz") as archive:
        members = archive.getmembers()
        require(any("/snapshots/2026-10-03T06:52:58Z/db.lmdb" in m.name and m.size > 0 for m in members),
                "The consistent metadata snapshot is missing")
        require(any("pvc-dc762538-5aa6-4937-9b5f-6e26e63345b7/mount/" in m.name and m.size > 0 for m in members),
                "The surviving data blocks are missing")

    app = get("application", "heterocloud-syouyu", "argocd")
    require(not app.get("operation"), "An Argo operation is still running")
    sts = get("statefulset", NAME, NS)
    require(sts["spec"]["replicas"] == 3, "Unexpected replica count")
    retention = sts["spec"].get("persistentVolumeClaimRetentionPolicy", {})
    require(retention.get("whenScaled", "Retain") == "Retain", "Scaling would delete claims")
    survivor = get("pod", NAME + "-0", NS)
    require(survivor["status"]["phase"] == "Running" and survivor["spec"]["nodeName"] == "ichikawap1",
            "The surviving Garage node is not running on the expected host")
    records = {"application": app, "statefulset": sts, "survivor": survivor}
    for ordinal in (1, 2):
        pod = get("pod", NAME + "-" + str(ordinal), NS)
        require(pod["status"]["phase"] == "Pending" and not pod["spec"].get("nodeName"),
                "A lost pod has been scheduled; refuse to replace its claims")
    for claim, volume in OLD.items():
        pvc, pv = get("pvc", claim, NS), get("pv", volume)
        require(pvc["spec"]["volumeName"] == volume, "The claim has already changed")
        require(pv["spec"]["persistentVolumeReclaimPolicy"] == "Retain", "Old PV must have Retain policy")
        require(pv["spec"]["claimRef"]["uid"] == pvc["metadata"]["uid"], "Claim identity mismatch")
        records[claim] = pvc
        records[volume] = pv
        records[volume + "-longhorn"] = get("volumes.longhorn.io", volume, "longhorn-system")
    for worker in WORKERS:
        node = get("node", worker)
        require(any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]),
                "A destination worker is not Ready")

    print("Verified independent data backup and 4 Retain PVs; preserve Garage-0.")
    print("Replace only Pending Garage-1/2 claim bindings; schedule on " + ", ".join(WORKERS))
    if not args.apply:
        print("Dry run; no cluster changes.")
        return

    # Never overwrite the original recovery record on a subsequent invocation.
    with (args.backup_dir / "replacement-preflight.json").open("x") as stream:
        json.dump(records, stream, indent=2)
    run("patch", "application", "heterocloud-syouyu", "-n", "argocd", "--type=json", "-p", json.dumps([
        {"op": "test", "path": "/metadata/resourceVersion", "value": app["metadata"]["resourceVersion"]},
        {"op": "replace", "path": "/spec/syncPolicy/automated/enabled", "value": False},
    ]))
    run("patch", "statefulset", NAME, "-n", NS, "--type=json", "-p", json.dumps([
        {"op": "test", "path": "/metadata/resourceVersion", "value": sts["metadata"]["resourceVersion"]},
        {"op": "replace", "path": "/spec/updateStrategy", "value": {"type": "OnDelete"}},
        {"op": "replace", "path": "/spec/replicas", "value": 1},
    ]))
    for ordinal in (1, 2):
        run("wait", "--for=delete", "pod/" + NAME + "-" + str(ordinal), "-n", NS, "--timeout=45s")
    require(get("pod", NAME + "-0", NS)["metadata"]["uid"] == survivor["metadata"]["uid"], "Survivor changed")
    for claim, volume in OLD.items():
        print(run("delete", "pvc", claim, "-n", NS, "--timeout=30s").strip())
        require(get("pv", volume)["spec"]["persistentVolumeReclaimPolicy"] == "Retain", "PV was not retained")
    affinity = sts["spec"]["template"]["spec"]["affinity"]
    affinity["nodeAffinity"] = {"requiredDuringSchedulingIgnoredDuringExecution": {
        "nodeSelectorTerms": [{"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": WORKERS}]}]}}
    run("patch", "statefulset", NAME, "-n", NS, "--type=merge", "-p", json.dumps({"spec": {
        "replicas": 3, "template": {"spec": {"affinity": affinity}}}}))
    print("Fresh claims requested. Argo remains paused and Garage-0 remains untouched.")
    print("Next: replace lost Garage layout IDs, synchronize all replicas, then apply permanent GitOps values.")


if __name__ == "__main__":
    main()
