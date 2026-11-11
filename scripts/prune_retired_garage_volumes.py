#!/usr/bin/env python3
"""Delete only retained, lost Garage volumes after their replacements are healthy."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from retire_lost_garage_volume import Kube, backup_digest, delete_resources, host_affinity, require


def prune(kube, record, backup, backup_sha256, apply=False):
    backup_digest(backup, backup_sha256)
    target, namespace, statefulset = record["node"], record["namespace"], record["statefulset"]
    for name in (target, namespace, statefulset):
        require(isinstance(name, str) and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name),
                "retirement record contains an invalid resource name")
    node = kube.get("node", target)
    require(node.get("spec", {}).get("unschedulable") and
            any(c.get("type") == "Ready" and c.get("status") in ("False", "Unknown")
                for c in node.get("status", {}).get("conditions", [])), "target node is not safely stopped")
    sts = kube.get("statefulset", statefulset, "-n", namespace)
    require(sts["status"].get("readyReplicas") == sts["spec"]["replicas"] == 3,
            "replacement Garage replicas are not all ready")
    result = subprocess.run([kube.binary, "-n", namespace, "exec", statefulset + "-0", "--",
                             "/garage", "layout", "history"], capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and "stable state with a single live layout version" in result.stdout,
            "Garage metadata layout has not finished migrating")
    replicas = kube.get("replicas.longhorn.io", "-n", "longhorn-system")["items"]
    attachments = kube.get("volumeattachments.storage.k8s.io")["items"]
    selected = []
    require(len(record["claims"]) == 2, "exactly the Garage data and metadata claims are required")
    for old in record["claims"]:
        require(re.fullmatch(r"pvc-[0-9a-f-]{36}", old["volume"]) and
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", old["claim"]),
                "retirement record contains an invalid volume name")
        pv = kube.get("pv", old["volume"])
        require(pv["metadata"]["uid"] == old["pv_uid"] and pv["status"].get("phase") == "Released" and
                pv["spec"].get("persistentVolumeReclaimPolicy") == "Retain" and
                pv["spec"]["claimRef"].get("uid") == old["uid"] and host_affinity(pv) == target,
                "retained PV no longer matches the lost claim")
        volume = kube.get("volumes.longhorn.io", old["volume"], "-n", "longhorn-system")
        require(volume["status"].get("state") == "detached" and
                volume["status"].get("robustness") == "faulted" and
                not volume["spec"].get("nodeID"), "lost Longhorn volume is not detached and faulted")
        volume_replicas = [r for r in replicas if r["spec"].get("volumeName") == old["volume"]]
        require(volume_replicas and all(r["spec"].get("nodeID") == target and
                                        r["status"].get("currentState") == "stopped"
                                        for r in volume_replicas),
                "lost volume still has a replica on another host")
        require(not any(a["spec"].get("source", {}).get("persistentVolumeName") == old["volume"]
                        for a in attachments), "a volume attachment still references the old PV")
        replacement = kube.get("pvc", old["claim"], "-n", namespace)
        require(replacement["metadata"]["uid"] != old["uid"] and
                replacement["status"].get("phase") == "Bound", "replacement claim is not bound")
        replacement_volume = kube.get("volumes.longhorn.io", replacement["spec"]["volumeName"],
                                      "-n", "longhorn-system")
        require(replacement_volume["status"].get("robustness") == "healthy" and
                replacement_volume["status"].get("state") == "attached" and
                replacement_volume["status"].get("currentNodeID") != target,
                "replacement volume is not healthy on a surviving host")
        selected.append((old, volume["metadata"]["uid"]))
    if apply:
        delete_resources(kube, [("/api/v1/persistentvolumes/" + old["volume"], old["pv_uid"])
                                for old, _ in selected])
        delete_resources(kube, [("/apis/longhorn.io/v1beta2/namespaces/longhorn-system/volumes/" + old["volume"], uid)
                                for old, uid in selected])
    return {"result": "deletion_requested" if apply else "preflight_passed",
            "node": target, "lost_volumes": len(selected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    require(args.record.is_file() and not args.record.is_symlink(), "retirement record is invalid")
    print(json.dumps(prune(Kube(args.kubectl), json.loads(args.record.read_text()),
                           args.backup, args.backup_sha256, args.apply), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit("Lost volume cleanup failed: " + str(error))
