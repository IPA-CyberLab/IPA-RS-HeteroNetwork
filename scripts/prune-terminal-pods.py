#!/usr/bin/env python3
"""Remove old terminal pods and stale terminating pods from stopped nodes."""

import argparse
from collections import Counter
import datetime
import json
import re
import subprocess
import sys
import time
from urllib.parse import quote
import uuid

from node_lifecycle import stopped_hosts


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed


def stale_stopped_nodes(roster, nodes, cutoff):
    declared = stopped_hosts(roster)
    records = {n["metadata"]["name"]: n for n in nodes}
    result = set()
    for name in declared:
        node = records.get(name)
        if node is None:
            result.add(name)
            continue
        conditions = [c for c in node.get("status", {}).get("conditions", []) if c.get("type") == "Ready"]
        if len(conditions) != 1 or conditions[0].get("status") not in ("False", "Unknown"):
            continue
        try:
            if timestamp(conditions[0].get("lastTransitionTime")) <= cutoff:
                result.add(name)
        except ValueError:
            continue
    return result


def terminal_finished_at(pod):
    """Use the most recent container exit, not the pod's creation time."""
    status = pod.get("status", {})
    finished = []
    for field in ("initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"):
        for container in status.get(field, []):
            value = container.get("state", {}).get("terminated", {}).get("finishedAt")
            if value:
                try:
                    finished.append(timestamp(value))
                except ValueError:
                    return None
    return max(finished) if finished else None


def select_pods(roster, nodes, pods, cutoff):
    stopped = stale_stopped_nodes(roster, nodes, cutoff)
    selected = []
    for pod in pods:
        meta = pod.get("metadata", {})
        namespace, name, uid = meta.get("namespace", ""), meta.get("name", ""), meta.get("uid", "")
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", namespace) or not re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", name):
            continue
        try:
            if str(uuid.UUID(uid)) != uid:
                continue
            created = timestamp(meta.get("creationTimestamp"))
        except (ValueError, TypeError):
            continue
        phase = pod.get("status", {}).get("phase")
        reason = None
        finished = terminal_finished_at(pod) if phase in ("Failed", "Succeeded") else None
        if finished is not None and created <= cutoff and finished <= cutoff:
            reason = "terminal"
        elif meta.get("deletionTimestamp") and pod.get("spec", {}).get("nodeName") in stopped:
            try:
                if timestamp(meta["deletionTimestamp"]) <= cutoff:
                    reason = "stopped_node_terminating"
            except ValueError:
                pass
        if reason:
            selected.append({"namespace": namespace, "name": name, "uid": uid, "reason": reason})
    return selected


def kubectl(kubeconfig, args, *, body=None, check=True):
    command = ["kubectl", f"--kubeconfig={kubeconfig}", "--request-timeout=20s", *args]
    return subprocess.run(command, input=json.dumps(body) if body is not None else None,
                          capture_output=True, text=True, timeout=30, check=check)


def inventory(kubeconfig):
    nodes = json.loads(kubectl(kubeconfig, ["get", "nodes", "-o", "json"]).stdout)["items"]
    pods = json.loads(kubectl(kubeconfig, ["get", "pods", "-A", "-o", "json"]).stdout)["items"]
    return nodes, pods


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--roster", required=True)
    parser.add_argument("--older-than-hours", type=int, default=24)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.older_than_hours <= 720:
        raise ValueError("age must be between 1 and 720 hours")
    with open(args.roster, encoding="utf-8") as source:
        roster = json.load(source)
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=args.older_than_hours)
    nodes, pods = inventory(args.kubeconfig)
    selected = select_pods(roster, nodes, pods, cutoff)
    counts = dict(Counter(item["reason"] for item in selected))
    report = {"selected": len(selected), "by_reason": counts, "applied": args.apply}
    if not args.apply:
        print(json.dumps(report, sort_keys=True))
        return 0
    failed = 0
    for item in selected:
        path = "/api/v1/namespaces/{}/pods/{}".format(
            quote(item["namespace"], safe=""), quote(item["name"], safe=""))
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0,
                   "preconditions": {"uid": item["uid"]}}
        result = kubectl(args.kubeconfig, ["delete", "--raw", path, "-f", "-"], body=options, check=False)
        if result.returncode:
            failed += 1
        time.sleep(0.05)
    _, after = inventory(args.kubeconfig)
    remaining_ids = {p.get("metadata", {}).get("uid") for p in after}
    remaining = sum(item["uid"] in remaining_ids for item in selected)
    report.update({"removed_or_already_gone": len(selected) - remaining,
                   "remaining": remaining, "request_errors": failed})
    print(json.dumps(report, sort_keys=True))
    return 1 if remaining else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"pod cleanup failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
