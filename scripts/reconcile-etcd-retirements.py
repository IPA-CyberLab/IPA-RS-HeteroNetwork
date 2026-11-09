#!/usr/bin/env python3
"""Retire explicitly identified stopped etcd members, with fail-closed guards.

Stopping a node alone never retires its etcd vote. The separate, reviewed
intent file identifies the exact old member and a recent verified snapshot.
This tool removes at most one member per invocation and never adds a member.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlparse

from node_lifecycle import stopped_hosts


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_intent(intent, roster):
    if intent.get("schema_version") != 1 or len(intent.get("retirements", [])) != 1:
        raise ValueError("exactly one explicit retirement is required")
    item = intent["retirements"][0]
    node = item["node"]
    if node not in stopped_hosts(roster) or node == intent["executor_node"]:
        raise ValueError("target must be explicitly stopped and different from the executor")
    peer = next((p for p in roster["peers"] if p["node_id"] == roster["hosts"].get(node)), None)
    if peer is None or item["peer_url"] != f"https://{peer['vpn_ip']}:2380":
        raise ValueError("declared peer must match the stopped node's registered VPN address")
    if not re.fullmatch(r"[0-9a-f]{1,16}", item["member_id"]):
        raise ValueError("member ID must be canonical lowercase hexadecimal")
    if not re.fullmatch(r"[0-9a-f]{64}", item["snapshot_sha256"]):
        raise ValueError("snapshot SHA-256 is invalid")
    if Path(item["snapshot_file"]).name != item["snapshot_file"] or item["snapshot_file"] in ("", ".", ".."):
        raise ValueError("snapshot must be a filename in the private backup directory")
    timestamp(item["snapshot_created_at"])
    return item


def validate_node(node, name, now):
    if node.get("metadata", {}).get("name") != name or not node.get("spec", {}).get("unschedulable"):
        raise ValueError("target Kubernetes node must be explicitly unschedulable")
    ready = [c for c in node.get("status", {}).get("conditions", []) if c.get("type") == "Ready"]
    if len(ready) != 1 or ready[0].get("status") not in ("False", "Unknown"):
        raise ValueError("target Kubernetes node must not be Ready")
    age = now - timestamp(ready[0]["lastTransitionTime"])
    if age < dt.timedelta(minutes=10):
        raise ValueError("target must have been not Ready for at least ten minutes")


def survivors_for_retirement(members, item):
    voters = members.get("members", [])
    if any(m.get("isLearner") for m in voters) or len({m["ID"] for m in voters}) != len(voters):
        raise ValueError("etcd members must be distinct voters with no learners")
    matching = [m for m in voters if m.get("name") == item["node"]
                or format(m["ID"], "x") == item["member_id"]
                or item["peer_url"] in m.get("peerURLs", [])]
    if not matching:
        return None
    if len(matching) != 1:
        raise ValueError("the retired node identity is ambiguous")
    target = matching[0]
    if (target.get("name") != item["node"] or format(target["ID"], "x") != item["member_id"]
            or target.get("peerURLs") != [item["peer_url"]]):
        raise ValueError("live member identity does not match the approved retirement")
    survivors = [m for m in voters if m["ID"] != target["ID"]]
    if len(survivors) < 3:
        raise ValueError("at least three voting members must remain")
    endpoints = []
    for member in survivors:
        urls = member.get("clientURLs", [])
        if len(urls) != 1:
            raise ValueError("each remaining voter must have exactly one client endpoint")
        url = urlparse(urls[0])
        if url.scheme != "https" or not url.hostname or url.port != 2379 or url.path:
            raise ValueError("invalid remaining etcd client endpoint")
        endpoints.append(urls[0])
    if len(set(endpoints)) != len(endpoints):
        raise ValueError("remaining etcd client endpoints are not unique")
    return survivors, endpoints


def validate_health(survivors, endpoints, statuses, health):
    ids = {m["ID"] for m in survivors}
    if len(statuses) != len(ids) or {s["Status"]["header"]["member_id"] for s in statuses} != ids:
        raise ValueError("every remaining voter must report its status")
    if {s["Endpoint"] for s in statuses} != set(endpoints):
        raise ValueError("status endpoints do not match remaining voters")
    leaders = {s["Status"]["leader"] for s in statuses}
    if len(leaders) != 1 or not leaders <= ids:
        raise ValueError("remaining voters do not agree on a surviving leader")
    if any(s["Status"].get("errors") or s["Status"].get("isLearner") for s in statuses):
        raise ValueError("a remaining voter reports an error")
    applied = [s["Status"]["raftAppliedIndex"] for s in statuses]
    if max(applied) - min(applied) > 10000:
        raise ValueError("remaining voters have not caught up")
    if {h["endpoint"] for h in health} != set(endpoints) or not all(h["health"] for h in health):
        raise ValueError("all remaining voter endpoints must be healthy")


def validate_snapshot(item, directory, now):
    age = now - timestamp(item["snapshot_created_at"])
    if age < dt.timedelta(0) or age > dt.timedelta(hours=6):
        raise ValueError("a snapshot less than six hours old is required before retirement")
    path = directory / item["snapshot_file"]
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("snapshot must be an owner-only regular file")
    if metadata.st_size < 1024 * 1024:
        raise ValueError("snapshot is unexpectedly small")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != item["snapshot_sha256"]:
        raise ValueError("snapshot checksum differs from the verified backup")


class Cluster:
    def __init__(self, kubeconfig, executor):
        self.kubeconfig, self.executor = kubeconfig, executor

    def kube(self, *args):
        result = subprocess.run(["kubectl", "--kubeconfig", self.kubeconfig,
                                 "--request-timeout=50s", *args],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError("Kubernetes operation failed: " + result.stderr[-500:])
        return result.stdout

    def etcd(self, endpoints, *args):
        return self.kube("-n", "kube-system", "exec", "etcd-" + self.executor, "--", "etcdctl",
                         "--endpoints=" + ",".join(endpoints), "--dial-timeout=3s", "--command-timeout=8s",
                         "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
                         "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt",
                         "--key=/etc/kubernetes/pki/etcd/healthcheck-client.key", *args)

    def members(self):
        return json.loads(self.etcd(["https://127.0.0.1:2379"], "member", "list", "-w", "json"))

    def healthy(self, survivors, endpoints):
        statuses = json.loads(self.etcd(endpoints, "endpoint", "status", "-w", "json"))
        health = json.loads(self.etcd(endpoints, "endpoint", "health", "-w", "json"))
        validate_health(survivors, endpoints, statuses, health)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--intent", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    intent, roster = json.loads(args.intent.read_text()), json.loads(args.roster.read_text())
    item = validate_intent(intent, roster)
    cluster = Cluster(args.kubeconfig, intent["executor_node"])
    remaining = survivors_for_retirement(cluster.members(), item)
    if remaining is None:
        print(json.dumps({"node": item["node"], "result": "already_absent"}))
        return
    survivors, endpoints = remaining
    validate_node(json.loads(cluster.kube("get", "node", item["node"], "-o", "json")), item["node"], dt.datetime.now(dt.timezone.utc))
    validate_snapshot(item, args.backup_dir, dt.datetime.now(dt.timezone.utc))
    cluster.healthy(survivors, endpoints)
    # Re-check node and member identity immediately before the membership change.
    validate_node(json.loads(cluster.kube("get", "node", item["node"], "-o", "json")), item["node"], dt.datetime.now(dt.timezone.utc))
    if survivors_for_retirement(cluster.members(), item) != remaining:
        raise ValueError("etcd membership changed during preflight")
    if args.preflight_only:
        print(json.dumps({"node": item["node"], "result": "preflight_passed", "remaining_voters": len(survivors)}))
        return
    try:
        cluster.etcd(["https://127.0.0.1:2379"], "member", "remove", item["member_id"])
    except ValueError:
        # The server can commit the change before a client timeout. Never retry
        # blindly; resolve the result by rereading membership.
        if survivors_for_retirement(cluster.members(), item) is not None:
            raise
    if survivors_for_retirement(cluster.members(), item) is not None:
        raise ValueError("retired member is still present")
    cluster.healthy(survivors, endpoints)
    print(json.dumps({"node": item["node"], "result": "retired", "remaining_voters": len(survivors)}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
