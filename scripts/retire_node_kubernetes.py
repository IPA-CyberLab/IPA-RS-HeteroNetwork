"""Fail-closed Kubernetes cleanup for an explicitly lost node."""
import datetime
import importlib.util
import json
from pathlib import Path
import re

from retire_lost_garage_volume import delete_resources


SCRIPT = Path(__file__).with_name("reconcile-etcd-retirements.py")
SPEC = importlib.util.spec_from_file_location("retirement_etcd", SCRIPT)
ETCD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ETCD)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_objects(node, identity, replicas, attachments):
    name, address = identity["hostname"], identity["vpn_ip"]
    ETCD.validate_node(node, name, datetime.datetime.now(datetime.timezone.utc))
    require(node["metadata"].get("labels", {}).get("heteronetwork.io/lifecycle") == "stopped",
            "Kubernetes node must be marked stopped")
    require(any(item.get("type") == "InternalIP" and item.get("address") == address
                for item in node.get("status", {}).get("addresses", [])), "Kubernetes node address differs")
    expected_uid = identity.get("kubernetes_uid")
    require(not expected_uid or node["metadata"]["uid"] == expected_uid,
            "Kubernetes node was recreated since retirement began")
    remaining = [r for r in replicas if r.get("spec", {}).get("nodeID") == name]
    require(not remaining, "Longhorn replicas remain on the target node")
    remaining = [a for a in attachments if a.get("spec", {}).get("nodeName") == name]
    require(not remaining, "Kubernetes volume attachments remain on the target node")


def kubernetes_preflight(kube, kubeconfig, executor, identity):
    name, address = identity["hostname"], identity["vpn_ip"]
    require(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name), "invalid node name")
    cluster = ETCD.Cluster(kubeconfig, executor, kubectl=kube.binary)
    current = cluster.members()["members"]
    require(not any(member.get("name") == name or
                    f"https://{address}:2380" in member.get("peerURLs", []) for member in current),
            "the node is still a Kubernetes etcd voter")
    cluster.healthy(current, ETCD.survivor_endpoints(current))
    nodes = kube.get("nodes")["items"]
    target = [node for node in nodes if node["metadata"]["name"] == name]
    require(len(target) <= 1, "Kubernetes node name is ambiguous")
    replicas = kube.get("replicas.longhorn.io", "-n", "longhorn-system")["items"]
    attachments = kube.get("volumeattachments.storage.k8s.io")["items"]
    if target:
        verify_objects(target[0], identity, replicas, attachments)
        uid = target[0]["metadata"]["uid"]
    else:
        require(not any(r.get("spec", {}).get("nodeID") == name for r in replicas),
                "Longhorn replicas remain on the removed node")
        require(not any(a.get("spec", {}).get("nodeName") == name for a in attachments),
                "volume attachments remain on the removed node")
        uid = identity.get("kubernetes_uid")
    longhorn = [node for node in kube.get("nodes.longhorn.io", "-n", "longhorn-system")["items"]
                if node["metadata"]["name"] == name]
    require(len(longhorn) <= 1 and all(not node.get("spec", {}).get("allowScheduling") for node in longhorn),
            "Longhorn node is still eligible for scheduling")
    pods = [pod for pod in kube.get("pods", "-A", "--field-selector", "spec.nodeName=" + name)["items"]
            if pod.get("spec", {}).get("nodeName") == name]
    return {"node_uid": uid, "node_present": bool(target), "longhorn": longhorn,
            "pods": [{"namespace": pod["metadata"]["namespace"], "name": pod["metadata"]["name"],
                      "uid": pod["metadata"]["uid"]} for pod in pods]}


def delete_kubernetes_objects(kube, name, checked):
    resources = []
    if checked["node_present"]:
        resources.append(("/api/v1/nodes/" + name, checked["node_uid"]))
    for node in checked["longhorn"]:
        resources.append(("/apis/longhorn.io/v1beta2/namespaces/longhorn-system/nodes/" + name,
                          node["metadata"]["uid"]))
    for pod in checked["pods"]:
        resources.append(("/api/v1/namespaces/" + pod["namespace"] + "/pods/" + pod["name"], pod["uid"], 0))
    if resources:
        delete_resources(kube, resources)
    return {"node": name, "node_deleted": checked["node_present"],
            "stale_pods_deleted": len(checked["pods"]), "longhorn_node_deleted": bool(checked["longhorn"])}
