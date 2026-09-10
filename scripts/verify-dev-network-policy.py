#!/usr/bin/env python3
"""Bounded TCP NetworkPolicy gate for the dedicated three-node dev cluster."""
import argparse
import ipaddress
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path


NODES = {f"hetero-dev-{i}": f"10.251.0.{i}" for i in range(1, 4)}
LABEL = {"app": "dev-policy-probe"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guard(system, nodes, expected_uid):
    require(system["metadata"]["uid"] == expected_uid, "cluster UID mismatch")
    items = nodes["items"]
    require(len(items) == 3 and {n["metadata"]["name"] for n in items} == set(NODES),
            "unexpected node inventory")
    networks = []
    for node in items:
        name = node["metadata"]["name"]
        require(any(c["type"] == "Ready" and c["status"] == "True"
                    for c in node["status"].get("conditions", [])), "node not Ready")
        require([a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"]
                == [NODES[name]], "unexpected node address")
        cidr = ipaddress.ip_network(node["spec"]["podCIDR"])
        require(cidr.version == 4 and cidr.prefixlen == 24
                and cidr.subnet_of(ipaddress.ip_network("172.29.0.0/16")), "unexpected Pod CIDR")
        require(node["spec"].get("podCIDRs", [str(cidr)]) == [str(cidr)], "unexpected Pod CIDRs")
        require(not any(cidr.overlaps(other) for other in networks), "overlapping Pod CIDRs")
        networks.append(cidr)


def manifests(namespace, image):
    require(bool(re.fullmatch(r"(?:[a-z0-9][a-z0-9._-]*/)*busybox@sha256:[0-9a-f]{64}", image)),
            "immutable BusyBox image required")
    metadata = {"name": "probe", "namespace": namespace}
    return [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata,
         "data": {"index.html": "ok\n"}},
        {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": metadata,
         "spec": {"selector": {"matchLabels": LABEL}, "template": {
             "metadata": {"labels": LABEL}, "spec": {
                 "automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
                     "nodeSelectorTerms": [{"matchExpressions": [{"key": "kubernetes.io/hostname",
                         "operator": "In", "values": sorted(NODES)}]}]}}},
                 "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"}],
                 "containers": [{"name": "http", "image": image,
                     "command": ["/bin/busybox", "httpd", "-f", "-p", "8080", "-h", "/www"],
                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                         "capabilities": {"drop": ["ALL"]}},
                     "resources": {"requests": {"cpu": "10m", "memory": "8Mi"},
                                   "limits": {"cpu": "100m", "memory": "32Mi"}},
                     "readinessProbe": {"tcpSocket": {"port": 8080}, "periodSeconds": 2},
                     "volumeMounts": [{"name": "www", "mountPath": "/www", "readOnly": True}]}],
                 "volumes": [{"name": "www", "configMap": {"name": "probe"}}]}}}}
    ]


def policy(namespace, name, direction, allow=False):
    rule = {"from": [{"podSelector": {"matchLabels": LABEL}}],
            "ports": [{"protocol": "TCP", "port": 8080}]}
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"podSelector": {"matchLabels": LABEL}, "policyTypes": [direction],
                     direction.lower(): [rule] if allow else []}}


class Gate:
    def __init__(self, kubeconfig, expected_uid, image):
        self.kubeconfig, self.expected_uid, self.image = kubeconfig, expected_uid, image
        self.namespace = "dev-policy-" + uuid.uuid4().hex
        self.owner = uuid.uuid4().hex
        self.uid = None
        self.pods = []
        self.phase_deadline = None

    def kubectl(self, *args, data=None, timeout=25):
        if self.phase_deadline is not None:
            remaining = self.phase_deadline - time.monotonic()
            require(remaining > 0, "policy convergence deadline exceeded")
            timeout = min(timeout, remaining)
        return subprocess.run(["kubectl", "--kubeconfig", self.kubeconfig, "--request-timeout=15s", *args],
                              input=json.dumps(data) if data is not None else None,
                              capture_output=True, text=True, timeout=timeout, check=False)

    def checked(self, *args, data=None, timeout=25):
        result = self.kubectl(*args, data=data, timeout=timeout)
        require(result.returncode == 0, "kubectl operation failed: " + args[0])
        return result.stdout

    def get(self, *args):
        return json.loads(self.checked("get", *args, "-o", "json"))

    def apply(self, value):
        self.checked("apply", "-f", "-", data=value)

    def cleanup(self):
        if self.uid is None:
            return
        current = self.get("namespace", self.namespace)
        require(current["metadata"]["uid"] == self.uid and
                current["metadata"].get("labels", {}).get("dev-policy-owner") == self.owner,
                "cleanup ownership mismatch")
        self.checked("delete", "--raw", "/api/v1/namespaces/" + self.namespace, "-f", "-",
                     data={"apiVersion": "v1", "kind": "DeleteOptions",
                           "preconditions": {"uid": self.uid}, "propagationPolicy": "Foreground"})
        self.checked("wait", "--for=delete", "namespace/" + self.namespace, "--timeout=90s", timeout=100)

    def check_pods(self):
        items = self.get("pods", "-n", self.namespace)["items"]
        require(len(items) == 3 and {p["spec"]["nodeName"] for p in items} == set(NODES),
                "unexpected probe placement")
        for pod in items:
            require(not pod["metadata"].get("deletionTimestamp") and
                    any(c["type"] == "Ready" and c["status"] == "True"
                        for c in pod["status"].get("conditions", [])), "probe not Ready")
            require(ipaddress.ip_address(pod["status"]["podIP"]) in ipaddress.ip_network("172.29.0.0/16"),
                    "unexpected probe address")
        identities = sorted((p["metadata"]["name"], p["metadata"]["uid"], p["status"]["podIP"]) for p in items)
        if self.pods:
            require(identities == self.pods, "probe identities changed")
        self.pods = identities

    def sample(self):
        self.check_pods()
        results = []
        for source, _, _ in self.pods:
            require(self.checked("exec", "-n", self.namespace, source, "-c", "http", "--",
                    "/bin/busybox", "wget", "-T", "2", "-q", "-O", "-",
                    "http://127.0.0.1:8080/").strip() == "ok", "local HTTP server unavailable")
            for destination, _, address in self.pods:
                if source == destination:
                    continue
                # The exec itself must succeed: transport/RBAC failures are not policy denials.
                output = self.checked("exec", "-n", self.namespace, source, "-c", "http", "--",
                    "/bin/sh", "-c",
                    'r=$(/bin/busybox wget -T 2 -q -O - "$1" 2>/dev/null); s=$?; '
                    'if [ "$s" = 0 ] && [ "$r" = ok ]; then echo allowed; '
                    'elif [ "$s" != 0 ]; then echo denied; else echo invalid; fi',
                    "probe", "http://" + address + ":8080/")
                require(output.strip() in ("allowed", "denied"), "unexpected HTTP response")
                results.append(output.strip())
        self.check_pods()
        return results

    def converge(self, allowed):
        self.phase_deadline = time.monotonic() + 120
        consecutive = 0
        try:
            while time.monotonic() < self.phase_deadline:
                results = self.sample()
                consecutive = consecutive + 1 if results == ["allowed" if allowed else "denied"] * 6 else 0
                if consecutive == 2:
                    return {"directed_checks": 6, "result": "allowed" if allowed else "denied", "consecutive_samples": 2}
                time.sleep(min(2, max(0, self.phase_deadline - time.monotonic())))
            raise ValueError("policy convergence deadline exceeded")
        finally:
            self.phase_deadline = None

    def run(self):
        guard(self.get("namespace", "kube-system"), self.get("nodes"), self.expected_uid)
        resources = manifests(self.namespace, self.image)
        evidence = {}
        try:
            try:
                created = json.loads(self.checked("create", "-f", "-", "-o", "json", data={
                    "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.namespace,
                        "labels": {"dev-policy-owner": self.owner, "pod-security.kubernetes.io/enforce": "restricted"}}}))
                self.uid = created["metadata"]["uid"]
            except Exception:
                # A timed-out create may have committed. Recover ownership, never adopt by name alone.
                current = self.get("namespace", self.namespace)
                if current["metadata"].get("labels", {}).get("dev-policy-owner") == self.owner:
                    self.uid = current["metadata"]["uid"]
                raise
            for resource in resources:
                self.apply(resource)
            self.checked("rollout", "status", "daemonset/probe", "-n", self.namespace,
                         "--timeout=180s", timeout=190)
            evidence["baseline"] = self.converge(True)
            self.apply(policy(self.namespace, "deny-ingress", "Ingress"))
            evidence["ingress_deny"] = self.converge(False)
            self.apply(policy(self.namespace, "allow-ingress", "Ingress", True))
            evidence["ingress_allow"] = self.converge(True)
            self.apply(policy(self.namespace, "deny-egress", "Egress"))
            evidence["egress_deny"] = self.converge(False)
            self.checked("delete", "networkpolicy/deny-egress", "-n", self.namespace, "--wait=false")
            evidence["egress_restore"] = self.converge(True)
        finally:
            self.cleanup()
        return {"ok": True, "cluster_uid": self.expected_uid, "namespace_uid": self.uid,
                "image": self.image, "phases": evidence, "cleanup": "complete"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-kube-system-uid", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    require(Path(args.kubeconfig).is_absolute() and Path(args.kubeconfig).is_file(), "explicit absolute kubeconfig required")
    gate = Gate(args.kubeconfig, args.expected_kube_system_uid, args.image)
    try:
        print(json.dumps(gate.run(), sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"ok": False, "namespace": gate.namespace, "namespace_uid": gate.uid,
                          "error": str(error) if isinstance(error, ValueError) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
