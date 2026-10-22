#!/usr/bin/env python3
"""Check the deployed Coder UDP grant using isolated, bounded gVisor Pods.

Copies the two live policies into a fresh namespace with new peer, organization
and VPC identities. No user workload, credential, volume or policy is changed.
"""
import argparse
import copy
import datetime
import json
import os
from pathlib import Path
import subprocess
import time
import uuid


INSTANCE = "flash.heterocloud.io/instance"
ORGANIZATION = "flash.heterocloud.io/organization"
VPC = "vpc.heterocloud.io/network"
SERVER = """
import socket,threading,time
def echo(kind):
 s=socket.socket(socket.AF_INET,kind);s.bind(('0.0.0.0',39000))
 if kind==socket.SOCK_STREAM:
  s.listen()
  while True:
   c,_=s.accept();c.sendall(b'fixture');c.close()
 else:
  while True:
   data,source=s.recvfrom(512);s.sendto(data,source)
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
 threading.Thread(target=echo,args=(kind,),daemon=True).start()
while True:time.sleep(60)
"""
PROBE = """
import json,socket,sys,uuid
kind=socket.SOCK_DGRAM if sys.argv[2]=='UDP' else socket.SOCK_STREAM
s=socket.socket(socket.AF_INET,kind);s.settimeout(1.5)
try:
 s.connect((sys.argv[1],39000))
 if kind==socket.SOCK_DGRAM:
  data=uuid.uuid4().hex.encode();s.send(data);ok=s.recv(512)==data
 else:ok=s.recv(512)==b'fixture'
except (TimeoutError,OSError):ok=False
print(json.dumps({'reachable':ok}))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--image", required=True, help="Pinned image with Python 3, cached on both workers")
    parser.add_argument("--nodes", nargs=2, default=["uc-k8sp4", "uc-k8sp5"])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if "@sha256:" not in args.image or len(set(args.nodes)) != 2:
        parser.error("Use a pinned cached image and two distinct workers")
    run = uuid.uuid4().hex
    namespace = "coder-transport-e2e-" + run[:12]
    identities = {"control": str(uuid.uuid4()), "hyperevm": str(uuid.uuid4())}
    organization, vpc = str(uuid.uuid4()), str(uuid.uuid4())
    marker = {"operations-e2e/run": run}
    command = [args.kubectl, "--kubeconfig=" + args.kubeconfig, "--request-timeout=15s"]
    report = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "result": "incomplete", "checks": [], "cleanup": {}}
    created = []

    def kube(*parts, value=None):
        result = subprocess.run(command + list(parts), input=json.dumps(value) if value is not None else None,
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("fixture_kubernetes_operation_failed")
        return json.loads(result.stdout) if result.stdout.lstrip().startswith("{") else None

    def create(value):
        value["metadata"].setdefault("labels", {}).update(marker)
        actual = kube("create", "-f", "-", "-o", "json", value=value)
        created.append((value["kind"], actual["metadata"]["name"],
                        actual["metadata"].get("namespace"), actual["metadata"]["uid"]))
        return actual

    def check(name, source, target, expected, protocol="UDP"):
        # Pod label and policy changes propagate asynchronously to node agents.
        # Every attempt opens a new flow rather than accepting conntrack state.
        deadline = time.monotonic() + 20
        matches = 0
        while time.monotonic() < deadline:
            actual = kube("-n", namespace, "exec", source, "--", "python3", "-c", PROBE, target, protocol)
            matches = matches + 1 if actual == {"reachable": expected} else 0
            if matches >= (1 if expected else 2):
                break
            time.sleep(1)
        else:
            raise RuntimeError("transport_check_failed_" + name)
        report["checks"].append({"name": name, "passed": True})
        print(json.dumps({"check": name, "passed": True}), flush=True)

    try:
        source_policies = {}
        for role in identities:
            policy = kube("-n", "heterocloud-flash-workloads", "get", "networkpolicy",
                          "coder-hyperevm-peer-" + role, "-o", "json")
            spec = policy["spec"]
            if set(spec["podSelector"]["matchLabels"]) != {INSTANCE, ORGANIZATION, VPC}:
                raise RuntimeError("unexpected_live_policy_selector")
            if set(spec["policyTypes"]) != {"Ingress", "Egress"}:
                raise RuntimeError("unexpected_live_policy_types")
            for direction, peer in [("ingress", "from"), ("egress", "to")]:
                rule, = spec[direction]
                if set(rule) != {peer, "ports"} or rule["ports"] != [{"protocol": "UDP"}]:
                    raise RuntimeError("unexpected_live_policy_ports")
                selector, = rule[peer]
                if set(selector) != {"podSelector"} or set(selector["podSelector"]["matchLabels"]) != {INSTANCE, ORGANIZATION, VPC}:
                    raise RuntimeError("unexpected_live_policy_peer")
            source_policies[role] = spec
        for node_name in args.nodes:
            node = kube("get", "node", node_name, "-o", "json")
            if node["metadata"]["labels"].get("heteronetwork.io/control-plane-only") == "true":
                raise RuntimeError("dedicated_master_forbidden")
            if not any(name.endswith(args.image.split("@")[1]) for image in node["status"]["images"] for name in image["names"]):
                raise RuntimeError("fixture_image_not_cached")
        create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": "default-deny", "namespace": namespace},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}})
        pods = {}
        for role, node in zip(identities, args.nodes):
            labels = {INSTANCE: identities[role], ORGANIZATION: organization, VPC: vpc}
            create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": role, "namespace": namespace, "labels": labels},
                    "spec": {"runtimeClassName": "gvisor", "automountServiceAccountToken": False,
                             "restartPolicy": "Never", "nodeSelector": {"kubernetes.io/hostname": node},
                             "containers": [{"name": "echo", "image": args.image, "imagePullPolicy": "Never",
                                             "command": ["python3", "-B", "-u", "-c", SERVER],
                                             "resources": {"requests": {"cpu": "25m", "memory": "64Mi", "ephemeral-storage": "32Mi"},
                                                           "limits": {"cpu": "300m", "memory": "128Mi", "ephemeral-storage": "32Mi"}},
                                             "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                                                 "capabilities": {"drop": ["ALL"]}}}]}})
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                pod = kube("-n", namespace, "get", "pod", role, "-o", "json")
                if pod.get("status", {}).get("phase") == "Running":
                    pods[role] = pod["status"]["podIP"]
                    break
                if pod.get("status", {}).get("phase") == "Failed":
                    raise RuntimeError("bounded_fixture_failed")
                time.sleep(2)
            else:
                raise RuntimeError("bounded_fixture_timed_out")
        check("default_denies_udp", "control", pods["hyperevm"], False)
        for role in identities:
            peer = next(other for other in identities if other != role)
            spec = copy.deepcopy(source_policies[role])
            spec["podSelector"] = {"matchLabels": {INSTANCE: identities[role], ORGANIZATION: organization, VPC: vpc}}
            for direction, name in [("ingress", "from"), ("egress", "to")]:
                spec[direction][0][name] = [{"podSelector": {"matchLabels": {INSTANCE: identities[peer], ORGANIZATION: organization, VPC: vpc}}}]
            create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                    "metadata": {"name": role, "namespace": namespace}, "spec": spec})
        time.sleep(3)
        check("cross_node_udp_control_to_agent", "control", pods["hyperevm"], True)
        check("cross_node_udp_agent_to_control", "hyperevm", pods["control"], True)
        check("tcp_remains_denied", "control", pods["hyperevm"], False, "TCP")
        for key, name, original in [(ORGANIZATION, "other_organization_denied", organization),
                                    (VPC, "other_vpc_denied", vpc), (INSTANCE, "other_service_denied", identities["hyperevm"])]:
            kube("-n", namespace, "label", "pod", "hyperevm", key + "=" + str(uuid.uuid4()), "--overwrite")
            time.sleep(2)
            check(name, "control", pods["hyperevm"], False)
            kube("-n", namespace, "label", "pod", "hyperevm", key + "=" + original, "--overwrite")
            time.sleep(2)
        check("grant_restored", "control", pods["hyperevm"], True)
        for role in identities:
            kube("-n", namespace, "delete", "networkpolicy", role, "--wait=true")
        time.sleep(2)
        check("revoked_grant_denies_new_flows", "control", pods["hyperevm"], False)
        report["result"] = "passed"
    except Exception as error:
        report.update(result="failed", failure=str(error) if isinstance(error, RuntimeError) else "probe_operation_failed")
    finally:
        cleaned = True
        for kind, name, ns, uid in reversed(created):
            try:
                prefix = ["-n", ns] if ns else []
                actual = kube(*prefix, "get", kind, name, "-o", "json", "--ignore-not-found=true")
                if actual:
                    if actual["metadata"]["uid"] != uid or actual["metadata"].get("labels", {}).get("operations-e2e/run") != run:
                        raise RuntimeError("foreign_resource_cleanup_refused")
                    kube(*prefix, "delete", kind, name, "--wait=false")
            except Exception:
                cleaned = False
        if cleaned:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if not kube("get", "namespace", namespace, "-o", "json", "--ignore-not-found=true"):
                    break
                time.sleep(1)
            else:
                cleaned = False
        report["cleanup"]["namespace_deletion_verified"] = cleaned
        if not cleaned:
            report["result"] = "failed"
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(report, output, indent=2)
        print(json.dumps(report), flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
