#!/usr/bin/env python3
"""Replace claims for one lost Garage ordinal without deleting surviving data.

The old PVs are retained.  A verified metadata backup, exact claim/PV identity,
lost-node affinity, faulted Longhorn volumes and healthy surviving Garage pods
are required before any change.  The StatefulSet is restored to its original
replica count even if claim deletion fails.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request
import yaml


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Kube:
    def __init__(self, binary):
        self.binary = binary

    def command(self, *args, payload=None):
        result = subprocess.run([self.binary, *args], input=payload, text=True,
                                capture_output=True, timeout=45)
        if result.returncode:
            raise ValueError("Kubernetes operation failed: " + result.stderr[-350:])
        return result.stdout

    def get(self, *args):
        return json.loads(self.command("get", *args, "-o", "json"))

    def patch(self, namespace, resource, name, patch):
        self.command("-n", namespace, "patch", resource, name, "--type=json",
                     "--patch-file=/dev/stdin", payload=json.dumps(patch))


def host_affinity(pv):
    terms = pv.get("spec", {}).get("nodeAffinity", {}).get("required", {}).get("nodeSelectorTerms", [])
    hosts = []
    for term in terms:
        expressions = term.get("matchExpressions", [])
        require(len(expressions) == 1 and expressions[0].get("key") == "kubernetes.io/hostname"
                and expressions[0].get("operator") == "In", "PV affinity is not a single-host constraint")
        hosts += expressions[0].get("values", [])
    require(len(hosts) == 1, "PV must be pinned to exactly one host")
    return hosts[0]


def validate_claim(pvc, pv, volume, namespace, claim, target):
    require(pvc["metadata"]["name"] == claim and pvc["metadata"]["namespace"] == namespace,
            "unexpected claim identity")
    uid = pvc["metadata"]["uid"]
    name = pvc["spec"]["volumeName"]
    require(pv["metadata"]["name"] == name and
            pv["spec"]["claimRef"].get("uid") == uid and
            pv["spec"]["claimRef"].get("name") == claim and
            pv["spec"]["claimRef"].get("namespace") == namespace,
            "PV does not belong to the expected claim")
    require(pv["spec"].get("persistentVolumeReclaimPolicy") == "Retain",
            "old storage must be retained while replacement is verified")
    require(host_affinity(pv) == target, "PV is not pinned to the lost node")
    require(pv["spec"].get("csi", {}).get("driver") == "driver.longhorn.io" and
            pv["spec"].get("csi", {}).get("volumeHandle") == name,
            "PV is not the matching Longhorn volume")
    require(volume["metadata"]["name"] == name and
            volume.get("status", {}).get("state") == "detached" and
            volume.get("status", {}).get("robustness") == "faulted",
            "the old Longhorn volume is not detached and faulted")
    return {"claim": claim, "uid": uid, "volume": name, "pv_uid": pv["metadata"]["uid"]}


def backup_digest(path, expected):
    info = path.lstat()
    require(path.is_file() and not path.is_symlink() and info.st_uid == os.geteuid() and
            info.st_mode & 0o077 == 0 and info.st_size > 1024,
            "metadata backup must be a nonempty owner-only regular file")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    require(digest.hexdigest() == expected, "metadata backup checksum differs")


def delete_resources(kube, resources):
    # kubectl proxy handles the operator's TLS credentials; DeleteOptions
    # enforce that no claim recreated under the same name can be deleted.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([kube.binary, "proxy", f"--port={port}", "--address=127.0.0.1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            require(process.poll() is None, "Kubernetes proxy failed to start")
            try:
                with urllib.request.urlopen(base + "/version", timeout=1):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise ValueError("Kubernetes proxy did not start")
        for resource in resources:
            path, uid, *options = resource
            delete_options = {"apiVersion": "v1", "kind": "DeleteOptions",
                              "preconditions": {"uid": uid}}
            if options:
                delete_options["gracePeriodSeconds"] = options[0]
            body = json.dumps(delete_options).encode()
            req = urllib.request.Request(base + path, method="DELETE", data=body,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=15):
                    pass
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    try:
                        detail = json.loads(error.read(65536))
                        reason = detail.get("message", detail.get("reason", "request rejected"))
                    except (ValueError, OSError):
                        reason = "request rejected"
                    raise ValueError(f"Kubernetes could not delete {path}: {reason}") from error
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def delete_claims(kube, namespace, claims):
    delete_resources(kube, [(f"/api/v1/namespaces/{namespace}/persistentvolumeclaims/{claim['claim']}",
                             claim["uid"]) for claim in claims])


def recover(kube, namespace, statefulset, ordinal, target, backup, expected_sha,
            application, apply=False):
    backup_digest(backup, expected_sha)
    node = kube.get("node", target)
    require(node.get("spec", {}).get("unschedulable") and
            any(c.get("type") == "Ready" and c.get("status") in ("False", "Unknown")
                for c in node.get("status", {}).get("conditions", [])),
            "target must be cordoned and not Ready")
    app = kube.get("application", application, "-n", "argocd")
    values = yaml.safe_load(app["spec"]["source"]["helm"]["values"])
    require(values.get("layoutBootstrap", {}).get("enabled") is False,
            "the declared Garage layout bootstrap must be paused")
    jobs = kube.get("jobs", "-n", namespace, "-l", "app.kubernetes.io/component=layout-bootstrap")
    require(not jobs["items"], "a Garage layout bootstrap job is still present")
    sts = kube.get("statefulset", statefulset, "-n", namespace)
    count = sts["spec"]["replicas"]
    require(count >= 3 and ordinal == count - 1, "only the last Garage ordinal may be replaced")
    require(sts["spec"].get("updateStrategy", {}).get("type") == "OnDelete",
            "Garage must use OnDelete during recovery so healthy replicas do not roll")
    name = f"{statefulset}-{ordinal}"
    pod = kube.get("pod", name, "-n", namespace)
    require(not pod["spec"].get("nodeName") and pod["status"].get("phase") == "Pending",
            "lost ordinal must be unscheduled and pending")
    for i in range(ordinal):
        survivor = kube.get("pod", f"{statefulset}-{i}", "-n", namespace)
        require(survivor["spec"].get("nodeName") != target and
                any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in survivor.get("status", {}).get("conditions", [])),
                "all surviving Garage replicas must be ready")
    claims = []
    for prefix in ("data", "meta"):
        claim = f"{prefix}-{name}"
        pvc = kube.get("pvc", claim, "-n", namespace)
        pv = kube.get("pv", pvc["spec"]["volumeName"])
        volume = kube.get("volumes.longhorn.io", pv["metadata"]["name"], "-n", "longhorn-system")
        claims.append(validate_claim(pvc, pv, volume, namespace, claim, target))
    pods = kube.get("pods", "-n", namespace)["items"]
    for other in pods:
        if other["metadata"]["name"] == name:
            continue
        referenced = {v.get("persistentVolumeClaim", {}).get("claimName")
                      for v in other.get("spec", {}).get("volumes", [])}
        require(not referenced.intersection(c["claim"] for c in claims),
                "another pod references a lost claim")
    result = {"node": target, "ordinal": ordinal, "claims": claims,
              "result": "preflight_passed"}
    if not apply:
        return result
    uid = sts["metadata"]["uid"]
    kube.patch(namespace, "statefulset", statefulset, [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/spec/replicas", "value": count},
        {"op": "replace", "path": "/spec/replicas", "value": ordinal}])
    try:
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            current = kube.get("pods", "-n", namespace)["items"]
            if all(p["metadata"]["name"] != name for p in current):
                break
            time.sleep(1)
        else:
            raise ValueError("pending ordinal did not terminate; claims were not deleted")
        live = kube.get("statefulset", statefulset, "-n", namespace)
        require(live["metadata"]["uid"] == uid and live["spec"]["replicas"] == ordinal,
                "StatefulSet changed while preparing claim replacement")
        for claim in claims:
            pvc = kube.get("pvc", claim["claim"], "-n", namespace)
            require(pvc["metadata"]["uid"] == claim["uid"], "claim identity changed during recovery")
        for i in range(ordinal):
            survivor = kube.get("pod", f"{statefulset}-{i}", "-n", namespace)
            require(any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in survivor.get("status", {}).get("conditions", [])),
                    "a surviving Garage replica became unavailable")
        delete_claims(kube, namespace, claims)
    finally:
        live = kube.get("statefulset", statefulset, "-n", namespace)
        if live["metadata"]["uid"] == uid and live["spec"]["replicas"] == ordinal:
            kube.patch(namespace, "statefulset", statefulset, [
                {"op": "test", "path": "/metadata/uid", "value": uid},
                {"op": "test", "path": "/spec/replicas", "value": ordinal},
                {"op": "replace", "path": "/spec/replicas", "value": count}])
    result["result"] = "claims_retired_retaining_old_volumes"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--statefulset", required=True)
    parser.add_argument("--ordinal", required=True, type=int)
    parser.add_argument("--target", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(recover(Kube(args.kubectl), args.namespace, args.statefulset,
                             args.ordinal, args.target, args.backup,
                             args.backup_sha256, args.application, args.apply), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, urllib.error.URLError) as error:
        raise SystemExit("Garage replacement failed: " + str(error))
