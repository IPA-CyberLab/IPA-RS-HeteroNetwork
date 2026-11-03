#!/usr/bin/env python3
"""Exercise gateway health and failover with isolated, disposable backends.

This creates an unresolvable .invalid test route and never alters a tenant
service. It needs a kubeconfig with permission to create temporary resources in
the heterocloud namespace and to port-forward an existing Envoy gateway pod.
"""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "docker.io/library/python@sha256:c900d35aba5fe4c1dc1cd358408baae2902ff2a2926a1d15cc5002c6061ddb2e"
SERVER = r'''
import http.server, os, pathlib
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        failed = self.path == '/health' and pathlib.Path('/tmp/unhealthy').exists()
        if self.path == '/health': print('health', 503 if failed else 200, flush=True)
        self.send_response(503 if failed else 200)
        self.end_headers()
        self.wfile.write(os.environ['POD_NAME'].encode())
    def log_message(self, *args): pass
http.server.ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--namespace", default="heterocloud")
    parser.add_argument("--node-a", default="ichikawap1")
    parser.add_argument("--node-b", default="uc-k8sp5")
    args = parser.parse_args()
    kubectl = [args.kubectl, "--kubeconfig", args.kubeconfig, "--request-timeout=20s"]
    namespace = args.namespace
    name = "gateway-health-e2e-" + uuid.uuid4().hex[:10]
    host = name + ".invalid"
    labels = {"e2e.heteronetwork.io/id": name}
    objects = []
    forward = None
    admin_forward = None

    def run(*parts, data=None):
        return subprocess.run(kubectl + list(parts), input=data, text=True, capture_output=True, check=True, timeout=110)

    def create(value):
        run("-n", namespace, "create", "-f", "-", data=json.dumps(value))
        objects.append((value["kind"], value["metadata"]["name"]))

    def pod(suffix, node):
        return {
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name + suffix, "labels": labels},
            "spec": {"nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "server", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                         "command": ["python3", "-u", "/test/server.py"], "ports": [{"containerPort": 8080}],
                         "env": [{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}],
                         "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}},
                         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                         "volumeMounts": [{"name": "source", "mountPath": "/test", "readOnly": True}, {"name": "tmp", "mountPath": "/tmp"}]}],
                     "volumes": [{"name": "source", "configMap": {"name": name}}, {"name": "tmp", "emptyDir": {"sizeLimit": "8Mi"}}]},
        }

    def response():
        request = urllib.request.Request("http://127.0.0.1:18193/work", headers={"Host": host})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as result:
                return result.status, result.read(256).decode()
        except urllib.error.HTTPError as error:
            return error.code, ""
        except (OSError, TimeoutError):
            return 0, ""

    def wait_for(predicate, seconds, message):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.5)
        raise RuntimeError(message)

    def health_info():
        clusters = json.load(urllib.request.urlopen("http://127.0.0.1:18194/clusters?format=json", timeout=5))
        for cluster in clusters.get("cluster_statuses", []):
            if cluster.get("name") == f"httproute/{namespace}/{name}/rule/0":
                return [host.get("health_status") for host in cluster.get("host_statuses", [])]
        return []

    try:
        policy = yaml.safe_load((ROOT / "deploy/gitops/envoy-gateway/backend-traffic-policy.yaml").read_text())["spec"]
        policy = {key: copy.deepcopy(value) for key, value in policy.items() if key in ("healthCheck", "retry", "timeout")}
        policy["targetRefs"] = [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": name}]
        policy["healthCheck"]["active"]["http"]["path"] = "/health"

        create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"server.py": SERVER}})
        create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": {"clusterIP": "None", "selector": labels, "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
        create({"apiVersion": "gateway.envoyproxy.io/v1alpha1", "kind": "Backend", "metadata": {"name": name}, "spec": {"endpoints": [{"fqdn": {"hostname": f"{name}.{namespace}.svc.cluster.local", "port": 8080}}]}})
        create(pod("-a", args.node_a))
        create({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": {"name": name}, "spec": {"parentRefs": [{"name": "heterocloud-edge", "namespace": "heterocloud-edge", "sectionName": "http"}], "hostnames": [host], "rules": [{"backendRefs": [{"group": "gateway.envoyproxy.io", "kind": "Backend", "name": name}]}]}})
        create({"apiVersion": "gateway.envoyproxy.io/v1alpha1", "kind": "BackendTrafficPolicy", "metadata": {"name": name}, "spec": policy})
        run("-n", namespace, "wait", "--for=condition=Ready", "pod/" + name + "-a", "--timeout=90s")

        pods = json.loads(run("-n", "envoy-gateway-system", "get", "pods", "-o", "json").stdout)["items"]
        gateway = next(p["metadata"]["name"] for p in pods if p["metadata"]["name"].startswith("envoy-heterocloud-edge-heterocloud-edge") and not p["metadata"].get("deletionTimestamp") and any(s.get("ready") for s in p.get("status", {}).get("containerStatuses", [])))
        forward = subprocess.Popen(kubectl + ["-n", "envoy-gateway-system", "port-forward", "pod/" + gateway, "18193:18081"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        admin_forward = subprocess.Popen(kubectl + ["-n", "envoy-gateway-system", "port-forward", "pod/" + gateway, "18194:19000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(lambda: response()[0] == 200, 90, "the isolated route did not become ready")

        run("-n", namespace, "exec", name + "-a", "--", "python3", "-c", "from pathlib import Path; Path('/tmp/unhealthy').touch()")
        injected = run("-n", namespace, "exec", name + "-a", "--", "python3", "-c", "import urllib.request, urllib.error\ntry: print(urllib.request.urlopen('http://127.0.0.1:8080/health').status)\nexcept urllib.error.HTTPError as e: print(e.code)").stdout.strip()
        if injected != "503":
            raise RuntimeError("the test backend did not enter the simulated failure")
        # Envoy may already have scheduled its first no-traffic check for up
        # to 60 seconds; require an observed failed check before accepting.
        deadline = time.monotonic() + 120
        statuses = []
        unhealthy_observed = False
        next_health_read = 0.0
        while time.monotonic() < deadline:
            statuses.append(response()[0])
            if time.monotonic() >= next_health_read:
                next_health_read = time.monotonic() + 2
                if any(item.get("failed_active_health_check") for item in health_info()):
                    unhealthy_observed = True
                    break
            time.sleep(.25)
        if not unhealthy_observed:
            raise RuntimeError("the gateway did not observe the simulated health failure")
        statuses.extend(response()[0] for _ in range(10))
        if any(status != 200 for status in statuses):
            raise RuntimeError("a temporary health failure interrupted the only backend: " + repr(statuses))
        print(json.dumps({"stage": "one_unhealthy_backend", "health": health_info()}), flush=True)

        create(pod("-b", args.node_b))
        run("-n", namespace, "wait", "--for=condition=Ready", "pod/" + name + "-b", "--timeout=90s")
        wait_for(lambda: response() == (200, name + "-b") and len(health_info()) == 2 and
                 sum(bool(item.get("failed_active_health_check")) for item in health_info()) == 1,
                 120, "the gateway did not fail over to the healthy backend")
        final = [response() for _ in range(10)]
        if any(item != (200, name + "-b") for item in final):
            print(json.dumps({"upstream_health": health_info()}), flush=True)
            config = json.load(urllib.request.urlopen("http://127.0.0.1:18194/config_dump", timeout=5))
            for section in config.get("configs", []):
                for entry in section.get("dynamic_active_clusters", []):
                    cluster = entry.get("cluster", {})
                    if cluster.get("name") == f"httproute/{namespace}/{name}/rule/0":
                        print(json.dumps({"active_checks": cluster.get("health_checks", [])}), flush=True)
            for suffix in ("-a", "-b"):
                lines = run("-n", namespace, "logs", name + suffix).stdout.splitlines()
                print(json.dumps({"test_backend": suffix, "health_ok": lines.count("health 200"), "health_failed": lines.count("health 503")}), flush=True)
            raise RuntimeError("traffic did not stay on the healthy backend: " + repr(final))
        print(json.dumps({"single_backend_requests": len(statuses), "single_backend_errors": 0,
                          "healthy_backend_failover": True, "post_failover_requests": len(final)}))
    finally:
        if forward:
            forward.terminate()
            forward.wait(timeout=10)
        if admin_forward:
            admin_forward.terminate()
            admin_forward.wait(timeout=10)
        for kind, obj in reversed(objects):
            subprocess.run(kubectl + ["-n", namespace, "delete", kind, obj, "--ignore-not-found", "--wait=false"], capture_output=True, timeout=20)


if __name__ == "__main__":
    main()
