#!/usr/bin/env python3
"""Operator-only, bounded Flash provider autoscaling smoke test.

Creates ONE disposable FlashService (at most 2 x 100m CPU / 64Mi RAM / 1Gi disk)
and cleans it up in finally. Never targets an existing service. This exercises
the CRD/controller/HPA, not HeteroCloud authentication or account quota checks.
Run only after the matching Flash controller and Metrics Server are deployed.
"""

import argparse
import json
import os
import subprocess
import time
import uuid


def kube(*args, body=None):
    server = os.environ.get("KUBERNETES_API_SERVER")
    override = [f"--server={server}"] if server else []
    return subprocess.check_output(
        ["kubectl", *override, "--request-timeout=15s", *args],
        input=None if body is None else json.dumps(body).encode(), timeout=20,
    )


def get(*args):
    return json.loads(kube(*args, "-o", "json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-port", required=True, type=int)
    parser.add_argument("--timeout", type=int, default=720)
    args = parser.parse_args()
    if not 30000 <= args.service_port <= 32767 or not 60 <= args.timeout <= 1200:
        parser.error("service-port must be 30000..32767 and timeout 60..1200 seconds")
    namespace = "heterocloud-flash-workloads"
    for service in get("-n", namespace, "get", "services")["items"]:
        if any(p["port"] == args.service_port for p in service["spec"].get("ports", [])):
            parser.error("requested test port is already in use")
    identifier = str(uuid.uuid4())
    name = f"flash-{identifier}"
    # Each replica burns <=100m for 150 seconds, then idles. HTTP serves only
    # the Pod hostname; it exposes no command or load-control API.
    command = """import http.server, multiprocessing, socket, time
def load():
    end = time.monotonic() + 150
    while time.monotonic() < end:
        sum(i*i for i in range(10000))
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (socket.gethostname() + '\\n').encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
if __name__ == '__main__':
    multiprocessing.Process(target=load).start()
    http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"""
    resource = {
        "apiVersion": "flash.heterocloud.io/v1alpha1", "kind": "FlashService",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"test.heterocloud.io/purpose": "autoscaling-e2e"}},
        "spec": {
            "service_instance_id": identifier, "organization_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()), "display_name": "disposable-autoscaling-e2e",
            "desired_generation": 1,
            "workload": {
                "region": "heteronet-global", "image": "python:3.12-alpine",
                "replicas": 1, "cpu_millis": 100, "memory_mib": 64,
                "ephemeral_storage_gib": 1,
                "autoscaling": {"min_replicas": 1, "max_replicas": 2,
                                "target_cpu_utilization_percent": 30,
                                "target_memory_utilization_percent": 90},
                "ports": [{"name": "http", "protocol": "tcp", "container_port": 8080,
                           "service_port": args.service_port}],
                "exposure": {"type": "public", "traffic_mode": "forwarded",
                             "endpoint_mode": "load_balancer"},
                "command": ["python3", "-u", "-c"], "args": [command],
            },
        },
    }
    # A unique UUID makes the finally deletion safe even if create times out.
    try:
        kube("create", "-f", "-", body=resource)
        print(json.dumps({"created": name, "service_port": args.service_port}), flush=True)
        deadline = time.monotonic() + args.timeout
        scaled_up = False
        while time.monotonic() < deadline:
            flash = get("-n", namespace, "get", "flashservice", name)
            deployments = get("-n", namespace, "get", "deployment", "-l",
                              f"flash.heterocloud.io/instance={identifier}")["items"]
            if deployments:
                deployment = deployments[0]
                desired = deployment["spec"].get("replicas", 1)
                ready = deployment.get("status", {}).get("readyReplicas", 0)
                if desired > 2:
                    raise SystemExit("FAIL: autoscaler exceeded max_replicas")
                scaled_up = scaled_up or (desired == 2 and ready == 2)
                print(json.dumps({"desired": desired, "ready": ready,
                                  "phase": flash.get("status", {}).get("phase"),
                                  "endpoints": flash.get("status", {}).get("endpoints", [])}), flush=True)
                if scaled_up and desired == 1 and ready == 1:
                    hpa = get("-n", namespace, "get", "hpa", name)
                    if not any(c["type"] == "ScalingActive" and c["status"] == "True"
                               for c in hpa.get("status", {}).get("conditions", [])):
                        raise SystemExit("FAIL: HPA did not remain active")
                    print("PASS: scale-out 1->2 and stabilized scale-in 2->1", flush=True)
                    return
            time.sleep(10)
        raise SystemExit("FAIL: scale-out and scale-in did not complete before timeout")
    finally:
        kube("-n", namespace, "delete", "flashservice", name,
             "--ignore-not-found", "--wait=false")
        print(json.dumps({"cleanup_requested": name}), flush=True)


if __name__ == "__main__":
    main()
