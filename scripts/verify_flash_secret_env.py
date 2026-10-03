#!/usr/bin/env python3
"""Exercise Flash secret injection and removal with a disposable workload and value."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time
import uuid


NAMESPACE = "heterocloud-flash-workloads"
BAO_HOST = "openbao-active.openbao.svc.cluster.local"
BAO_PORT = 8200
LOCAL_PORT = 18200
SECRET_NAME = "flash-e2e-value"
ENV_NAME = "FLASH_E2E_VALUE"


def kubectl(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["kubectl", *args], input=input_text, text=True, capture_output=True, check=True
    )
    return result.stdout


class PortForwardConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        raw = socket.create_connection(("127.0.0.1", LOCAL_PORT), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=BAO_HOST)


def request(context: ssl.SSLContext, method: str, path: str,
            payload: dict | None = None, token: str | None = None) -> dict:
    connection = PortForwardConnection(BAO_HOST, BAO_PORT, context=context, timeout=10)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    connection.request(
        method, f"/v1/{path}",
        body=json.dumps(payload).encode() if payload is not None else None,
        headers=headers,
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status < 200 or response.status >= 300:
        raise RuntimeError(f"secret manager {method} {path} returned HTTP {response.status}")
    return json.loads(body) if body else {}


def wait_for_port_forward(context: ssl.SSLContext, process: subprocess.Popen, timeout: int = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("secret manager port forward exited")
        try:
            request(context, "GET", "sys/health?standbyok=true")
            return
        except (OSError, ssl.SSLError, TimeoutError):
            time.sleep(0.5)
    raise RuntimeError("secret manager port forward did not become ready")


def test_spec(service_id: str) -> dict:
    existing = json.loads(kubectl(
        "-n", NAMESPACE, "get", "flashservices", "-o", "json"
    ))["items"]
    if not existing:
        raise RuntimeError("no Flash service exists to provide a known-good tenant policy")
    baseline = existing[0]["spec"]
    workload = {
        "region": baseline["workload"]["region"],
        "image": "docker.io/library/busybox:1.36.1",
        "replicas": 1,
        "cpu_millis": 100,
        "memory_mib": 128,
        "ephemeral_storage_gib": 1,
        "ports": [],
        "exposure": {"type": "internal", "traffic_mode": "forwarded", "endpoint_mode": "ip"},
        "egress": {"mode": "disabled"},
        "env": {},
        "secret_env": {ENV_NAME: SECRET_NAME},
        "command": ["/bin/sh", "-c", "sleep 600"],
        "args": [],
        "metadata": {},
    }
    return {
        "apiVersion": "flash.heterocloud.io/v1alpha1",
        "kind": "FlashService",
        "metadata": {"name": f"flash-{service_id}", "namespace": NAMESPACE},
        "spec": {
            "desired_generation": 1,
            "display_name": "secret environment acceptance",
            "organization_id": baseline["organization_id"],
            "policy": baseline["policy"],
            "project_id": baseline["project_id"],
            "service_instance_id": service_id,
            "subject_id": baseline["subject_id"],
            "workload": workload,
        },
    }


def wait_for_pod(service_id: str, expected_generation: int = 1, timeout: int = 240) -> str:
    deadline = time.monotonic() + timeout
    selector = f"flash.heterocloud.io/instance={service_id}"
    while time.monotonic() < deadline:
        service = json.loads(kubectl(
            "-n", NAMESPACE, "get", "flashservice", f"flash-{service_id}", "-o", "json"
        ))
        status = service.get("status", {})
        if status.get("observed_generation") != expected_generation:
            time.sleep(3)
            continue
        if status.get("phase") == "error":
            raise RuntimeError(f"Flash service failed: {status.get('message', 'unknown error')}")
        pods = json.loads(kubectl(
            "-n", NAMESPACE, "get", "pods", "-l", selector, "-o", "json"
        ))["items"]
        for pod in pods:
            if pod["metadata"].get("labels", {}).get("flash.heterocloud.io/generation") != str(expected_generation):
                continue
            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", [])
            )
            if ready and status.get("phase") == "ready":
                return pod["metadata"]["name"]
        time.sleep(3)
    raise RuntimeError(f"Flash secret workload generation {expected_generation} did not become Ready within {timeout} seconds")


def main() -> int:
    service_id = str(uuid.uuid4())
    account = f"flash-{service_id.replace('-', '')}"
    value = secrets.token_hex(24)
    path = f"flash/{account}/{SECRET_NAME}"
    ca_data = json.loads(kubectl(
        "-n", "openbao", "get", "secret", "openbao-server-tls", "-o", "json"
    ))["data"]["ca.crt"]
    context = ssl.create_default_context(cadata=base64.b64decode(ca_data).decode())
    process = subprocess.Popen(
        ["kubectl", "-n", "openbao", "port-forward", "svc/openbao-active",
         f"{LOCAL_PORT}:{BAO_PORT}", "--address", "127.0.0.1"],
        env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    token = None
    created = False
    try:
        wait_for_port_forward(context, process)
        jwt = kubectl("-n", "heterocloud", "create", "token", "heterocloud-heterocloud",
                      "--duration=10m").strip()
        token = request(context, "POST", "auth/kubernetes/login", {
            "role": "heterosecrets-flash-api", "jwt": jwt
        })["auth"]["client_token"]
        request(context, "POST", f"secret/data/{path}", {"data": {"value": value}}, token)
        kubectl("apply", "-f", "-", input_text=json.dumps(test_spec(service_id)))
        created = True
        pod_name = wait_for_pod(service_id)
        deployment = kubectl("-n", NAMESPACE, "get", "deployment", f"flash-{service_id}", "-o", "json")
        if value in deployment:
            raise RuntimeError("secret value leaked into the Deployment object")
        spec = json.loads(deployment)["spec"]["template"]["spec"]
        workload = next(item for item in spec["containers"] if item["name"] == "workload")
        if workload.get("command") != ["/run/flash-helper/launcher"]:
            raise RuntimeError("workload is not launched through the environment helper")
        # kubectl exec starts a separate process with the PodSpec environment.
        # The launcher adds secrets to PID 1, so inspect that process instead.
        digest = kubectl(
            "-n", NAMESPACE, "exec", pod_name, "-c", "workload", "--", "sh", "-c",
            f"tr '\\000' '\\n' </proc/1/environ | grep '^{ENV_NAME}=' | "
            "cut -d= -f2- | tr -d '\\n' | sha256sum",
        ).split()[0]
        if digest != hashlib.sha256(value.encode()).hexdigest():
            raise RuntimeError("workload did not receive the expected environment variable")
        # Removing the last binding must replace the workload identity. Kubernetes
        # also persists the deprecated serviceAccount alias; leaving either field
        # behind can strand the rollout after the controller deletes the identity.
        kubectl("-n", NAMESPACE, "patch", "flashservice", f"flash-{service_id}",
                "--type=merge", "-p", json.dumps({"spec": {
                    "desired_generation": 2, "workload": {"secret_env": {ENV_NAME: None}}
                }}))
        replacement_name = wait_for_pod(service_id, expected_generation=2)
        if replacement_name == pod_name:
            raise RuntimeError("secret removal did not replace the workload Pod")
        replacement = json.loads(kubectl(
            "-n", NAMESPACE, "get", "pod", replacement_name, "-o", "json"
        ))["spec"]
        if replacement.get("serviceAccountName") != "default" or replacement.get("serviceAccount") != "default":
            raise RuntimeError("secret removal retained the old workload identity")
        if replacement.get("automountServiceAccountToken") is not False:
            raise RuntimeError("secret removal retained the service account token mount")
        kubectl("-n", NAMESPACE, "exec", replacement_name, "-c", "workload", "--", "sh", "-c",
                "test -r /proc/1/environ && ! tr '\\000' '\\n' </proc/1/environ | "
                f"grep -q '^{ENV_NAME}='")
        if kubectl("-n", NAMESPACE, "get", "serviceaccount", account, "--ignore-not-found").strip():
            raise RuntimeError("unused secret service account was not removed")
        print("Flash secret environment injection and removal acceptance passed")
        return 0
    finally:
        if created:
            subprocess.run(["kubectl", "-n", NAMESPACE, "delete", "flashservice",
                            f"flash-{service_id}", "--ignore-not-found", "--wait=false"],
                           text=True, capture_output=True, check=False)
        if token:
            try:
                request(context, "DELETE", f"secret/metadata/{path}", token=token)
            except (OSError, RuntimeError):
                print("warning: disposable secret cleanup failed", file=sys.stderr)
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Flash secret environment acceptance failed: {error}", file=sys.stderr)
        sys.exit(1)
