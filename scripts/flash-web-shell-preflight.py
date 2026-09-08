#!/usr/bin/env python3
"""Operator-only Flash provider check; requires kubectl, PyJWT and signing-key access.

Checks provider authorization and the WebSocket handshake, not browser cookies or
terminal rendering. A successful handshake may briefly open a diagnostic shell;
no input is sent and the connection is closed immediately.
"""

import argparse
import base64
import http.client
import json
import os
import subprocess
import time
import urllib.parse
import uuid

import jwt


def kube(*args):
    return json.loads(subprocess.check_output(
        ["kubectl", "--request-timeout=15s", *args, "-o", "json"], timeout=20
    ))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-id", type=uuid.UUID, required=True)
    parser.add_argument("--principal-id", type=uuid.UUID, required=True)
    args = parser.parse_args()
    instance = str(args.service_id)
    resource = kube("-n", "heterocloud-flash-workloads", "get", "flashservice", f"flash-{instance}")
    spec = resource["spec"]
    if resource["metadata"].get("deletionTimestamp"):
        raise SystemExit("Service is terminating; refusing diagnostic connection")
    deployment = kube("-n", "heterocloud", "get", "deployment", "heterocloud-heterocloud")
    pod_spec = deployment["spec"]["template"]["spec"]
    flags = dict(arg[2:].split("=", 1) for arg in pod_spec["containers"][0]["args"] if arg.startswith("--") and "=" in arg)
    volume = next(v["secret"] for v in pod_spec["volumes"] if v["name"] == "provider")
    key_name = next(i["key"] for i in volume["items"] if i["path"] == "ed25519-private.pem")
    secret = kube("-n", "heterocloud", "get", "secret", volume["secretName"])
    private_key = base64.b64decode(secret["data"][key_name])

    def token(action):
        now = int(time.time())
        return jwt.encode({
            "iss": flags["provider-issuer"], "aud": flags["flash-audience"],
            "sub": str(args.principal_id), "organization_id": spec["organization_id"],
            "project_id": spec["project_id"], "service_instance_id": instance,
            "generation": spec["desired_generation"], "action": action,
            "jti": str(uuid.uuid4()), "iat": now, "nbf": now - 5, "exp": now + 60,
        }, private_key, algorithm="EdDSA", headers={"kid": flags["provider-key-id"]})

    endpoints = kube("-n", "heterocloud-flash", "get", "endpointslices", "-l", "kubernetes.io/service-name=heterocloud-flash-api")
    checked = 0
    for endpoint_slice in endpoints["items"]:
        port = next(p["port"] for p in endpoint_slice["ports"] if p.get("protocol", "TCP") == "TCP")
        for endpoint in endpoint_slice["endpoints"]:
            if endpoint.get("conditions", {}).get("ready") is False:
                continue
            for address in endpoint["addresses"]:
                connection = http.client.HTTPConnection(address, port, timeout=15)
                query = urllib.parse.urlencode({"generation": spec["desired_generation"]})
                path = f"/internal/v1/service-instances/{instance}"
                try:
                    connection.request("GET", f"{path}/containers?{query}", headers={"Authorization": f"Bearer {token('flash.containers.list')}"})
                    response = connection.getresponse()
                    body = response.read(65537)
                    if response.status != 200 or len(body) > 65536:
                        raise SystemExit(f"{address}: container list HTTP {response.status}")
                    items = json.loads(body)["items"]
                finally:
                    connection.close()
                runnable = [item for item in items if item["phase"] == "Running" and item["ready"]]
                if not runnable:
                    raise SystemExit(f"{address}: no executable workload")
                for item in runnable:
                    connection = http.client.HTTPConnection(address, port, timeout=15)
                    try:
                        query = urllib.parse.urlencode({"generation": spec["desired_generation"], "pod": item["name"]})
                        connection.request("GET", f"{path}/exec?{query}", headers={
                            "Authorization": f"Bearer {token('flash.exec')}",
                            "Connection": "Upgrade", "Upgrade": "websocket",
                            "Sec-WebSocket-Version": "13",
                            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
                        })
                        response = connection.getresponse()
                        if response.status != 101:
                            raise SystemExit(f"{address}: shell handshake HTTP {response.status}")
                        print(json.dumps({"endpoint": address, "pod": item["name"], "containers_http": 200, "websocket_http": 101}))
                        checked += 1
                    finally:
                        connection.close()
    if not checked:
        raise SystemExit("No ready Flash provider endpoints")


if __name__ == "__main__":
    main()
