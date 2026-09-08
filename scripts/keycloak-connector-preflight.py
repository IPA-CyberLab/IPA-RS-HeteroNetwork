#!/usr/bin/env python3
"""Check private OIDC routing without credentials or changes to workloads."""

import json
import os
import subprocess
import urllib.request


def kube(*args):
    server = os.environ.get("KUBERNETES_API_SERVER")
    override = [f"--server={server}"] if server else []
    return json.loads(subprocess.check_output(
        ["kubectl", *override, "--request-timeout=10s", *args, "-o", "json"],
        timeout=15,
    ))


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    service = kube("-n", "kube-system", "get", "service", "keycloak-ha-connector")
    vip = service["spec"]["clusterIP"]
    slices = kube("-n", "kube-system", "get", "endpointslices", "-l",
                  "kubernetes.io/service-name=keycloak-ha-connector")
    ready = {endpoint.get("nodeName") for item in slices["items"]
             for endpoint in item.get("endpoints", [])
             if endpoint.get("conditions", {}).get("ready") is True}
    ready.discard(None)
    require(len(ready) >= 2, "Fewer than two ready OIDC connector nodes")
    connectors = kube("-n", "kube-system", "get", "pods", "-l",
                      "app.kubernetes.io/name=keycloak-ha-connector")
    for pod in connectors["items"]:
        if pod["metadata"].get("deletionTimestamp") or not any(
                condition["type"] == "Ready" and condition["status"] == "True"
                for condition in pod.get("status", {}).get("conditions", [])):
            continue
        config_name = next(volume["configMap"]["name"]
                           for volume in pod["spec"]["volumes"]
                           if volume["name"] == "config")
        config = kube("-n", "kube-system", "get", "configmap", config_name)
        require('"${NODE_IP}:18080"' in config["data"]["haproxy.cfg"],
                f"{pod['metadata']['name']} still routes through an edge proxy")
    for component in ("api", "owner-console"):
        pods = kube("-n", "heterocloud", "get", "pods", "-l",
                    f"app.kubernetes.io/component={component}")
        running = [pod for pod in pods["items"]
                   if not pod["metadata"].get("deletionTimestamp")]
        require(running, f"No {component} Pods")
        for pod in running:
            require(any(alias["ip"] == vip and
                        "console.heteronetwork.internal" in alias["hostnames"]
                        for alias in pod["spec"].get("hostAliases", [])),
                    f"{pod['metadata']['name']} does not use the OIDC service")
    # Retain the configured Host so Keycloak emits the correct backchannel URLs.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    path = "/realms/heterocloud/.well-known/openid-configuration"
    for _ in range(10):
        request = urllib.request.Request(
            f"http://{vip}:18079{path}",
            headers={"Host": "console.heteronetwork.internal:18079"},
        )
        with opener.open(request, timeout=5) as response:
            metadata = json.loads(response.read(262144))
        require(metadata.get("issuer") ==
                "https://heterocloud.mizuame.app/id/realms/heterocloud",
                "Unexpected public issuer")
        for field, suffix in (("token_endpoint", "protocol/openid-connect/token"),
                              ("jwks_uri", "protocol/openid-connect/certs")):
            require(metadata.get(field) ==
                    f"http://console.heteronetwork.internal:18079/realms/heterocloud/{suffix}",
                    f"Unexpected {field}")
    print(json.dumps({"ready_connector_nodes": sorted(ready),
                      "metadata_checks": 10, "result": "PASS"}))


if __name__ == "__main__":
    main()
