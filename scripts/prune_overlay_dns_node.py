#!/usr/bin/env python3
"""Remove a retired VPN address from the declared overlay DNS zone."""
import argparse
import copy
import ipaddress
import json
import subprocess


def without_address(zone, address):
    address = str(ipaddress.ip_address(address))
    result = copy.deepcopy(zone)
    if result.get("schema_version") != 1 or not isinstance(result.get("records"), dict):
        raise ValueError("unsupported overlay DNS zone")
    for name, addresses in result["records"].items():
        if not isinstance(addresses, list):
            raise ValueError("invalid DNS address list")
        filtered = [value for value in addresses if value != address]
        if addresses and not filtered:
            raise ValueError(f"removing the address would empty DNS record {name}")
        result["records"][name] = filtered
    for name, gateways in result.get("gateway_records", {}).items():
        if not isinstance(gateways, dict):
            raise ValueError("invalid gateway DNS mapping")
        gateways.pop(address, None)
        for gateway, addresses in gateways.items():
            if not isinstance(addresses, list):
                raise ValueError("invalid gateway DNS address list")
            filtered = [value for value in addresses if value != address]
            if addresses and not filtered:
                raise ValueError(f"removing the address would empty gateway DNS record {name}")
            gateways[gateway] = filtered
    result["gateway_records"] = {name: gateways for name, gateways in result.get("gateway_records", {}).items() if gateways}
    return result


def reconcile(kubectl, kubeconfig, address, apply=False):
    command = [kubectl, "--kubeconfig", kubeconfig, "-n", "heteronetwork-system"]
    obj = json.loads(subprocess.check_output(command + ["get", "configmap", "heteronetwork-overlay-dns", "-o", "json"]))
    original = obj["data"]["records.json"]
    old = json.loads(original)
    new = without_address(old, address)
    changed = new != old
    if changed and apply:
        patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": obj["metadata"]["resourceVersion"]},
                 {"op": "test", "path": "/data/records.json", "value": original},
                 {"op": "replace", "path": "/data/records.json", "value": json.dumps(new, indent=2) + "\n"}]
        result = subprocess.run(command + ["patch", "configmap", "heteronetwork-overlay-dns", "--type=json", "--patch-file=/dev/stdin"],
                                input=json.dumps(patch), text=True, capture_output=True)
        if result.returncode:
            raise ValueError("overlay DNS changed concurrently; retry the operation")
    return {"changed": changed, "applied": bool(changed and apply)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(reconcile(args.kubectl, args.kubeconfig, args.address, args.apply), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Overlay DNS retirement failed: " + str(error))
