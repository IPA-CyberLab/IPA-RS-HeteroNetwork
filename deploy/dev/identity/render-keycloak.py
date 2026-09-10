#!/usr/bin/env python3
"""Render DEV Keycloak resources without provisioning users, secrets or TLS."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import yaml


def render(origin):
    parsed = urlsplit(origin)
    hostname = parsed.hostname or ""
    if (parsed.scheme != "https" or parsed.netloc != hostname
            or parsed.path or parsed.query or parsed.fragment
            or len(hostname) > 253 or not hostname.startswith("id.dev.")
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in hostname.split("."))):
        raise ValueError("Expected an HTTPS origin with hostname id.dev.<domain>, no port or path")
    documents = list(yaml.safe_load_all(Path(__file__).with_name("keycloak.yaml").read_text()))
    site = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "dev-keycloak-site", "namespace": "hetero-dev-identity"},
            "data": {"origin": origin}}
    # Apply network isolation before creating any server Pods.
    policies = [item for item in documents if item["kind"] == "NetworkPolicy"]
    return {"apiVersion": "v1", "kind": "List", "items": [
        *policies, site, *(item for item in documents if item["kind"] != "NetworkPolicy")]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = render(args.origin)
    with args.output.open("x") as output:
        json.dump(document, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
