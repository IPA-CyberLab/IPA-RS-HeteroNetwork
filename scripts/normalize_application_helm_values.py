#!/usr/bin/env python3
"""Remove a legacy valuesObject override only after the declared YAML values apply.

Argo CD gives valuesObject precedence over values. SSA preserves fields owned
by older managers, so a YAML migration needs an explicit, guarded removal.
"""
import argparse
import json
from pathlib import Path
import subprocess
import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    expected = yaml.safe_load(args.manifest.read_text())
    assert expected["kind"] == "Application"
    name, namespace = expected["metadata"]["name"], expected["metadata"]["namespace"]
    source = expected["spec"]["source"]
    assert isinstance(source["helm"].get("values"), str)
    base = ["kubectl", "-n", namespace]
    actual = json.loads(subprocess.check_output(base + ["get", "application", name, "-o", "json"]))
    helm = actual["spec"]["source"]["helm"]
    assert actual["spec"]["source"]["targetRevision"] == source["targetRevision"], "revision changed concurrently"
    assert helm.get("values") == source["helm"]["values"], "declared YAML values have not applied"
    if "valuesObject" not in helm:
        print(name + ": YAML Helm values already authoritative")
        return
    patch = [
        {"op": "test", "path": "/metadata/resourceVersion", "value": actual["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec/source/helm/values", "value": source["helm"]["values"]},
        {"op": "remove", "path": "/spec/source/helm/valuesObject"},
    ]
    # Values may contain private configuration; send the patch through stdin.
    subprocess.run(base + ["patch", "application", name, "--type=json", "--patch-file=/dev/stdin"],
                   input=json.dumps(patch), text=True, check=True, stdout=subprocess.DEVNULL)
    print(name + ": removed obsolete Helm valuesObject override")


if __name__ == "__main__":
    main()
