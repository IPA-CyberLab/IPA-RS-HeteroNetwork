#!/usr/bin/env python3
"""Remove a legacy valuesObject override only after the declared YAML values apply.

Argo CD gives valuesObject precedence over values. SSA preserves fields owned
by older managers, so a YAML migration needs an explicit, guarded removal.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
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
    # Argo CD also writes status and changes resourceVersion during a sync.
    # Re-read and re-check the declared revision on every bounded retry.
    for attempt in range(8):
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
        result = subprocess.run(base + ["patch", "application", name, "--type=json", "--patch-file=/dev/stdin"],
                                input=json.dumps(patch), text=True, capture_output=True)
        if result.returncode == 0:
            print(name + ": removed obsolete Helm valuesObject override")
            return
        time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(name + ": guarded Helm values migration failed after retries")


if __name__ == "__main__":
    main()
