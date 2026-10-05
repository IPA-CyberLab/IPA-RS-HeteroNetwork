#!/usr/bin/env python3
"""Configure the strategy omitted by the upstream Envoy Gateway Helm chart.

Only the named controller Deployment's strategy is changed. Its image, Pod
template, replicas and data-plane Deployments remain managed by Argo CD.
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
    app = yaml.safe_load(args.manifest.read_text())
    assert app["metadata"]["name"] == "envoy-gateway"
    assert app["spec"]["destination"]["namespace"] == "envoy-gateway-system"
    values = yaml.safe_load(app["spec"]["source"]["helm"]["values"])
    assert values["deployment"]["replicas"] == 3
    assert values["podDisruptionBudget"]["minAvailable"] == 2
    strategy = {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 1}}
    base = ["kubectl", "-n", "envoy-gateway-system"]
    for attempt in range(8):
        deployment = json.loads(subprocess.check_output(base + ["get", "deployment", "envoy-gateway", "-o", "json"]))
        spec = deployment["spec"]
        assert spec["replicas"] == 3
        assert spec["selector"]["matchLabels"]["control-plane"] == "envoy-gateway"
        assert spec["template"]["spec"]["containers"][0]["image"].endswith(":" + app["spec"]["source"]["targetRevision"])
        if spec["strategy"] == strategy:
            print("Envoy Gateway rollout strategy already reconciled")
            return
        patch = [
            {"op": "test", "path": "/metadata/resourceVersion", "value": deployment["metadata"]["resourceVersion"]},
            {"op": "replace", "path": "/spec/strategy", "value": strategy},
        ]
        result = subprocess.run(base + ["patch", "deployment", "envoy-gateway", "--type=json", "--patch-file=/dev/stdin"],
                                input=json.dumps(patch), text=True, capture_output=True)
        if result.returncode == 0:
            print("Envoy Gateway rollout permits one unavailable controller and retains two")
            return
        time.sleep(0.5 * (attempt + 1))
    raise RuntimeError("Guarded Envoy Gateway strategy reconciliation failed")


if __name__ == "__main__":
    main()
