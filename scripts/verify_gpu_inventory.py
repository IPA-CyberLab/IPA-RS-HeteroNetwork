#!/usr/bin/env python3
"""Verify the protected Flash GPU inventory without printing physical IDs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid


PRESENT_LABEL = "nvidia.com/gpu.present"
COUNT_LABEL = "flash.heterocloud.io/gpu-count"
TYPE_LABEL = "flash.heterocloud.io/gpu-type"
MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
INVENTORY_NODE_LABEL = "flash.heterocloud.io/inventory-node"
INVENTORY_API = "flashgpudevices.flash.heterocloud.io"
GPU_UUID = re.compile(r"^GPU-[A-Za-z0-9][A-Za-z0-9-]{15,127}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], text=True, capture_output=True, check=True)


def get_json(*args: str) -> dict:
    return json.loads(run(*args, "-o", "json").stdout)


def hashed_name(physical_id: str) -> str:
    return "gpu-" + hashlib.sha256(physical_id.encode()).hexdigest()[:16]


def parse_counts(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        name, separator, raw_count = value.partition("=")
        if not separator or not name or not raw_count.isdigit() or int(raw_count) < 1:
            raise ValueError(f"invalid --require-node value: {value!r}")
        result[name] = int(raw_count)
    return result


def parse_types(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, gpu_type = value.partition("=")
        if not separator or not name or not DNS_LABEL.fullmatch(gpu_type):
            raise ValueError(f"invalid --require-type value: {value!r}")
        result[name] = gpu_type
    return result


def validate_snapshot(
    nodes_document: dict,
    inventory_document: dict,
    required_counts: dict[str, int],
    required_types: dict[str, str],
) -> dict[str, dict]:
    gpu_nodes: dict[str, dict] = {}
    for node in nodes_document.get("items", []):
        metadata = node.get("metadata", {})
        labels = metadata.get("labels", {})
        if labels.get(PRESENT_LABEL) == "true":
            name = metadata.get("name", "")
            raw_count = labels.get(COUNT_LABEL, "")
            gpu_type = labels.get(TYPE_LABEL, "")
            if not name or not raw_count.isdigit() or int(raw_count) < 1:
                raise RuntimeError("a GPU node has invalid count metadata")
            if not DNS_LABEL.fullmatch(gpu_type):
                raise RuntimeError(f"{name} has invalid GPU type metadata")
            gpu_nodes[name] = {"declared_count": int(raw_count), "gpu_type": gpu_type}

    physical_ids: set[str] = set()
    by_node: dict[str, list[dict]] = {name: [] for name in gpu_nodes}
    for item in inventory_document.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        spec = item.get("spec", {})
        name = metadata.get("name", "")
        node_name = spec.get("node_name", "")
        physical_id = spec.get("physical_id", "")
        gpu_type = spec.get("gpu_type", "")
        model = spec.get("model", "")
        memory_mib = spec.get("memory_mib")
        if node_name not in gpu_nodes:
            raise RuntimeError("GPU inventory references a node that does not advertise GPU support")
        if not GPU_UUID.fullmatch(physical_id) or name != hashed_name(physical_id):
            raise RuntimeError(f"{name or 'GPU inventory'} has an invalid protected identity")
        if physical_id in physical_ids:
            raise RuntimeError("GPU inventory contains a duplicate physical identity")
        physical_ids.add(physical_id)
        if not DNS_LABEL.fullmatch(gpu_type) or not isinstance(model, str) or not model:
            raise RuntimeError(f"{name} has invalid type metadata")
        if not isinstance(memory_mib, int) or memory_mib < 1:
            raise RuntimeError(f"{name} has invalid memory metadata")
        if (
            labels.get(MANAGED_BY_LABEL) != "heteronetwork-iac"
            or labels.get(INVENTORY_NODE_LABEL) != node_name
            or labels.get(TYPE_LABEL) != gpu_type
        ):
            raise RuntimeError(f"{name} is missing hardware inventory ownership labels")
        visibility = spec.get("visibility")
        if visibility not in {"open", "private"}:
            raise RuntimeError(f"{name} has invalid visibility")
        assignments = spec.get("private_assignments")
        if not isinstance(assignments, list) or len(assignments) != len(set(assignments)):
            raise RuntimeError(f"{name} has invalid private assignments")
        for subject in assignments:
            try:
                uuid.UUID(subject)
            except (TypeError, ValueError, AttributeError) as error:
                raise RuntimeError(f"{name} has invalid private assignments") from error
        if item.get("status", {}).get("health") != "healthy":
            raise RuntimeError(f"{name} is not healthy")
        by_node[node_name].append({"gpu_type": gpu_type, "model": model, "memory_mib": memory_mib})

    summary: dict[str, dict] = {}
    for node_name, node in gpu_nodes.items():
        devices = by_node[node_name]
        if len(devices) != node["declared_count"]:
            raise RuntimeError(
                f"{node_name} inventory has {len(devices)} devices; expected {node['declared_count']}"
            )
        types = {device["gpu_type"] for device in devices}
        models = {device["model"] for device in devices}
        memory_sizes = {device["memory_mib"] for device in devices}
        if types != {node["gpu_type"]} or len(models) != 1 or len(memory_sizes) != 1:
            raise RuntimeError(f"{node_name} inventory does not match its node type")
        summary[node_name] = {
            "count": len(devices),
            "gpu_type": node["gpu_type"],
            "model": next(iter(models)),
            "memory_mib": next(iter(memory_sizes)),
        }

    for node_name, expected_count in required_counts.items():
        if summary.get(node_name, {}).get("count") != expected_count:
            raise RuntimeError(f"{node_name} does not have the required inventory count")
    for node_name, expected_type in required_types.items():
        if summary.get(node_name, {}).get("gpu_type") != expected_type:
            raise RuntimeError(f"{node_name} does not have the required inventory type")
    return summary


def inspect(required_counts: dict[str, int], required_types: dict[str, str]) -> dict[str, dict]:
    return validate_snapshot(
        get_json("get", "nodes"),
        get_json("get", INVENTORY_API),
        required_counts,
        required_types,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-node", action="append", default=[])
    parser.add_argument("--require-type", action="append", default=[])
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    required_counts = parse_counts(args.require_node)
    required_types = parse_types(args.require_type)
    if args.check:
        try:
            summary = inspect(required_counts, required_types)
        except (RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
            print(json.dumps({"ready": False, "message": str(error)}, sort_keys=True))
            return 2
        print(json.dumps({"ready": True, "nodes": summary}, sort_keys=True))
        return 0
    deadline = time.monotonic() + args.timeout_seconds
    message = "GPU inventory did not become healthy"
    while time.monotonic() < deadline:
        try:
            summary = inspect(required_counts, required_types)
            print(json.dumps({"ready": True, "nodes": summary}, sort_keys=True))
            return 0
        except (RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
            message = str(error)
            time.sleep(5)
    raise RuntimeError(message)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
