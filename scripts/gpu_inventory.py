#!/usr/bin/env python3
"""Discover NVIDIA devices and render the private Flash GPU inventory."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
from dataclasses import dataclass


GPU_UUID = re.compile(r"^GPU-[A-Za-z0-9][A-Za-z0-9-]{15,127}$")
PCI_BUS_ID = re.compile(r"^(?:[0-9A-Fa-f]{8}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
MANAGED_BY = "heteronetwork-iac"


class InventoryError(ValueError):
    """The detected hardware cannot be published safely."""


@dataclass(frozen=True)
class Device:
    physical_id: str
    model: str
    pci_bus_id: str
    memory_mib: int


def canonical_gpu_type(model: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", model.strip().lower()).strip("-")
    if not value:
        raise InventoryError("GPU model does not contain a usable type name")
    if len(value) > 63:
        digest = hashlib.sha256(value.encode()).hexdigest()[:12]
        value = f"{value[:50].rstrip('-')}-{digest}"
    if not DNS_LABEL.fullmatch(value):
        raise InventoryError(f"canonical GPU type is not a DNS label: {value!r}")
    return value


def parse_nvidia_smi(text: str) -> list[Device]:
    devices: list[Device] = []
    for line_number, row in enumerate(csv.reader(io.StringIO(text)), start=1):
        if not row or all(not value.strip() for value in row):
            continue
        if len(row) != 4:
            raise InventoryError(f"nvidia-smi row {line_number} has {len(row)} fields, expected 4")
        physical_id, model, pci_bus_id, raw_memory = (value.strip() for value in row)
        if not GPU_UUID.fullmatch(physical_id):
            raise InventoryError(f"nvidia-smi row {line_number} has an invalid GPU UUID")
        if not model or len(model) > 128:
            raise InventoryError(f"nvidia-smi row {line_number} has an invalid model")
        if not PCI_BUS_ID.fullmatch(pci_bus_id):
            raise InventoryError(f"nvidia-smi row {line_number} has an invalid PCI bus ID")
        try:
            memory_mib = int(raw_memory)
        except ValueError as error:
            raise InventoryError(f"nvidia-smi row {line_number} has invalid memory") from error
        if not 1 <= memory_mib <= 2**31 - 1:
            raise InventoryError(f"nvidia-smi row {line_number} has invalid memory")
        devices.append(Device(physical_id, model, pci_bus_id.lower(), memory_mib))
    if not devices:
        raise InventoryError("nvidia-smi did not report a GPU")
    if len({device.physical_id for device in devices}) != len(devices):
        raise InventoryError("nvidia-smi reported a duplicate GPU UUID")
    if len({device.pci_bus_id for device in devices}) != len(devices):
        raise InventoryError("nvidia-smi reported a duplicate PCI bus ID")
    return devices


def discover() -> list[Device]:
    result = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=uuid,name,pci.bus_id,memory.total",
            "--format=csv,noheader,nounits",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_nvidia_smi(result.stdout)


def validate_inventory(
    devices: list[Device],
    *,
    expected_count: int | None = None,
    expected_type: str | None = None,
    expected_model: str | None = None,
    expected_memory_mib: int | None = None,
) -> tuple[str, str, int]:
    models = {device.model for device in devices}
    memory_sizes = {device.memory_mib for device in devices}
    if len(models) != 1:
        raise InventoryError("a GPU node must contain one GPU model")
    if len(memory_sizes) != 1:
        raise InventoryError("GPUs of one model must expose the same memory size")
    model = next(iter(models))
    memory_mib = next(iter(memory_sizes))
    gpu_type = canonical_gpu_type(model)
    checks = (
        (expected_count, len(devices), "count"),
        (expected_type, gpu_type, "type"),
        (expected_model, model, "model"),
        (expected_memory_mib, memory_mib, "memory"),
    )
    for expected, actual, field in checks:
        if expected is not None and expected != actual:
            raise InventoryError(f"GPU {field} does not match the declared inventory")
    return gpu_type, model, memory_mib


def resource_name(physical_id: str) -> str:
    return "gpu-" + hashlib.sha256(physical_id.encode()).hexdigest()[:16]


def render_inventory(
    node_name: str,
    devices: list[Device],
    *,
    expected_count: int | None = None,
    expected_type: str | None = None,
    expected_model: str | None = None,
    expected_memory_mib: int | None = None,
) -> dict:
    if not DNS_LABEL.fullmatch(node_name):
        raise InventoryError("node name must be a DNS label")
    gpu_type, model, memory_mib = validate_inventory(
        devices,
        expected_count=expected_count,
        expected_type=expected_type,
        expected_model=expected_model,
        expected_memory_mib=expected_memory_mib,
    )
    resources = []
    for device in sorted(devices, key=lambda value: value.physical_id):
        resources.append(
            {
                "apiVersion": "flash.heterocloud.io/v1alpha1",
                "kind": "FlashGpuDevice",
                "metadata": {
                    "name": resource_name(device.physical_id),
                    "labels": {
                        "app.kubernetes.io/managed-by": MANAGED_BY,
                        "flash.heterocloud.io/inventory-node": node_name,
                        "flash.heterocloud.io/gpu-type": gpu_type,
                    },
                },
                # Access fields are deliberately absent. The CRD defaults new devices to
                # open, while the owner API manages visibility and assignments separately.
                "spec": {
                    "node_name": node_name,
                    "physical_id": device.physical_id,
                    "gpu_type": gpu_type,
                    "model": device.model,
                    "memory_mib": device.memory_mib,
                },
            }
        )
    return {
        "node_name": node_name,
        "gpu_type": gpu_type,
        "model": model,
        "memory_mib": memory_mib,
        "count": len(devices),
        "resources": resources,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    parser.add_argument("--expected-count", type=int)
    parser.add_argument("--expected-type")
    parser.add_argument("--expected-model")
    parser.add_argument("--expected-memory-mib", type=int)
    parser.add_argument(
        "--input",
        help="Read captured nvidia-smi CSV from this path instead of probing hardware.",
    )
    args = parser.parse_args()
    if args.input:
        with open(args.input, encoding="utf-8") as source:
            devices = parse_nvidia_smi(source.read())
    else:
        devices = discover()
    inventory = render_inventory(
        args.node,
        devices,
        expected_count=args.expected_count,
        expected_type=args.expected_type,
        expected_model=args.expected_model,
        expected_memory_mib=args.expected_memory_mib,
    )
    json.dump(inventory, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (InventoryError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
