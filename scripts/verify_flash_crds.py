#!/usr/bin/env python3
"""Verify that the live Flash GPU APIs enforce the release schema contract."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time


DEVICE_CRD = "flashgpudevices.flash.heterocloud.io"
JOB_CRD = "flashgpujobs.flash.heterocloud.io"
APPLICATION = "heterocloud-flash"
VERSION = "v1alpha1"
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
GPU_TYPE_RULE = (
    "self.gpu_type.matches('^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$')"
)
OPTIONAL_GPU_TYPE_RULE = "!has(self.gpu_type) || " + GPU_TYPE_RULE


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], text=True, capture_output=True, check=True)


def get_crd(name: str) -> dict:
    return json.loads(run("get", "crd", name, "-o", "json").stdout)


def get_application() -> dict:
    return json.loads(run("-n", "argocd", "get", "application", APPLICATION, "-o", "json").stdout)


def version_schema(document: dict, name: str) -> dict:
    conditions = {
        condition.get("type"): condition.get("status")
        for condition in document.get("status", {}).get("conditions", [])
    }
    if conditions.get("Established") != "True":
        raise RuntimeError(f"{name} is not Established")
    versions = [
        version
        for version in document.get("spec", {}).get("versions", [])
        if version.get("name") == VERSION
    ]
    if len(versions) != 1 or not versions[0].get("served") or not versions[0].get("storage"):
        raise RuntimeError(f"{name} does not serve and store {VERSION}")
    try:
        return versions[0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
    except (KeyError, TypeError) as error:
        raise RuntimeError(f"{name} is missing its spec schema") from error


def validation_rules(spec: dict, name: str) -> set[str]:
    rules = spec.get("x-kubernetes-validations", [])
    if not isinstance(rules, list):
        raise RuntimeError(f"{name} has malformed CEL validation rules")
    return {rule.get("rule", "") for rule in rules if isinstance(rule, dict)}


def validate(application: dict, device: dict, job: dict) -> dict[str, dict[str, object]]:
    desired_revision = application.get("spec", {}).get("source", {}).get("targetRevision")
    sync = application.get("status", {}).get("sync", {})
    compared_revision = sync.get("comparedTo", {}).get("source", {}).get("targetRevision")
    health = application.get("status", {}).get("health", {}).get("status")
    if (
        not desired_revision
        or compared_revision != desired_revision
        or sync.get("status") != "Synced"
        or health != "Healthy"
    ):
        raise RuntimeError(f"{APPLICATION} has not reconciled its desired revision")
    resources = {
        (resource.get("kind"), resource.get("name")): resource.get("status")
        for resource in application.get("status", {}).get("resources", [])
    }
    for name in (DEVICE_CRD, JOB_CRD):
        if resources.get(("CustomResourceDefinition", name)) != "Synced":
            raise RuntimeError(f"{APPLICATION} has not synced {name}")

    device_spec = version_schema(device, DEVICE_CRD)
    try:
        assignments = device_spec["properties"]["private_assignments"]
        assignment_items = assignments["items"]
    except (KeyError, TypeError) as error:
        raise RuntimeError(f"{DEVICE_CRD} is missing private assignment validation") from error
    expected_assignments = {
        "maxItems": 256,
        "minLength": 36,
        "maxLength": 36,
        "pattern": UUID_PATTERN,
    }
    actual_assignments = {
        "maxItems": assignments.get("maxItems"),
        "minLength": assignment_items.get("minLength"),
        "maxLength": assignment_items.get("maxLength"),
        "pattern": assignment_items.get("pattern"),
    }
    if actual_assignments != expected_assignments:
        raise RuntimeError(f"{DEVICE_CRD} does not enforce bounded lowercase UUID assignments")
    if GPU_TYPE_RULE not in validation_rules(device_spec, DEVICE_CRD):
        raise RuntimeError(f"{DEVICE_CRD} does not enforce the canonical GPU type")

    job_spec = version_schema(job, JOB_CRD)
    try:
        gpu_type = job_spec["properties"]["gpu_type"]
        count = job_spec["properties"]["count"]
    except (KeyError, TypeError) as error:
        raise RuntimeError(f"{JOB_CRD} is missing GPU request validation") from error
    if gpu_type.get("type") != "string" or gpu_type.get("nullable") is not True:
        raise RuntimeError(f"{JOB_CRD} has an incompatible gpu_type schema")
    if OPTIONAL_GPU_TYPE_RULE not in validation_rules(job_spec, JOB_CRD):
        raise RuntimeError(f"{JOB_CRD} does not enforce the canonical optional GPU type")
    if count.get("minimum") != 1 or count.get("maximum") != 1:
        raise RuntimeError(f"{JOB_CRD} does not limit jobs to one GPU")

    return {
        APPLICATION: {"synced": True, "healthy": True},
        DEVICE_CRD: {"established": True, "assignment_contract": True},
        JOB_CRD: {"established": True, "gpu_type_contract": True, "max_gpus": 1},
    }


def inspect() -> dict[str, dict[str, object]]:
    return validate(get_application(), get_crd(DEVICE_CRD), get_crd(JOB_CRD))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    deadline = time.monotonic() + (0 if args.check else args.timeout_seconds)
    while True:
        try:
            result = inspect()
            print(json.dumps({"ready": True, "crds": result}, sort_keys=True))
            return 0
        except (RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
            if args.check or time.monotonic() >= deadline:
                print(json.dumps({"ready": False, "message": str(error)}, sort_keys=True))
                return 2 if args.check else 1
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
