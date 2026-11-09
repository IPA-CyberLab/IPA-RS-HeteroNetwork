#!/usr/bin/env python3
"""Ensure a GitHub recovery environment is restricted without storing secrets."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote


def validate_config(config):
    if set(config) != {"repository", "environment", "allowed_branch", "required_secret_name"}:
        raise ValueError("invalid environment configuration")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", config["repository"]):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", config["environment"]):
        raise ValueError("invalid environment name")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", config["allowed_branch"]):
        raise ValueError("invalid allowed branch")
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", config["required_secret_name"]):
        raise ValueError("invalid required secret name")


class GitHub:
    def request(self, method, path, value=None, allow_missing=False):
        args = ["gh", "api", "--method", method, path]
        if value is not None:
            args += ["--input", "-"]
        result = subprocess.run(args, input=json.dumps(value) if value is not None else None,
                                capture_output=True, text=True, timeout=45)
        if result.returncode:
            if allow_missing and "HTTP 404" in result.stderr:
                return None
            raise ValueError("GitHub environment API request failed")
        return json.loads(result.stdout)


def reconcile(config, github):
    validate_config(config)
    path = f"repos/{config['repository']}/environments/{quote(config['environment'], safe='')}"
    environment = github.request("GET", path, allow_missing=True)
    if environment is None:
        environment = github.request("PUT", path, {
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        })
    expected = {"protected_branches": False, "custom_branch_policies": True}
    if environment.get("name") != config["environment"] or environment.get("deployment_branch_policy") != expected:
        raise ValueError("existing environment branch restrictions differ; refusing to weaken them")
    policies = github.request("GET", path + "/deployment-branch-policies").get("branch_policies", [])
    if not policies:
        github.request("POST", path + "/deployment-branch-policies", {
            "name": config["allowed_branch"], "type": "branch",
        })
        policies = github.request("GET", path + "/deployment-branch-policies").get("branch_policies", [])
    if len(policies) != 1 or policies[0].get("name") != config["allowed_branch"] or policies[0].get("type") != "branch":
        raise ValueError("recovery environment must allow only the declared branch")
    secret_names = {secret["name"] for secret in github.request("GET", path + "/secrets").get("secrets", [])}
    if config["required_secret_name"] not in secret_names:
        raise ValueError("required recovery key secret is missing; supply it separately")
    return {"repository": config["repository"], "environment": config["environment"],
            "allowed_branch": config["allowed_branch"], "required_secret_present": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(reconcile(json.loads(args.config.read_text()), GitHub())))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit("Recovery environment reconciliation failed: " + str(error))
