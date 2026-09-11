#!/usr/bin/env python3
"""Render the public, exact DEV sudo policy from reviewed repository inputs."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "deploy/dev/native"
GUESTS = {f"hetero-dev-{member}" for member in range(1, 4)}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique_object)


def render():
    manifest = load(NATIVE / "sudo-manifest.json")
    roster = load(NATIVE / "sudo-roster.json")
    hosts = load(NATIVE / "sudo-hosts.json")
    owner = load(NATIVE / "sudo-owner.json")

    require(set(manifest) == {"schema_version", "cluster_id", "epoch", "members",
                              "public_key_package"}, "invalid_manifest_shape")
    require(manifest["schema_version"] == 1 and manifest["epoch"] == 1,
            "invalid_manifest_version")
    require(roster["schema_version"] == 1 and roster["cluster_id"] == manifest["cluster_id"]
            and roster["epoch"] == manifest["epoch"]
            and roster["members"] == manifest["members"], "roster_manifest_mismatch")
    require(len(manifest["members"]) == 3
            and {member["identifier"] for member in manifest["members"]} == {1, 2, 3},
            "invalid_voter_set")
    require(all(re.fullmatch(r"node-[0-9a-f]{32}", member["node_id"])
                and member["endpoint"] == f"http://10.251.0.{member['identifier']}:8981"
                for member in manifest["members"]), "invalid_voter_endpoint")
    require(isinstance(manifest["public_key_package"], list)
            and 1 <= len(manifest["public_key_package"]) <= 262144
            and all(type(value) is int and 0 <= value <= 255
                    for value in manifest["public_key_package"]), "invalid_public_key_package")

    require(set(hosts) == {"schema_version", "cluster_id", "manifest_file_sha256", "hosts"}
            and hosts["schema_version"] == 1 and hosts["cluster_id"] == manifest["cluster_id"],
            "invalid_host_document")
    require(len(hosts["hosts"]) == 3
            and {host["guest"] for host in hosts["hosts"]} == GUESTS,
            "invalid_host_inventory")
    require(len({host["machine_id"] for host in hosts["hosts"]}) == 3
            and len({bytes(host["attestation_public_key"]) for host in hosts["hosts"]}) == 3,
            "duplicate_host_identity")

    require(set(owner) == {"schema_version", "caller_uid", "identity", "oidc_client_id",
                           "required_email", "vpn_cidr"}
            and owner["schema_version"] == 1 and owner["caller_uid"] == 1000,
            "invalid_owner_document")
    identity = owner["identity"]
    require(set(identity) == {"issuer", "subject"}
            and re.fullmatch(r"[0-9a-f-]{36}", identity["subject"]), "invalid_owner_identity")
    issuer = urlsplit(identity["issuer"])
    require(issuer.scheme == "https" and issuer.hostname and not issuer.username
            and not issuer.password and not issuer.query and not issuer.fragment,
            "invalid_owner_issuer")
    require(owner["oidc_client_id"] == "ipars-web"
            and owner["required_email"].lower() == owner["required_email"]
            and owner["required_email"].count("@") == 1, "invalid_owner_oidc_contract")
    network = ipaddress.ip_network(owner["vpn_cidr"], strict=True)
    require(network == ipaddress.ip_network("10.251.0.0/24"), "invalid_dev_vpn")

    manifest_nodes = {member["node_id"] for member in manifest["members"]}
    policy_hosts = {}
    for host in hosts["hosts"]:
        require(set(host) == {"guest", "machine_id", "host_node_id",
                             "attestation_key_epoch", "attestation_public_key"},
                "invalid_host_shape")
        require(host["host_node_id"] in manifest_nodes
                and re.fullmatch(r"[0-9a-f]{32}", host["machine_id"])
                and host["attestation_key_epoch"] == 1
                and len(host["attestation_public_key"]) == 32
                and all(type(value) is int and 0 <= value <= 255
                        for value in host["attestation_public_key"]), "invalid_host_pin")
        policy_hosts[host["host_node_id"]] = {
            "attestation_key_epoch": host["attestation_key_epoch"],
            "attestation_public_key": host["attestation_public_key"],
            "callers": {str(owner["caller_uid"]): identity},
        }
    require(set(policy_hosts) == manifest_nodes, "incomplete_host_policy")
    return {"schema_version": 2, "manifest": manifest, "hosts": policy_hosts}


def encoded():
    return (json.dumps(render(), sort_keys=True, indent=2) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    raw = encoded()
    if args.check is not None:
        require(args.check.read_bytes() == raw, "rendered_policy_is_stale")
        return
    if args.output is None:
        sys.stdout.buffer.write(raw)
        return
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"DEV sudo policy rendering failed: {error}") from None
