#!/usr/bin/env python3
"""Disable the legacy public owner client after private owner access is proven."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile


def sibling(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if not spec or not spec.loader:
        raise RuntimeError("required private identity helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def retire(kc):
    clients = kc.get("clients", realm="heterocloud", query={"clientId": "ipars-web"})
    if not isinstance(clients, list) or len(clients) > 1:
        raise ValueError("legacy public owner client is ambiguous")
    if not clients:
        return False
    client = clients[0]
    if client.get("clientId") != "ipars-web" or client.get("publicClient") is not True:
        raise ValueError("refusing to change an unexpected public client")
    if client.get("enabled") is False:
        return False
    if client.get("enabled") is not True:
        raise ValueError("legacy public client state is invalid")
    redirects = client.get("redirectUris") or []
    if "http://console.heteronetwork.internal/ui/callback" not in redirects:
        raise ValueError("legacy public client is not the known owner console")
    identifier = client.get("id", "")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", identifier):
        raise ValueError("legacy public client identity is invalid")
    kc.update_client(identifier, {"enabled": False}, realm="heterocloud")
    updated = kc.get("clients", realm="heterocloud", query={"clientId": "ipars-web"})
    if len(updated) != 1 or updated[0].get("enabled") is not False:
        raise RuntimeError("legacy public client disablement was not confirmed")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--identity-origin", required=True)
    parser.add_argument("--proof-owner", default=os.environ.get("HNN_IAC_SSH_USER", "mizuame"))
    parser.add_argument("--control-plane", action="append", default=[])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("must run as root")
    try:
        if len(set(args.control_plane)) < 2:
            raise ValueError("both private control planes must be verified before retirement")
        proof = sibling("verify-private-owner-proof.py", "private_owner_proof")
        client = sibling("reconcile-private-oidc-client.py", "private_oidc_client")
        origin = proof.identity_origin(args.identity_origin)
        uid = pwd.getpwnam(args.proof_owner).pw_uid
        token = proof.read_proof(args.token_file, uid)
        pool, email = proof.bootstrap_values(proof.read_regular(proof.BOOTSTRAP, 0, mode_mask=0o077, max_size=131072))
        proof.verify(token, origin + "/realms/heteronetwork", email, pool, args.control_plane)
        del token
        password = client.private_file(client.ADMIN_PASSWORD, world_only=True).strip()
        with tempfile.TemporaryDirectory(prefix="hnn-retire-public-owner-", dir="/run") as directory:
            kc = client.Keycloak("http://127.0.0.1:18080", directory, password)
            del password
            changed = retire(kc)
        print(json.dumps({"changed": changed}))
        return 0
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("public owner client retirement failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
