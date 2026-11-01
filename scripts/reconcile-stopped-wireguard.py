#!/usr/bin/env python3
"""Remove explicitly stopped nodes' declared keys from a live WireGuard interface."""

import argparse
import base64
import binascii
import json
from pathlib import Path
import re
import subprocess
import sys

from node_lifecycle import stopped_hosts


def stopped_keys(roster):
    stopped = stopped_hosts(roster)
    hosts = roster["hosts"]
    peers = roster["peers"]
    if len(peers) != len(hosts) or {p["node_id"] for p in peers} != set(hosts.values()):
        raise ValueError("invalid host and peer roster")
    keys = set()
    by_node = {}
    for peer in peers:
        key = peer["wireguard_public_key"]
        try:
            valid_key = len(base64.b64decode(key, validate=True)) == 32
        except (ValueError, binascii.Error):
            valid_key = False
        if not valid_key or key in keys:
            raise ValueError("invalid or duplicate declared WireGuard key")
        keys.add(key)
        by_node[peer["node_id"]] = key
    return {by_node[hosts[host]] for host in stopped}


def reconcile(roster, interface, run=subprocess.run):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", interface):
        raise ValueError("invalid WireGuard interface")
    expected = stopped_keys(roster)
    link = run(["ip", "link", "show", "dev", interface], capture_output=True, text=True, timeout=10)
    if link.returncode:
        if "does not exist" in link.stderr or "Cannot find device" in link.stderr:
            return 0
        raise RuntimeError("failed to inspect WireGuard interface")
    listing = run(["wg", "show", interface, "peers"], capture_output=True, text=True, timeout=10, check=True)
    current = set(listing.stdout.splitlines())
    targets = sorted(expected & current)
    for key in targets:
        run(["wg", "set", interface, "peer", key, "remove"], capture_output=True, text=True, timeout=10, check=True)
    return len(targets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--interface", default="heteronetwork0")
    args = parser.parse_args()
    try:
        count = reconcile(json.loads(args.roster.read_text()), args.interface)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"stopped WireGuard peer reconciliation failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(f"stopped_peers_removed={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
