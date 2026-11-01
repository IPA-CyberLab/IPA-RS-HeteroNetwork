#!/usr/bin/env python3
"""Fence stopped overlay addresses even when an old agent restores a peer."""

import argparse
import fcntl
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
import sys

from node_lifecycle import stopped_hosts

CHAIN = "HNN-STOPPED-PEERS"


def stopped_addresses(roster):
    stopped = stopped_hosts(roster)
    hosts = roster["hosts"]
    peers = roster["peers"]
    if len(peers) != len(hosts) or {p["node_id"] for p in peers} != set(hosts.values()):
        raise ValueError("invalid host and peer roster")
    by_node = {peer["node_id"]: ipaddress.ip_address(peer["vpn_ip"]) for peer in peers}
    if len(set(by_node.values())) != len(peers):
        raise ValueError("overlay addresses must be unique")
    addresses = set()
    for host in stopped:
        address = by_node[hosts[host]]
        if address.version != 4 or address.is_unspecified or address.is_multicast:
            raise ValueError("stopped overlay address must be a unicast IPv4 address")
        addresses.add(f"{address}/32")
    return sorted(addresses)


def reconcile(roster, run=subprocess.run):
    addresses = stopped_addresses(roster)  # Fail before changing firewall rules.
    created = run(["iptables", "-N", CHAIN], capture_output=True, text=True, timeout=10)
    if created.returncode not in (0, 1):
        raise RuntimeError("failed to create stopped-node firewall chain")
    listed = run(["iptables", "-S", CHAIN], capture_output=True, text=True, timeout=10, check=True)
    lines = ["*filter", f":{CHAIN} - [0:0]", f"-F {CHAIN}"]
    expected_rules = []
    for address in addresses:
        rules = (f"-A {CHAIN} -s {address} -j DROP", f"-A {CHAIN} -d {address} -j DROP")
        lines.extend(rules)
        expected_rules.extend(shlex.split(rule) for rule in rules)
    lines.extend(("COMMIT", ""))
    current_rules = [shlex.split(line) for line in listed.stdout.splitlines() if line.startswith(f"-A {CHAIN} ")]
    if current_rules != expected_rules:
        run(["iptables-restore", "--noflush"], input="\n".join(lines), capture_output=True, text=True, timeout=10, check=True)
    for hook in ("INPUT", "OUTPUT", "FORWARD"):
        listed = run(["iptables", "-S", hook], capture_output=True, text=True, timeout=10, check=True)
        rules = [shlex.split(line) for line in listed.stdout.splitlines() if line.startswith(f"-A {hook} ")]
        if not rules or rules[0] != ["-A", hook, "-j", CHAIN]:
            run(["iptables", "-I", hook, "1", "-j", CHAIN], capture_output=True, text=True, timeout=10, check=True)
    return len(addresses)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roster", type=Path, required=True)
    args = parser.parse_args()
    try:
        roster = json.loads(args.roster.read_text())
        with open("/run/lock/heteronetwork-stopped-firewall.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            count = reconcile(roster)
    except (OSError, KeyError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"stopped overlay firewall reconciliation failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(f"stopped_addresses_fenced={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
