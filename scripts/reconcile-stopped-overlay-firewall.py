#!/usr/bin/env python3
"""Fence stopped overlay addresses even when an old agent restores a peer."""

import argparse
import fcntl
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys

from node_lifecycle import stopped_hosts

CHAIN = "HNN-STOPPED-PEERS"
ANCHOR_PREFIX = "hnn-stopped-"


def managed_hook(rule, hook):
    if rule == ["-A", hook, "-j", CHAIN]:
        return True
    return (len(rule) == 8 and rule[:5] == ["-A", hook, "-m", "comment", "--comment"]
            and re.fullmatch(ANCHOR_PREFIX + r"[0-9a-f]{16}", rule[5]) is not None
            and rule[6:] == ["-j", CHAIN])


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
    chain_lines = [f":{CHAIN} - [0:0]", f"-F {CHAIN}"]
    expected_rules = []
    for address in addresses:
        rules = (f"-A {CHAIN} -s {address} -j DROP", f"-A {CHAIN} -d {address} -j DROP")
        chain_lines.extend(rules)
        expected_rules.extend(shlex.split(rule) for rule in rules)
    current_rules = [shlex.split(line) for line in listed.stdout.splitlines() if line.startswith(f"-A {CHAIN} ")]
    lines = ["*filter"]
    if current_rules != expected_rules:
        lines.extend(chain_lines)
    for hook in ("INPUT", "OUTPUT", "FORWARD"):
        listed = run(["iptables", "-S", hook], capture_output=True, text=True, timeout=10, check=True)
        rules = [shlex.split(line) for line in listed.stdout.splitlines() if line.startswith(f"-A {hook} ")]
        existing = [rule for rule in rules if managed_hook(rule, hook)]
        if len(existing) == 1 and rules[0] == existing[0]:
            continue
        # A uniquely tagged replacement stays in place while exact matches of
        # old managed jumps are removed. Apply all changes in one transaction:
        # there is no interval without the fence and unrelated rules survive.
        while True:
            tag = ANCHOR_PREFIX + secrets.token_hex(8)
            if all(tag not in rule for rule in existing):
                break
        lines.append(shlex.join(["-I", hook, "1", "-m", "comment", "--comment", tag, "-j", CHAIN]))
        lines.extend(shlex.join(["-D", hook, *rule[2:]]) for rule in existing)
    if len(lines) > 1:
        lines.extend(("COMMIT", ""))
        run(["iptables-restore", "--noflush"], input="\n".join(lines),
            capture_output=True, text=True, timeout=180, check=True)
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
