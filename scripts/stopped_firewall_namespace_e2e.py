#!/usr/bin/env python3
"""Exercise stopped-peer firewall cleanup inside a disposable network namespace."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/reconcile-stopped-overlay-firewall.py"
SPEC = importlib.util.spec_from_file_location("stopped_overlay_firewall", SCRIPT)
firewall = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(firewall)
ROSTER = {
    "hosts": {"stopped": "node-stopped", "live": "node-live"},
    "peers": [
        {"node_id": "node-stopped", "vpn_ip": "10.250.0.11"},
        {"node_id": "node-live", "vpn_ip": "10.250.0.2"},
    ],
    "node_states": {"stopped": {"state": "stopped", "reason": "test"}},
}


def command(*argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=180, **kwargs).stdout


def hook_rules(hook):
    return [shlex.split(line) for line in command("iptables", "-S", hook).splitlines()
            if line.startswith(f"-A {hook} ")]


def main():
    if os.geteuid() != 0 or os.environ.get("HNN_FIREWALL_TEST_NAMESPACE") != "1":
        raise RuntimeError("This test requires root and explicit isolated-namespace opt-in")
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("Refusing to run in the host network namespace")
    initial = command("iptables", "-S")
    if any(line.startswith(("-A ", "-N ")) for line in initial.splitlines()):
        raise RuntimeError("Refusing to run in a nonempty network namespace")

    command("iptables", "-N", firewall.CHAIN)
    command("iptables", "-N", "HNN-UNRELATED")
    fixture = ["*filter",
               f"-A {firewall.CHAIN} -s 10.250.0.11/32 -j DROP",
               f"-A {firewall.CHAIN} -d 10.250.0.11/32 -j DROP"]
    for hook in ("INPUT", "OUTPUT", "FORWARD"):
        fixture.append(f"-A {hook} -j HNN-UNRELATED")
        fixture.extend([f"-A {hook} -j {firewall.CHAIN}"] * 3500)
        fixture.append(f"-A {hook} -m comment --comment hnn-stopped-0123456789abcdef -j {firewall.CHAIN}")
    fixture.extend(("COMMIT", ""))
    command("iptables-restore", "--noflush", input="\n".join(fixture))

    start = time.monotonic()
    if firewall.reconcile(ROSTER) != 1:
        raise RuntimeError("Stopped address was not fenced")
    elapsed_ms = round((time.monotonic() - start) * 1000)
    for hook in ("INPUT", "OUTPUT", "FORWARD"):
        rules = hook_rules(hook)
        managed = [r for r in rules if firewall.managed_hook(r, hook)]
        if len(managed) != 1 or rules[0] != managed[0]:
            raise RuntimeError(f"{hook} retains duplicate or misplaced hooks")
        if rules.count(["-A", hook, "-j", "HNN-UNRELATED"]) != 1:
            raise RuntimeError(f"{hook} lost an unrelated rule")
    fence = command("iptables", "-S", firewall.CHAIN)
    if "-s 10.250.0.11/32 -j DROP" not in fence or "-d 10.250.0.11/32 -j DROP" not in fence:
        raise RuntimeError("Stopped address is not blocked in both directions")

    # Another controller may prepend a rule after our first run. Reconciliation
    # must move the fence back to the front without duplicating or deleting it.
    command("iptables", "-I", "INPUT", "1", "-j", "HNN-UNRELATED")
    command("iptables", "-A", "INPUT", "-j", firewall.CHAIN)
    firewall.reconcile(ROSTER)
    rules = hook_rules("INPUT")
    if (not firewall.managed_hook(rules[0], "INPUT")
            or sum(firewall.managed_hook(r, "INPUT") for r in rules) != 1
            or rules.count(["-A", "INPUT", "-j", "HNN-UNRELATED"]) != 2):
        raise RuntimeError("Concurrent rule reordering was not repaired safely")
    before = command("iptables-save")
    firewall.reconcile(ROSTER)
    if command("iptables-save") != before:
        raise RuntimeError("An already reconciled firewall was modified")
    print(json.dumps({"result": "passed", "duplicates_per_hook": 3500, "cleanup_ms": elapsed_ms}))


if __name__ == "__main__":
    main()
