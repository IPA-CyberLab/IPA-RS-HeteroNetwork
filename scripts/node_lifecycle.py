"""Operator-declared server lifecycle shared by deployment, recovery and E2E."""

import ipaddress
import json
from pathlib import Path


ROSTER = Path(__file__).resolve().parents[1] / "deploy/terraform/master-only/overlay-boot-peers.json"
LIFECYCLE_LABEL = "heteronetwork.io/lifecycle"


def stopped_hosts(roster):
    states = roster.get("node_states", {})
    if not isinstance(states, dict) or set(states) - set(roster["hosts"]):
        raise ValueError("lifecycle states must refer to declared hosts")
    for value in states.values():
        if not isinstance(value, dict) or set(value) - {"state", "reason"}:
            raise ValueError("invalid node lifecycle fields")
        if value.get("state") not in ("active", "stopped"):
            raise ValueError("node lifecycle state must be active or stopped")
        if value["state"] == "stopped" and not str(value.get("reason", "")).strip():
            raise ValueError("stopped nodes require an operator reason")
    return {name for name, value in states.items() if value["state"] == "stopped"}


def active_peers(roster):
    stopped = {roster["hosts"][name] for name in stopped_hosts(roster)}
    return [peer for peer in roster["peers"] if peer["node_id"] not in stopped]


def gateway_ips(path):
    roster = json.loads(Path(path).read_text())
    if roster.get("schema_version") != 1:
        raise ValueError("unsupported lifecycle roster version")
    peers = roster["peers"]
    if len(peers) != len(roster["hosts"]) or {p["node_id"] for p in peers} != set(roster["hosts"].values()):
        raise ValueError("invalid lifecycle host bindings")
    addresses = [str(ipaddress.ip_address(peer["vpn_ip"])) for peer in active_peers(roster)]
    if not addresses or len(addresses) != len(set(addresses)):
        raise ValueError("lifecycle roster must contain unique active gateway addresses")
    return ",".join(sorted(addresses, key=ipaddress.ip_address))
