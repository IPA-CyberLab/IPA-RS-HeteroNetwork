"""Synthetic stopped node for lifecycle tests, independent of live inventory."""

import base64
import copy
import json

from node_lifecycle import ROSTER, stopped_hosts


HOST = "fixture-stopped"
NODE_ID = "node-" + "f" * 32
VPN_IP = "10.250.0.250"


def roster_with_stopped_node():
    roster = json.loads(ROSTER.read_text())
    for host in stopped_hosts(roster):
        old = roster["hosts"].pop(host)
        roster["peers"] = [peer for peer in roster["peers"] if peer["node_id"] != old]
        roster["node_states"].pop(host)
    peer = copy.deepcopy(roster["peers"][0])
    peer.update(node_id=NODE_ID, hostname=HOST, vpn_ip=VPN_IP,
                identity_public_key=base64.b64encode(b"i" * 32).decode(),
                wireguard_public_key=base64.b64encode(b"w" * 32).decode())
    for candidate in peer["endpoint_candidates"]:
        candidate["node_id"] = NODE_ID
    roster["hosts"][HOST] = NODE_ID
    roster["peers"].append(peer)
    roster["node_states"][HOST] = {"state": "stopped", "reason": "synthetic test"}
    return roster
