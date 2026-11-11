"""Prepare the declarative inventory changes for retiring a physical node."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from node_lifecycle import stopped_hosts


SAFE_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _read(root, relative):
    path = root / relative
    require(path.is_file() and not path.is_symlink(), f"invalid inventory file: {relative}")
    return json.loads(path.read_text())


def _replace(path, payload, mode):
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".retire-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def plan(root, hostname, *, etcd_member_absent, offline_retirement=False):
    """Return an immutable-by-convention plan without mutating the checkout."""
    root = Path(root).resolve()
    require(SAFE_HOST.fullmatch(hostname), "invalid Kubernetes node name")
    base = Path("deploy/terraform/master-only")
    roster_path = base / "overlay-boot-peers.json"
    standard_path = base / "standard-nodes.json"
    retirements_path = base / "etcd-retirements.json"
    dns_path = Path("deploy/gitops/public-dns-quorum/pool.json")
    roster, standard = _read(root, roster_path), _read(root, standard_path)
    retirements, dns = _read(root, retirements_path), _read(root, dns_path)
    stopped = stopped_hosts(roster)
    require(hostname in standard and hostname in roster["hosts"],
            "target is not a declared standard host (protected hosts require a replacement plan)")
    require(hostname in stopped or offline_retirement,
            "target must first be explicitly stopped")
    node_id = roster["hosts"][hostname]
    matches = [peer for peer in roster["peers"] if peer.get("node_id") == node_id]
    require(len(matches) == 1 and matches[0].get("hostname") == hostname,
            "network and infrastructure identities do not match")
    peer = matches[0]
    require(peer.get("vpn_ip") == standard[hostname].get("vpn_ip"), "VPN address differs between inventories")
    require(etcd_member_absent, "verify etcd member removal before clearing its retirement intent")
    desired_roster, desired_standard = copy.deepcopy(roster), copy.deepcopy(standard)
    desired_retirements, desired_dns = copy.deepcopy(retirements), copy.deepcopy(dns)
    del desired_roster["hosts"][hostname]
    desired_roster["peers"] = [item for item in desired_roster["peers"] if item["node_id"] != node_id]
    desired_roster.get("node_states", {}).pop(hostname, None)
    del desired_standard[hostname]
    desired_retirements["retirements"] = [item for item in desired_retirements["retirements"]
                                           if item.get("node") != hostname]
    desired_dns["members"] = [item for item in desired_dns["members"] if item.get("node") != hostname]
    desired_dns["origins"] = [item for item in desired_dns["origins"] if item.get("id") != hostname]
    require(len(desired_dns["members"]) >= 2, "retirement would leave fewer than two DNS voters")
    require(desired_dns["origins"], "retirement would remove the last declared public origin")
    stopped_hosts(desired_roster)
    updates = {roster_path: desired_roster, standard_path: desired_standard,
               retirements_path: desired_retirements, dns_path: desired_dns}
    return {
        "hostname": hostname, "node_id": node_id, "vpn_ip": peer["vpn_ip"],
        "cluster_id": roster["cluster_id"], "public_ip": standard[hostname].get("ssh_host"),
        "tailscale_ip": standard[hostname].get("tailscale_ip"),
        "postgres_name": standard[hostname].get("postgres_name"),
        "updates": updates,
        "original_digests": {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
                             for path in updates},
    }


def apply(root, proposed):
    """Atomically replace each validated inventory, rolling back on an error."""
    root = Path(root).resolve()
    original, written = {}, []
    try:
        # Check all inputs before changing any of them. An operator can safely
        # re-plan if a controller or another administrator edited the checkout.
        for relative, value in proposed["updates"].items():
            path = root / relative
            require(path.is_file() and not path.is_symlink(), "inventory changed since planning")
            payload = path.read_bytes()
            require(hashlib.sha256(payload).hexdigest() == proposed["original_digests"][relative],
                    "inventory changed since planning")
            original[path] = (payload, path.stat().st_mode & 0o777)
        for relative, value in proposed["updates"].items():
            path = root / relative
            payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
            _replace(path, payload, original[path][1])
            written.append(path)
    except Exception:
        for path in reversed(written):
            _replace(path, *original[path])
        raise
