#!/usr/bin/env python3
"""Seed a bounded, operator-approved recovery map before the VPN agent starts.

The live neighbor map can contain a single unavailable peer. It must not be the
only way to reconnect the database, control plane and VPN after a power loss.
Only host routes from the declared server roster are retained for bootstrap.
"""
import argparse
import base64
import copy
import datetime
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def load(path, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                'configuration_must_be_a_regular_unlinked_file')
        require(metadata.st_uid == os.geteuid() and not metadata.st_mode & (0o077 if private else 0o022),
                'configuration_permissions_invalid')
        require(metadata.st_size <= 1024 * 1024, 'configuration_too_large')
        return json.load(source)


def recovery_map(state, roster, node):
    require(roster.get('schema_version') == 1, 'unsupported_roster_version')
    peers = roster['peers']
    require(2 <= len(peers) <= 9, 'recovery_roster_must_have_two_to_nine_servers')
    registered = state.get('registered_node')
    require(registered is not None, 'agent_must_already_be_registered')
    require(roster['cluster_id'] == registered['cluster_id'], 'recovery_cluster_mismatch')
    require(set(roster['hosts'].values()) == {peer['node_id'] for peer in peers}
            and len(roster['hosts']) == len(peers), 'roster_host_bindings_invalid')
    require(node in roster['hosts'], 'host_not_in_approved_recovery_roster')
    seen = {key: set() for key in ['hostname', 'node_id', 'vpn_ip', 'wireguard_public_key', 'identity_public_key']}
    local = None
    for peer in peers:
        require(peer['cluster_id'] == roster['cluster_id'], 'peer_cluster_mismatch')
        require('kubernetes-control-plane' in peer['tags'], 'recovery_peer_is_not_a_control_plane')
        require(not peer.get('routes'), 'recovery_peers_must_not_publish_workload_routes')
        require(ipaddress.ip_address(peer['vpn_ip']) in ipaddress.ip_network('10.250.0.0/24'), 'invalid_recovery_overlay')
        for key in seen:
            require(peer[key] not in seen[key], 'duplicate_recovery_' + key)
            seen[key].add(peer[key])
        for key in ['wireguard_public_key', 'identity_public_key']:
            require(len(base64.b64decode(peer[key], validate=True)) == 32, 'invalid_peer_public_key')
        candidates = peer['endpoint_candidates']
        require(candidates, 'recovery_peer_requires_a_direct_endpoint')
        for candidate in candidates:
            address, port = candidate['addr'].rsplit(':', 1)
            ipaddress.ip_address(address)
            require(candidate['node_id'] == peer['node_id'] and 0 < int(port) < 65536,
                    'invalid_direct_endpoint')
        if peer['node_id'] == roster['hosts'][node]:
            local = peer
    require(local is not None, 'host_not_in_approved_recovery_roster')
    for key in ['node_id', 'wireguard_public_key', 'identity_public_key']:
        require(local[key] == registered[key] == state[key if key == 'node_id' else key + '_b64'],
                'local_recovery_identity_mismatch')
    current = state.get('bootstrap_peer_cache') or {}
    return {'cluster_id': roster['cluster_id'],
            'peers': [copy.deepcopy(peer) for peer in peers if peer['node_id'] != local['node_id']],
            'bootstrap_endpoints': current.get('bootstrap_endpoints', state.get('bootstrap_endpoints', [])),
            'generated_at': state['updated_at']}


def reconcile(state_path, roster_path, node, check=False):
    state_path, roster_path = Path(state_path), Path(roster_path)
    require(not state_path.parent.is_symlink(), 'linked_state_directory_refused')
    parent = state_path.parent.stat()
    require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o077, 'state_directory_permissions_invalid')
    state = load(state_path, private=True)
    original = copy.deepcopy(state)
    roster = load(roster_path)
    desired = recovery_map(state, roster, node)
    current = copy.deepcopy(state.get('bootstrap_peer_cache') or {})
    comparison = copy.deepcopy(desired)
    current.pop('generated_at', None)
    comparison.pop('generated_at', None)
    changed = current != comparison
    if changed and not check:
        state['bootstrap_peer_cache'] = desired
        # A boot before NTP sync must not make updated_at older than created_at.
        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        previous = datetime.datetime.fromisoformat(state['updated_at'].replace('Z', '+00:00'))
        if datetime.datetime.fromisoformat(now.replace('Z', '+00:00')) > previous:
            state['updated_at'] = now
        descriptor, temporary = tempfile.mkstemp(prefix='.overlay-boot-', dir=state_path.parent)
        try:
            with os.fdopen(descriptor, 'w') as output:
                os.fchmod(output.fileno(), 0o600)
                json.dump(state, output)
                output.flush()
                os.fsync(output.fileno())
            # Refuse a replacement race or a newly linked state file.
            current = load(state_path, private=True)
            require(current == original, 'agent_state_changed_during_recovery')
            os.replace(temporary, state_path)
            directory = os.open(state_path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return {'changed': changed and not check, 'approved_bootstrap_peers': len(desired['peers']), 'check_only': check}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('--roster', required=True)
    parser.add_argument('--node', required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(reconcile(args.state, args.roster, args.node, args.check)))
    except (RuntimeError, OSError, ValueError, KeyError, TypeError):
        # A malformed state can contain private keys. Never print its values.
        raise SystemExit('overlay_boot_recovery_validation_failed')


if __name__ == '__main__':
    main()
