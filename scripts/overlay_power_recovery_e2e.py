#!/usr/bin/env python3
"""Test a real Agent cold start in isolated namespaces with no control plane.

Requires root, systemd, openssl, iproute2, WireGuard tools, the native Agent and
reconcile-overlay-boot.py. Uses generated fixture keys only. Never restarts a
production Agent or changes host routes.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def run(*args, data=None, check=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError('fixture_command_failed:' + args[0])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--reconciler', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root is required to create isolated network namespaces')
    args.agent = args.agent.resolve(strict=True)
    args.reconciler = args.reconciler.resolve(strict=True)
    os.umask(0o077)
    prefix = 'hnb' + uuid.uuid4().hex[:8]
    namespaces, units = [], []
    report = {'test_id': prefix, 'passed': False, 'production_agent_restarted': False,
              'control_plane_available': False, 'generated_fixture_keys_only': True}
    root = Path(tempfile.mkdtemp(prefix=prefix + '-', dir='/run'))
    stage = 'fixture_setup'
    try:
        records, states = [], []
        cluster = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        for index in range(3):
            name = 'fixture-' + str(index)
            der = run('openssl', 'genpkey', '-algorithm', 'ED25519', '-outform', 'DER').stdout
            public = run('openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER', data=der).stdout[-32:]
            node_id = 'node-' + hashlib.sha256(public).digest()[:16].hex()
            private = run('wg', 'genkey').stdout.strip()
            wg_public = run('wg', 'pubkey', data=private + b'\n').stdout.decode().strip()
            record = {'node_id': node_id, 'hostname': name, 'cluster_id': cluster,
                      'vpn_ip': '10.250.0.' + str(201 + index),
                      'identity_public_key': base64.b64encode(public).decode(),
                      'wireguard_public_key': wg_public, 'role': 'worker',
                      'tags': ['kubernetes-control-plane'], 'routes': [],
                      'registered_at': now, 'relay_capability': None,
                      'token_policy': {'allow_join': False, 'allow_relay': False,
                                       'allowed_routes': [], 'allowed_tags': [], 'max_token_uses': 1},
                      'endpoint_candidates': [{'node_id': node_id, 'kind': 'local_udp',
                                               'addr': '10.254.253.' + str(index + 1) + ':51820',
                                               'observed_at': now, 'priority': 80, 'cost': 20,
                                               'source': 'stun_probe'}]}
            records.append(record)
            states.append({'node_id': node_id, 'registered_node': record, 'vpn_ip': record['vpn_ip'],
                           'identity_private_key_b64': base64.b64encode(der[-32:]).decode(),
                           'identity_public_key_b64': record['identity_public_key'],
                           'wireguard_private_key_b64': private.decode(),
                           'wireguard_public_key_b64': wg_public,
                           'created_at': now, 'updated_at': now})
        roster = {'schema_version': 1, 'cluster_id': cluster, 'peers': records,
                  'hosts': {r['hostname']: r['node_id'] for r in records}}
        (root / 'roster.json').write_text(json.dumps(roster))
        for index in range(2):
            directory = root / str(index)
            directory.mkdir(mode=0o700)
            state = states[index]
            state['bootstrap_peer_cache'] = {'cluster_id': cluster, 'peers': [records[2]],
                                             'bootstrap_endpoints': [], 'generated_at': now}
            (directory / 'agent.json').write_text(json.dumps(state))
            ns = prefix + str(index)
            run('ip', 'netns', 'add', ns)
            namespaces.append(ns)
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', prefix + 'a', 'type', 'veth', 'peer', 'name', prefix + 'b')
        for index, suffix in enumerate(['a', 'b']):
            link, ns = prefix + suffix, namespaces[index]
            run('ip', 'link', 'set', link, 'netns', ns)
            run('ip', '-n', ns, 'addr', 'add', '10.254.253.' + str(index + 1) + '/24', 'dev', link)
            run('ip', '-n', ns, 'link', 'set', link, 'up')

        def start(phase):
            for index, ns in enumerate(namespaces):
                unit = prefix + '-' + phase + '-' + str(index)
                command = ['systemd-run', '--quiet', '--collect', '--unit=' + unit,
                           '--property=NetworkNamespacePath=/run/netns/' + ns,
                           '--property=CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE',
                           '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict',
                           '--property=ProtectHome=yes', '--property=PrivateTmp=yes',
                           '--property=MemoryMax=256M', '--property=CPUQuota=25%',
                           '--property=ReadWritePaths=' + str(root / str(index)),
                           '--setenv=HETERONETWORK_AGENT_DISABLE_PUBLIC_SERVICES_AUTOPROMOTION=true',
                           '--setenv=HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_ENABLED=false',
                           str(args.agent), 'agent', '--state-path', str(root / str(index) / 'agent.json'),
                           '--apply-peer-map', '--wireguard-backend', 'kernel-netlink',
                           '--route-backend', 'kernel-netlink', '--control-plane-url', 'http://127.0.0.1:9',
                           '--disable-public-stun-fallback', '--disable-heartbeat',
                           '--disable-signal-registration', '--disable-peer-probe',
                           '--packet-flow-detector', 'disabled',
                           '--http-connect-timeout-seconds', '1', '--http-request-timeout-seconds', '2',
                           '--stun-bind', '0.0.0.0:51820']
                run(*command)
                units.append(unit)

        def ping():
            return run('ip', 'netns', 'exec', namespaces[0], 'ping', '-n', '-c', '1', '-W', '1',
                       '10.250.0.202', check=False).returncode == 0

        stage = 'negative_control_dead_cached_peer'
        start('dead')
        deadline = time.monotonic() + 30
        for ns in namespaces:
            while time.monotonic() < deadline:
                result = run('ip', 'netns', 'exec', ns, 'wg', 'show', 'heteronetwork0', 'peers', check=False)
                if result.returncode == 0 and result.stdout.decode().split() == [records[2]['wireguard_public_key']]:
                    break
                time.sleep(1)
            else:
                report['negative_probe']={'exit': result.returncode, 'peer_count': len(result.stdout.decode().split()), 'unit_state': run('systemctl', 'show', units[0], '-p', 'MainPID', '-p', 'ActiveState', '-p', 'SubState', check=False).stdout.decode()}; raise RuntimeError('negative_control_did_not_restore_the_dead_peer')
        if ping():
            raise RuntimeError('negative_control_unexpectedly_connected')
        report['dead_only_cache_failed_as_expected'] = True
        stage = 'remove_all_volatile_wireguard_state'
        for unit in units:
            run('systemctl', 'stop', unit)
        for ns in namespaces:
            run('ip', '-n', ns, 'link', 'del', 'heteronetwork0')
        for index in range(2):
            run('python3', str(args.reconciler), '--state', str(root / str(index) / 'agent.json'),
                '--roster', str(root / 'roster.json'), '--node', records[index]['hostname'])
        stage = 'cold_start_with_approved_roster'
        started = time.monotonic()
        start('recovered')
        while time.monotonic() - started < 40:
            if ping():
                report['recovery_seconds'] = round(time.monotonic() - started, 3)
                break
            time.sleep(1)
        else:
            raise RuntimeError('cold_boot_did_not_restore_connectivity')
        for ns in namespaces:
            handshakes = run('ip', 'netns', 'exec', ns, 'wg', 'show', 'heteronetwork0', 'latest-handshakes').stdout.decode()
            if not any(int(line.split()[1]) > 0 for line in handshakes.splitlines()):
                raise RuntimeError('kernel_handshake_missing')
        report.update(passed=True, kernel_state_recreated=True, bidirectional_handshake=True)
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report.update(failure_stage=stage, failure_kind=type(error).__name__, failure_detail=str(error))
    finally:
        for unit in units:
            run('systemctl', 'stop', unit, check=False)
        for ns in reversed(namespaces):
            run('ip', 'netns', 'del', ns, check=False)
        for suffix in ['a', 'b']:
            run('ip', 'link', 'del', prefix + suffix, check=False)
        shutil.rmtree(root)
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output, indent=2)
            output.write('\n')
        print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
