#!/usr/bin/env python3
"""Move the DB DCS voter off the Secret Manager hosts with quorum checks.

The protected authority is staged before the etcd learner/member transition
and is committed only after the replacement three-member quorum is healthy.
This tool runs as root on the bundle authority (uc-k8sp5).
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('recovery', ROOT / 'recover-database-authority.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

OLD_DCS = {'db-b': '100.96.127.54', 'db-e': '100.111.33.52', 'db-g': '100.94.130.38'}
NEW_DCS = {'db-b': '100.96.127.54', 'db-e': '100.111.33.52', 'db-h': '100.65.54.75'}
DEFAULT_BUNDLE = Path('/etc/heteronetwork/postgres-autopilot/bundle')
DEFAULT_ARCHIVE = Path('/etc/heteronetwork/postgres-autopilot/bundle.tar.gz')
DEFAULT_STAGE = Path('/var/backups/heteronetwork/iac-database-ha/secret-manager-dcs-replacement')
DEFAULT_HELPER = Path('/opt/heteronetwork/libexec/postgres-ha-node.sh')


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def mapping(values):
    return ','.join(f'{name}={address}' for name, address in values.items())


def stage_valid(stage, old_revision):
    bundle, archive = stage / 'bundle', stage / 'bundle.tar.gz'
    require(recovery.tree_digest(bundle) == recovery.archive_digest(archive)[0],
            'staged archive differs from its expanded bundle')
    values, _ = recovery.parse_manifest(recovery.read_limited(bundle / 'manifest.env', private=True))
    require(recovery.parse_mapping(values['HETERONETWORK_DB_DCS_MEMBERS']) == NEW_DCS,
            'staged DCS member map is not the requested replacement')
    require(recovery.parse_mapping(values['HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS']) == NEW_DCS,
            'staged DCS bootstrap map is not the requested replacement')
    require(int(values['HETERONETWORK_DB_TOPOLOGY_REVISION']) == old_revision + 1,
            'staged topology revision is invalid')
    cert = bundle / 'nodes/db-h/node.crt'
    key = bundle / 'nodes/db-h/node.key'
    require(cert.is_file() and key.is_file(), 'replacement voter certificate is missing')
    recovery.openssl('verify', '-CAfile', bundle / 'ca/ca.crt', cert)
    recovery.openssl('x509', '-in', cert, '-noout', '-checkip', NEW_DCS['db-h'])
    require(recovery.openssl('x509', '-in', cert, '-pubkey', '-noout', capture=True)
            == recovery.openssl('pkey', '-in', key, '-pubout', capture=True),
            'replacement voter certificate and key do not match')


def prepare(bundle, archive, stage, helper):
    require(os.geteuid() == 0, 'root is required')
    require(not stage.exists(), 'a staged replacement already exists')
    authority = recovery.inspect_authority(bundle, archive)
    require(not authority['retired'], 'database authority still has retired members')
    require(recovery.parse_mapping(authority['values']['HETERONETWORK_DB_DCS_MEMBERS']) == OLD_DCS,
            'old DCS topology differs from the reviewed topology')
    stage.mkdir(mode=0o700, parents=True)
    shutil.copytree(bundle, stage / 'bundle', symlinks=False)
    shutil.copy2(archive, stage / 'old-bundle.tar.gz')
    env = os.environ.copy()
    env.update(authority['values'])
    env.update({
        'HETERONETWORK_DB_DCS_MEMBERS': mapping(NEW_DCS),
        'HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS': mapping(NEW_DCS),
        'HETERONETWORK_DB_TOPOLOGY_REVISION': str(authority['revision'] + 1),
        'HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE': 'existing',
        'HETERONETWORK_DB_BUNDLE_DIR': str(stage / 'bundle'),
    })
    result = subprocess.run([str(helper), 'extend-bundle', str(stage / 'bundle')],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            check=False)
    require(result.returncode == 0, 'staging the replacement certificate and topology failed')
    recovery.pack_bundle(stage / 'bundle', stage / 'bundle.tar.gz')
    stage_valid(stage, authority['revision'])
    state = {
        'old_revision': authority['revision'],
        'old_archive_sha256': digest(archive),
        'new_archive_sha256': digest(stage / 'bundle.tar.gz'),
        'candidate': 'ichikawap1',
        'candidate_tailnet_ip': NEW_DCS['db-h'],
    }
    recovery.atomic_write(stage / 'state.json',
                          (json.dumps(state, sort_keys=True) + '\n').encode(), 0o600)
    return {'phase': 'staged', 'revision': authority['revision'] + 1,
            'candidate': state['candidate']}


def etcdctl(bundle, *args, endpoints=NEW_DCS):
    command = [
        '/opt/heteronetwork/postgres-ha/etcdctl',
        '--endpoints=' + ','.join(f'https://{address}:12379' for address in endpoints.values()),
        '--dial-timeout=3s', '--command-timeout=10s',
        '--cacert=' + str(bundle / 'ca/ca.crt'),
        '--cert=' + str(bundle / 'nodes/db-b/node.crt'),
        '--key=' + str(bundle / 'nodes/db-b/node.key'), *args,
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False)
    require(result.returncode == 0, 'new DCS quorum is not healthy')
    return result.stdout


def members_by_peer(bundle, endpoints):
    members = json.loads(etcdctl(bundle, 'member', 'list', '--write-out=json',
                                 endpoints=endpoints))['members']
    result = {}
    for member in members:
        peers = member.get('peerURLs', [])
        require(len(peers) == 1 and peers[0] not in result,
                'DCS member has unexpected peer URLs')
        result[peers[0]] = member
    return result


def expected_peers(members):
    return {f'https://{address}:12380' for address in members.values()}


def add_learner(bundle):
    current = members_by_peer(bundle, OLD_DCS)
    old_peers = expected_peers(OLD_DCS)
    new_peer = f'https://{NEW_DCS["db-h"]}:12380'
    require(set(current) in (old_peers, old_peers | {new_peer}),
            'unexpected membership before replacement learner addition')
    for name, address in OLD_DCS.items():
        require(current[f'https://{address}:12380']['name'] == name,
                'existing DCS voter name drift')
    if new_peer not in current:
        etcdctl(bundle, 'endpoint', 'health', '--cluster', endpoints=OLD_DCS)
        etcdctl(bundle, 'member', 'add', 'db-h',
                '--peer-urls=' + new_peer, '--learner', endpoints=OLD_DCS)
        current = members_by_peer(bundle, OLD_DCS)
    require(set(current) == old_peers | {new_peer}
            and current[new_peer].get('isLearner', False),
            'replacement learner was not registered')
    return {'phase': 'learner-added', 'member_count': 4}


def promote_learner(bundle):
    current = members_by_peer(bundle, OLD_DCS)
    require(set(current) == expected_peers(OLD_DCS) | expected_peers({'db-h': NEW_DCS['db-h']}),
            'replacement learner membership is incomplete')
    peer = f'https://{NEW_DCS["db-h"]}:12380'
    learner = current[peer]
    require(learner['name'] == 'db-h', 'replacement learner has not joined')
    if learner.get('isLearner', False):
        etcdctl(bundle, 'member', 'promote', format(int(learner['ID']), 'x'),
                endpoints=OLD_DCS)
    current = members_by_peer(bundle, OLD_DCS)
    require(not current[peer].get('isLearner', False), 'replacement DCS voter was not promoted')
    etcdctl(bundle, 'endpoint', 'health', '--cluster',
            endpoints={**OLD_DCS, 'db-h': NEW_DCS['db-h']})
    return {'phase': 'learner-promoted', 'member_count': 4}


def retire_old_voter(bundle):
    current = members_by_peer(bundle, NEW_DCS)
    require(set(current) == expected_peers(OLD_DCS) | expected_peers({'db-h': NEW_DCS['db-h']}),
            'four-voter transition membership differs from the reviewed topology')
    for name, address in NEW_DCS.items():
        member = current[f'https://{address}:12380']
        require(member['name'] == name and not member.get('isLearner', False),
                'new DCS quorum is not composed of voters')
    etcdctl(bundle, 'endpoint', 'health', endpoints=NEW_DCS)
    old = current[f'https://{OLD_DCS["db-g"]}:12380']
    require(old['name'] == 'db-g' and not old.get('isLearner', False),
            'retiring DCS voter identity differs from the reviewed node')
    etcdctl(bundle, 'member', 'remove', format(int(old['ID']), 'x'),
            endpoints=NEW_DCS)
    healthy_new_quorum(bundle)
    return {'phase': 'old-voter-removed', 'member_count': 3}


def healthy_new_quorum(bundle):
    members = json.loads(etcdctl(bundle, 'member', 'list', '--write-out=json'))['members']
    actual = {member['name']: member['peerURLs'] for member in members}
    require(actual == {name: [f'https://{address}:12380']
                       for name, address in NEW_DCS.items()},
            'actual etcd membership is not exactly the new three-voter topology')
    require(all(not member.get('isLearner', False) for member in members),
            'a DCS learner remains')
    etcdctl(bundle, 'endpoint', 'health', '--cluster')


def commit(bundle, archive, stage):
    require(os.geteuid() == 0, 'root is required')
    require(stage.is_dir() and not stage.is_symlink(), 'staged replacement is missing')
    state = json.loads(recovery.read_limited(stage / 'state.json', private=True))
    authority = recovery.inspect_authority(bundle, archive)
    require(authority['revision'] == state['old_revision']
            and digest(archive) == state['old_archive_sha256'],
            'the protected authority changed since replacement staging')
    stage_valid(stage, state['old_revision'])
    require(digest(stage / 'bundle.tar.gz') == state['new_archive_sha256'],
            'staged archive changed')
    healthy_new_quorum(bundle)
    backup = stage / 'previous'
    backup.mkdir(mode=0o700)
    moved_bundle = moved_archive = False
    try:
        os.replace(bundle, backup / 'bundle')
        moved_bundle = True
        os.replace(stage / 'bundle', bundle)
        os.replace(archive, backup / 'bundle.tar.gz')
        moved_archive = True
        os.replace(stage / 'bundle.tar.gz', archive)
        require(recovery.tree_digest(bundle) == recovery.archive_digest(archive)[0],
                'committed authority and archive differ')
    except Exception:
        if moved_archive:
            os.replace(backup / 'bundle.tar.gz', archive)
        if moved_bundle:
            if bundle.exists():
                os.replace(bundle, stage / 'failed-bundle')
            os.replace(backup / 'bundle', bundle)
        raise
    recovery.fsync_directory(bundle.parent)
    return {'phase': 'committed', 'revision': state['old_revision'] + 1,
            'backup': str(backup)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'add-learner', 'promote-learner',
                                           'retire-old-voter', 'commit'))
    parser.add_argument('--bundle', type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument('--archive', type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument('--stage', type=Path, default=DEFAULT_STAGE)
    parser.add_argument('--helper', type=Path, default=DEFAULT_HELPER)
    args = parser.parse_args()
    require(all(path.is_absolute() for path in (args.bundle, args.archive, args.stage,
                                                args.helper)), 'all paths must be absolute')
    actions = {
        'prepare': lambda: prepare(args.bundle, args.archive, args.stage, args.helper),
        'add-learner': lambda: add_learner(args.bundle),
        'promote-learner': lambda: promote_learner(args.bundle),
        'retire-old-voter': lambda: retire_old_voter(args.bundle),
        'commit': lambda: commit(args.bundle, args.archive, args.stage),
    }
    require(os.geteuid() == 0, 'root is required')
    result = actions[args.action]()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError,
            recovery.RecoveryError, subprocess.SubprocessError):
        print('DCS voter migration failed closed; no protected value was printed.', file=sys.stderr)
        sys.exit(1)
