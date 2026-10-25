#!/usr/bin/env python3
"""Promote the existing db-h voter in the protected authority, retaining keys.

The database stays synchronous and strict. This changes only the reviewed
two-member topology to three members using an already provisioned DCS identity.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


spec = importlib.util.spec_from_file_location('authority', Path(__file__).with_name('recover-database-authority.py'))
AUTH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(AUTH)


def promote(bundle, archive, backups, helper, roster, apply=False):
    authority = AUTH.inspect_authority(bundle, archive)
    AUTH.require(not authority['retired'] and authority['revision'] >= 3,
                 'database_authority_requires_prior_recovery')
    peers = json.loads(roster.read_text())
    node_id = peers['hosts']['ichikawap1']
    peer, = [p for p in peers['peers'] if p['node_id'] == node_id]
    AUTH.require(peer['vpn_ip'] == '10.250.0.10', 'unexpected_sync_replica_identity')
    if authority['members'].get('db-h') == AUTH.EXPECTED_DCS['db-h']:
        AUTH.require(authority['identities'].get('db-h') == node_id,
                     'existing_sync_replica_identity_mismatch')
        return {'result': 'unchanged', 'members': 3, 'revision': authority['revision']}
    AUTH.require(authority['members'] == AUTH.EXPECTED_MEMBERS,
                 'only_the_reviewed_two_member_topology_can_be_promoted')
    if not apply:
        return {'result': 'promotion-required', 'members': 3}
    desired_members = {**authority['members'], 'db-h': AUTH.EXPECTED_DCS['db-h']}
    desired_ids = {**authority['identities'], 'db-h': node_id}
    values = dict(authority['values'])
    values['HETERONETWORK_DB_MEMBERS'] = ','.join(f'{k}={v}' for k,v in desired_members.items())
    values['HETERONETWORK_DB_MEMBER_IDENTITIES'] = ','.join(f'{k}={v}' for k,v in desired_ids.items())
    values['HETERONETWORK_DB_TOPOLOGY_REVISION'] = str(authority['revision'] + 1)
    AUTH.require(int(values['HETERONETWORK_DB_TOPOLOGY_REVISION']) >= 4, 'invalid_sync_replica_revision')
    with tempfile.TemporaryDirectory(prefix='.sync-replica-', dir=bundle.parent) as temporary:
        stage = Path(temporary) / 'bundle'
        shutil.copytree(bundle, stage)
        env = {**os.environ, **values}
        result = subprocess.run([str(helper), 'extend-bundle', str(stage)], env=env,
                                capture_output=True, timeout=90)
        AUTH.require(result.returncode == 0, 'existing_database_bundle_extension_failed')
        staged_archive = Path(temporary) / 'bundle.tar.gz'
        AUTH.pack_bundle(stage, staged_archive)
        checked = AUTH.inspect_authority(stage, staged_archive)
        AUTH.require(checked['members'] == desired_members and checked['identities'] == desired_ids,
                     'staged_replica_authority_did_not_converge')
        AUTH.require(AUTH.tree_digest(stage) == {**AUTH.tree_digest(bundle),
                     'manifest.env': AUTH.tree_digest(stage)['manifest.env']},
                     'replica_promotion_changed_existing_credentials')
        backup = AUTH.ensure_backup(backups, authority, archive)
        try:
            AUTH.atomic_write(bundle/'manifest.env', (stage/'manifest.env').read_bytes(), 0o600)
            AUTH.replace_archive(archive, staged_archive)
            AUTH.inspect_authority(bundle, archive)
        except Exception:
            AUTH.atomic_write(bundle/'manifest.env', authority['manifest'], 0o600)
            AUTH.replace_archive(archive, backup/'bundle.tar.gz')
            raise
    return {'result': 'changed', 'members': 3, 'revision': authority['revision'] + 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['bundle','archive','backups','helper','roster']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--proxy-archive', type=Path)
    args = parser.parse_args()
    try:
        AUTH.secure_directory(args.bundle.parent)
        lock = os.open(args.bundle.parent/'.sync-replica.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock,'w'):
            fcntl.flock(lock, fcntl.LOCK_EX)
            result=promote(args.bundle,args.archive,args.backups,args.helper,args.roster,args.apply)
            if args.apply and args.proxy_archive:
                result['proxy_bundle']='changed' if AUTH.publish_proxy_archive(args.bundle,args.proxy_archive) else 'unchanged'
            print(json.dumps(result))
    except Exception:
        raise SystemExit('protected_sync_replica_promotion_failed; protected values withheld')


if __name__ == '__main__':
    main()
