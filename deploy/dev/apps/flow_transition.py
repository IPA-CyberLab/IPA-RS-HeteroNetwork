#!/usr/bin/env python3
"""Offline admission for the exact DEV Flow dev6 -> dev7 migration repair."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

OLD_STAMP = '57adfb9d4f123e77c486fd46a2fc9f83b7cb537f56d119ea796ee0afe3f671a3'
OLD_COMMIT = '7e2b8e2db16387faff4087341c51efeac66802de'
NEW_COMMIT = '38d5c8805e4b477af3efd9090eaab2a49e53fded'
FILE = 'heterocloud-flow-dev.json'
REPOSITORY = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow'


def require(value):
    if not value:
        raise ValueError('Unexpected DEV Flow release transition')


def tagged(artifact, companion=False):
    reference = artifact['companions']['livekit']['image'] if companion else artifact['image']
    repository = REPOSITORY + ('-livekit' if companion else '')
    require(re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', reference))
    return reference.replace('@', ':' + artifact['version'] + '@', 1)


def validate(old, new, before, after):
    require(old['revision'] == 15 and new['revision'] == 16)
    for key in ('schema_version', 'channel', 'cluster_uid', 'production_cluster_uid', 'site_sha256'):
        require(new[key] == old[key])
    require(new['channel'] == 'dev' and new['schema_version'] == 1)
    require(set(new['components']) == set(old['components']) and set(new['files']) == set(old['files']))
    for component in old['components']:
        if component != 'flow':
            require(old['components'][component] == new['components'][component])
    for filename in old['files']:
        if filename != FILE:
            require(old['files'][filename] == new['files'][filename])
    previous, following = old['components']['flow'], new['components']['flow']
    require(previous['commit'] == OLD_COMMIT and previous['version'] == '0.1.21-dev.6'
            and following['commit'] == NEW_COMMIT and following['version'] == '0.1.21-dev.7')
    expected = copy.deepcopy(before)
    old_images = [tagged(previous), tagged(previous, True)]
    new_images = [tagged(following), tagged(following, True)]
    counts = [0, 0]
    for item in expected['items']:
        for container in item.get('spec', {}).get('template', {}).get('spec', {}).get('containers', []):
            if container['image'] in old_images:
                index = old_images.index(container['image'])
                container['image'] = new_images[index]
                counts[index] += 1
    require(counts == [4, 1])
    job = [d for d in expected['items'] if d['kind'] == 'Job' and d['metadata']['name'] == 'heterocloud-flow-dev-migrate']
    api = [d for d in expected['items'] if d['kind'] == 'Deployment' and d['metadata']['name'] == 'heterocloud-flow-dev-api']
    require(len(job) == len(api) == 1)
    env = job[0]['spec']['template']['spec']['containers'][0]['env']
    api_env = api[0]['spec']['template']['spec']['containers'][0]['env']
    keys = ('REDIS_SENTINEL_URLS', 'REDIS_SENTINEL_MASTER', 'REDIS_PASSWORD', 'REDIS_SENTINEL_PASSWORD')
    additions = [copy.deepcopy(e) for e in api_env if e['name'] in keys]
    require([e['name'] for e in additions] == list(keys) and not any(e['name'].startswith('REDIS_') for e in env))
    positions = [i for i, e in enumerate(env) if e['name'] == 'MIGRATE_ON_START']
    require(len(positions) == 1)
    env[positions[0] + 1:positions[0] + 1] = additions
    require(expected == after)
    return {'allowed_transition': True, 'old_revision': 15, 'new_revision': 16,
            'replacement_job': 'heterocloud-flow-dev-migrate', 'runtime_verified': False}


def read_bundle(path, stamp):
    raw = (path / 'manifest.json').read_bytes()
    require(len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == stamp)
    manifest = json.loads(raw)
    documents = {}
    for filename, digest in manifest['files'].items():
        require(filename in ('heterocloud-dev.json', 'heterocloud-flow-dev.json',
                             'heterocloud-flash-dev.json', 'heterocloud-syouyu-dev.json'))
        raw = (path / filename).read_bytes()
        require(len(raw) <= 2097152 and hashlib.sha256(raw).hexdigest() == digest)
        documents[filename] = json.loads(raw)
    return manifest, documents[FILE]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-bundle', type=Path, required=True)
    parser.add_argument('--new-bundle', type=Path, required=True)
    parser.add_argument('--new-manifest-sha256', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'[0-9a-f]{64}', args.new_manifest_sha256))
    old, before = read_bundle(args.old_bundle, OLD_STAMP)
    new, after = read_bundle(args.new_bundle, args.new_manifest_sha256)
    print(json.dumps(validate(old, new, before, after), sort_keys=True))


if __name__ == '__main__':
    main()
