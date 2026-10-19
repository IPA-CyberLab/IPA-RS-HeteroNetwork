#!/usr/bin/env python3
"""Retire only security image overrides superseded by a declared release.

SSA intentionally preserves the security promoter's Helm parameters. A manual
release must remove an older parameter to make its digest-pinned YAML effective.
Newer or same-source security images are preserved. Runs only when the declared
Application changes, never as periodic drift correction against security fixes.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import yaml


def require(value, message):
    if not value:
        raise RuntimeError(message)


def override_revision(value):
    require(re.fullmatch(r'[^@\s]{1,128}@sha256:[0-9a-f]{64}', value) is not None,
            'image override is not an immutable supported tag')
    tag = value.split('@', 1)[0]
    match = re.fullmatch(r'security-([0-9a-f]{40})(?:-[0-9]+)?', tag)
    if match:
        return match[1]
    require(re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', tag) is not None,
            'cannot verify the image override source')
    return 'v' + tag.removeprefix('v')


def superseded(old_source, desired_source, comparison):
    if old_source == desired_source:
        return False  # Same source can contain a newer verified base image fix.
    status = comparison.get('status')
    if status == 'ahead' and comparison.get('behind_by') == 0:
        return True
    if status == 'behind' and comparison.get('ahead_by') == 0:
        return False  # Preserve a security candidate that includes this release.
    raise RuntimeError('release and security image sources are unrelated; preserving the override')


def github(endpoint):
    result = subprocess.run(['gh', 'api', endpoint], capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'cannot verify release source history')
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args()
    expected = yaml.safe_load(args.manifest.read_text())
    require(expected['kind'] == 'Application', 'Application manifest required')
    source = expected['spec']['source']
    name, namespace = expected['metadata']['name'], expected['metadata']['namespace']
    values = yaml.safe_load(source['helm'].get('values', '{}'))
    if 'image' not in values or not isinstance(values['image'], dict) or not values['image'].get('tag'):
        return  # For example the upstream Envoy chart has no platform image.
    desired_image = values['image']['tag']
    require(re.fullmatch(r'[^@\s]{1,128}@sha256:[0-9a-f]{64}', desired_image) is not None,
            'declared platform image must be digest-pinned')
    match = re.fullmatch(r'https://github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\.git', source['repoURL'])
    require(match is not None, 'unsupported source history host')
    repository = match[1]
    revision = source['targetRevision']
    require(re.fullmatch(r'[0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+', revision) is not None,
            'an immutable release revision is required')
    base = ['kubectl', '-n', namespace]
    decisions = {}
    for attempt in range(8):
        actual = json.loads(subprocess.check_output(base + ['get', 'application', name, '-o', 'json']))
        current = actual['spec']['source']
        require(current['repoURL'] == source['repoURL'] and current['targetRevision'] == revision
                and current['helm'].get('values') == source['helm']['values'],
                'declared release changed concurrently or YAML values have not applied')
        parameters = current['helm'].get('parameters', [])
        overrides = [p for p in parameters if p['name'] == 'image.tag']
        require(len(overrides) <= 1 and not any(p['name'] == 'image.repository' for p in parameters),
                'ambiguous or external image override')
        if not overrides:
            print(name + ': release YAML is authoritative')
            return
        value = overrides[0]['value']
        if value.split('@')[-1] == desired_image.split('@')[-1]:
            print(name + ': image override already matches the release digest')
            return
        if value not in decisions:
            old_ref = override_revision(value)
            old = old_ref if re.fullmatch(r'[0-9a-f]{40}', old_ref) else github('repos/' + repository + '/commits/' + old_ref)['sha']
            desired = revision if re.fullmatch(r'[0-9a-f]{40}', revision) else github('repos/' + repository + '/commits/' + revision)['sha']
            comparison = {} if old == desired else github('repos/' + repository + '/compare/' + old + '...' + desired)
            decisions[value] = superseded(old, desired, comparison)
        if not decisions[value]:
            print(name + ': preserved a security image that includes this release')
            return
        patch = [
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': actual['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec/source/targetRevision', 'value': revision},
            {'op': 'test', 'path': '/spec/source/helm/parameters', 'value': parameters},
            {'op': 'replace', 'path': '/spec/source/helm/parameters', 'value': [p for p in parameters if p['name'] != 'image.tag']},
        ]
        # Parameter arrays can contain private settings: never put them in argv.
        result = subprocess.run(base + ['patch', 'application', name, '--type=json', '--patch-file=/dev/stdin'],
                                input=json.dumps(patch), capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(name + ': retired an older security override for the declared release')
            return
        time.sleep(.5 * (attempt + 1))
    raise RuntimeError('guarded release reconciliation failed after retries')


if __name__ == '__main__':
    main()
