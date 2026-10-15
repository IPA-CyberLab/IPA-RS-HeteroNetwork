#!/usr/bin/env python3
"""Bind manual source fixes to the last immutable service release image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request

from security_inventory import atomic_json, command_json, normalize_trivy


def fetch(url):
    headers = {'User-Agent': 'HeteroCloud-security'}
    token = os.environ.get('GH_TOKEN')
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return response.read(8 * 1024 * 1024)


def select_release(releases):
    return next((r for r in releases if not r.get('draft') and not r.get('prerelease')
                 and len([a for a in r.get('assets', []) if a['name'].endswith('-release-artifact.json')]) == 1), None)


def source_baseline(repository, source, image, current_findings, trivy, cache=None):
    if not re.fullmatch(r'[0-9a-f]{40}', source) or not re.fullmatch(re.escape('ghcr.io/' + repository.lower()) + r'@sha256:[0-9a-f]{64}', image):
        raise ValueError('stable source/image identity was not verified')
    raw = fetch('https://raw.githubusercontent.com/' + repository + '/' + source + '/Cargo.lock')
    with tempfile.TemporaryDirectory(prefix='security-baseline-') as directory:
        (Path(directory) / 'Cargo.lock').write_bytes(raw)
        command = [trivy] + (['--cache-dir', str(cache)] if cache else [])
        command += ['fs', '--scanners', 'vuln', '--format', 'json', '--list-all-pkgs', '--no-progress']
        if cache:
            command.append('--skip-db-update')
        report = command_json(command + [directory], timeout=300)
    _, old = normalize_trivy(report, 'baseline')
    remaining = {(f['id'], f['package']) for f in current_findings}
    removed = [f for f in old if f.get('fixed_version') and (f['id'], f['package']) not in remaining]
    return {'source_commit': source, 'image': image, 'lock_sha256': hashlib.sha256(raw).hexdigest(),
            'fixed_advisories': removed, 'findings': old}


def baseline(repository, current, trivy):
    releases = json.loads(fetch('https://api.github.com/repos/' + repository + '/releases?per_page=100'))
    release = select_release(releases)
    if release is None:
        return None
    assets = [a for a in release['assets'] if a['name'].endswith('-release-artifact.json')]
    artifact = json.loads(fetch(assets[0]['browser_download_url']))
    source = artifact.get('commit', '')
    image = artifact.get('image', '')
    _, new = normalize_trivy(current, 'candidate')
    return {**source_baseline(repository, source, image, new, trivy), 'release_tag': release['tag_name']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ['repository', 'source-report', 'trivy', 'output']:
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    atomic_json(args.output, baseline(args.repository, json.loads(Path(args.source_report).read_text()), args.trivy))


if __name__ == '__main__':
    main()
