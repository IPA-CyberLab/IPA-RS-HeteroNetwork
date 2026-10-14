#!/usr/bin/env python3
"""Rebuild unchanged sources when the deployed base gains a new OS fix."""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.request

from security_inventory import command_json, normalize_trivy


def new_os_fixes(previous, current):
    def keys(findings):
        return {(f['id'], f['package'], f['installed_version'], f['fixed_version'])
                for f in findings if f.get('fixed_version') and f.get('ecosystem') in ('debian', 'ubuntu', 'alpine', 'wolfi')}
    return sorted(keys(current) - keys(previous))


def fetch(url):
    headers = {'User-Agent': 'HeteroCloud-security'}
    if url.startswith('https://api.github.com/'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('candidate metadata exceeds its limit')
    return json.loads(raw)


def needed(repository, source, trivy):
    releases = fetch('https://api.github.com/repos/' + repository + '/releases?per_page=100')
    pattern = r'security-' + re.escape(source) + r'(?:-[0-9]+)?'
    release = next((r for r in releases if re.fullmatch(pattern, r['tag_name'])), None)
    if release is None:
        return True
    assets = [a for a in release['assets'] if a['name'] == 'security-candidate.json']
    if len(assets) != 1:
        raise ValueError('previous candidate descriptor is incomplete')
    value = fetch(assets[0]['browser_download_url'])
    prefix = 'ghcr.io/' + repository.lower() + '@sha256:'
    if value.get('repository') != repository or value.get('source_commit') != source or not re.fullmatch(re.escape(prefix) + r'[0-9a-f]{64}', value.get('image', '')):
        raise ValueError('previous candidate identity is invalid')
    # The previous signed SBOM records which advisories were already observed
    # when that image was built. New OS fixes require a new immutable build;
    # unchanged unresolved findings must not cause a rebuild loop.
    report = command_json([trivy, 'image', '--scanners', 'vuln', '--list-all-pkgs', '--format', 'json', '--no-progress', value['image']], timeout=300)
    _, findings = normalize_trivy(report, 'candidate')
    return bool(new_os_fixes(value['inventory']['image_findings'], findings))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trivy', required=True)
    args = parser.parse_args()
    required = (os.environ['BUILD_CANDIDATE'] == 'true' and Path('Dockerfile').is_file()
                and needed(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'], args.trivy))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('candidate_required=' + str(required).lower() + '\n')


if __name__ == '__main__':
    main()
