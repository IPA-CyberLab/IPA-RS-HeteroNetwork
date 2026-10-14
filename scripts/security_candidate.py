#!/usr/bin/env python3
"""Publish a content-addressed security candidate bound to its CI and SBOM."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re

from security_inventory import atomic_json, normalize_trivy


def candidate(repository, commit, image, run_id, source_report, image_report, fixes, ci_commit=None):
    if not re.fullmatch(r'IPA-CyberLab/IPA-RS-Hetero(?:Network|Cloud(?:-[A-Za-z]+)?)', repository):
        raise ValueError('repository is not a platform component')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('exact source commit required')
    prefix = 'ghcr.io/' + repository.lower() + '@sha256:'
    if not image.startswith(prefix) or not re.fullmatch(r'[0-9a-f]{64}', image[len(prefix):]):
        raise ValueError('candidate must use the component repository and an immutable digest')
    if not str(run_id).isdigit():
        raise ValueError('CI run identity required')
    packages, source_findings = normalize_trivy(source_report, 'source')
    image_packages, image_findings = normalize_trivy(image_report, 'image')
    if not packages or not image_packages:
        raise ValueError('source and built image package inventory required')
    targeted = {identifier for fix in fixes for identifier in fix['advisories']}
    remaining = {finding['id'] for finding in source_findings + image_findings}
    if targeted & remaining:
        raise ValueError('a targeted vulnerability remains in the built candidate')
    reports = {'source': source_report, 'image': image_report}
    return {
        'schema_version': 1, 'repository': repository, 'source_commit': commit,
        'image': image, 'platforms': ['linux/amd64'],
        'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'ci': {'run_id': int(run_id), 'workflow': '.github/workflows/oss-security.yml',
               'source_commit': ci_commit or commit,
               'ref': 'refs/heads/master'},
        'fixed_advisories': sorted(targeted), 'fixes': fixes,
        'inventory': {'source_packages': len(packages), 'image_packages': len(image_packages),
                      'source_sbom': packages, 'image_sbom': image_packages,
                      'source_findings': source_findings, 'image_findings': image_findings},
        'report_sha256': {key: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest() for key, value in reports.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['repository', 'commit', 'image', 'run-id', 'source-report', 'image-report', 'fixes', 'output']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ci-commit', required=True)
    parser.add_argument('--baseline')
    args = parser.parse_args()
    value = candidate(args.repository, args.commit, args.image, args.run_id,
                      json.loads(Path(args.source_report).read_text()),
                      json.loads(Path(args.image_report).read_text()),
                      json.loads(Path(args.fixes).read_text()), args.ci_commit)
    if args.baseline:
        value['baseline'] = json.loads(Path(args.baseline).read_text())
    atomic_json(args.output, value)
    print(json.dumps({'candidate': value['image'], 'source': value['source_commit'],
                      'fixed_advisories': len(value['fixed_advisories'])}))


if __name__ == '__main__':
    main()
