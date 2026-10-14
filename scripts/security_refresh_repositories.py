#!/usr/bin/env python3
"""Refresh public source snapshots for lockfile scanning; never execute them."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def refresh(policy, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for repository in policy['repositories']:
        if not re.fullmatch(r'IPA-CyberLab/IPA-RS-Hetero(?:Network|Cloud(?:-[A-Za-z]+)?)', repository):
            raise ValueError('Unexpected source repository')
        path = destination / repository.split('/')[1]
        url = 'https://github.com/' + repository + '.git'
        if not path.exists():
            subprocess.run(['git', 'clone', '--quiet', '--depth=1', '--filter=blob:none', '--no-tags', url, str(path)], check=True, timeout=180)
        else:
            remote = subprocess.check_output(['git', '-C', str(path), 'remote', 'get-url', 'origin'], text=True).strip()
            if remote != url:
                raise ValueError('Source origin changed')
            subprocess.run(['git', '-C', str(path), 'fetch', '--quiet', '--depth=1', 'origin', 'master'], check=True, timeout=180)
            subprocess.run(['git', '-C', str(path), 'reset', '--quiet', '--hard', 'FETCH_HEAD'], check=True, timeout=30)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy', required=True)
    p.add_argument('--destination', required=True)
    a = p.parse_args()
    refresh(json.loads(Path(a.policy).read_text()), a.destination)
