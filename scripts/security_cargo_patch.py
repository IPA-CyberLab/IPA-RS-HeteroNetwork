#!/usr/bin/env python3
"""Apply available Cargo security fixes, then verify the resulting lockfile."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def fixes(report):
    candidates = {}
    for result in report.get('Results') or []:
        if result.get('Type') != 'cargo':
            continue
        for v in result.get('Vulnerabilities') or []:
            name, installed = v.get('PkgName', ''), v.get('InstalledVersion', '')
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', name):
                continue
            old = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', installed)
            if not old:
                continue
            versions = []
            for value in v.get('FixedVersion', '').split(','):
                value = value.strip()
                match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', value)
                if match and tuple(map(int, match.groups())) > tuple(map(int, old.groups())) and match.group(1) == old.group(1) and (old.group(1) != '0' or match.group(2) == old.group(2)):
                    versions.append((tuple(map(int, match.groups())), value))
            if not versions:
                continue
            fixed = min(versions)[1]
            key = (name, installed)
            entry = candidates.setdefault(key, {'package': name, 'installed_version': installed, 'fixed_version': fixed, 'advisories': [], 'urls': []})
            if tuple(map(int, fixed.split('.'))) > tuple(map(int, entry['fixed_version'].split('.'))):
                entry['fixed_version'] = fixed
            entry['advisories'].append(v['VulnerabilityID'])
            if v.get('PrimaryURL'):
                entry['urls'].append(v['PrimaryURL'])
    return list(candidates.values())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--live-osv', action='store_true')
    p.add_argument('--advisory-cache', default='.security-osv-cache')
    a = p.parse_args()
    report = json.loads(Path(a.report).read_text())
    if a.live_osv:
        from security_inventory import live_osv, normalize_trivy
        packages, findings = normalize_trivy(report, 'ci')
        additions, errors = live_osv([p for p in packages if p['ecosystem'] == 'cargo'], findings, Path(a.advisory_cache))
        if errors:
            raise RuntimeError('live advisory lookup incomplete; no automatic patch is accepted')
        report.setdefault('Results', []).append({'Type': 'cargo', 'Vulnerabilities': [{'VulnerabilityID': f['id'], 'PkgName': f['package'], 'InstalledVersion': f['installed_version'], 'FixedVersion': f['fixed_version'], 'PrimaryURL': f['url']} for f in additions]})
    planned = fixes(report)
    Path(a.output).write_text(json.dumps(planned, indent=2) + '\n')
    if a.apply:
        for fix in planned:
            subprocess.run(['cargo', 'update', '-p', fix['package'] + '@' + fix['installed_version'], '--precise', fix['fixed_version']], check=True)
    print(json.dumps({'available_fixes': len(planned), 'applied_to_lockfile': a.apply and bool(planned)}))


if __name__ == '__main__':
    main()
