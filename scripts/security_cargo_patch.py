#!/usr/bin/env python3
"""Apply available Cargo security fixes, then verify the resulting lockfile."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib


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


def lock_packages(path):
    with Path(path).open('rb') as source:
        lock = tomllib.load(source)
    return {(p['name'], p['version']) for p in lock.get('package', [])}


def scanned_lockfiles(report, root=Path('.')):
    """Accept only real Cargo lockfiles underneath the scanned checkout."""
    root = root.resolve()
    paths = set()
    for result in report.get('Results') or []:
        if result.get('Type') != 'cargo':
            continue
        target = result.get('Target', '')
        if not isinstance(target, str) or not re.fullmatch(r'(?:[A-Za-z0-9_.-]+/)*Cargo\.lock', target):
            raise ValueError('unsupported Cargo lockfile target')
        relative = Path(target)
        if relative.is_absolute() or '..' in relative.parts or '.' in relative.parts:
            raise ValueError('unsafe Cargo lockfile target')
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or not (path.parent / 'Cargo.toml').is_file():
            raise ValueError('Cargo lockfile or manifest is missing')
        paths.add(path)
    return sorted(paths)


def validate_changed_lockfiles(changed, allowed, root=Path('.')):
    root = root.resolve()
    allowed = set(allowed)
    if not changed:
        raise ValueError('security patch did not change any lockfiles')
    for name in changed:
        if not re.fullmatch(r'(?:[A-Za-z0-9_.-]+/)*Cargo\.lock', name):
            raise ValueError('security patch changed a non-lockfile')
        relative = Path(name)
        resolved = (root / relative).resolve()
        if relative.is_absolute() or '..' in relative.parts or resolved not in allowed:
            raise ValueError('security patch changed an unscanned lockfile')
    return sorted(set(changed))


def apply_fixes(planned, lock_paths):
    """Patch every scanned lockfile, skipping only versions already resolved."""
    initial = {Path(path): lock_packages(path) for path in lock_paths}
    targets = {(fix['package'], fix['installed_version']):
               [path for path, packages in initial.items() if (fix['package'], fix['installed_version']) in packages]
               for fix in planned}
    if any(not paths for paths in targets.values()):
        raise RuntimeError('security scan does not match the initial Cargo.lock')
    applied = resolved = 0
    for fix in planned:
        key = (fix['package'], fix['installed_version'])
        for lock_path in targets[key]:
            if key not in lock_packages(lock_path):
                resolved += 1
                continue
            subprocess.run(['cargo', 'update', '--manifest-path', str(lock_path.parent / 'Cargo.toml'),
                            '-p', fix['package'] + '@' + fix['installed_version'],
                            '--precise', fix['fixed_version']], check=True)
            applied += 1
    return applied, resolved


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--live-osv', action='store_true')
    p.add_argument('--advisory-cache', default='.security-osv-cache')
    a = p.parse_args()
    report = json.loads(Path(a.report).read_text())
    lock_paths = scanned_lockfiles(report) if a.apply else []
    if a.live_osv:
        from security_inventory import live_osv, normalize_trivy
        packages, findings = normalize_trivy(report, 'ci')
        additions, errors = live_osv([p for p in packages if p['ecosystem'] == 'cargo'], findings, Path(a.advisory_cache))
        if errors:
            raise RuntimeError('live advisory lookup incomplete; no automatic patch is accepted')
        report.setdefault('Results', []).append({'Type': 'cargo', 'Vulnerabilities': [{'VulnerabilityID': f['id'], 'PkgName': f['package'], 'InstalledVersion': f['installed_version'], 'FixedVersion': f['fixed_version'], 'PrimaryURL': f['url']} for f in additions]})
    planned = fixes(report)
    Path(a.output).write_text(json.dumps(planned, indent=2) + '\n')
    applied, resolved = apply_fixes(planned, lock_paths) if a.apply else (0, 0)
    print(json.dumps({'available_fixes': len(planned), 'applied_to_lockfile': bool(applied),
                      'applied_updates': applied, 'resolved_by_earlier_updates': resolved}))


if __name__ == '__main__':
    main()
