#!/usr/bin/env python3
"""Refresh deployed OSS/SBOM/CVE inventory without reading workload secrets.

No scan error or stale host is represented as zero vulnerabilities. Image scans
use running image digests; source scans cover lockfiles, including transitive
dependencies. Only vulnerabilities are enabled (never secret/config scanning).
"""
import argparse
import base64
import collections
import concurrent.futures
import csv
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, ensure_ascii=False, separators=(',', ':'))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command_json(command, timeout=600, env=None):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode:
        # Registry errors may contain URLs with credentials. Do not propagate
        # raw command stderr to inventory, metrics, CI artifacts, or logs.
        error = result.stderr.lower()
        category = 'registry_authentication' if any(v in error for v in ['unauthorized', 'authentication required', 'denied']) else 'registry_rate_limit' if any(v in error for v in ['toomanyrequests', 'too many requests', '429']) else 'fetch_timeout' if any(v in error for v in ['deadline exceeded', 'timed out', 'timeout']) else 'process_failed'
        raise RuntimeError(category + ' (exit ' + str(result.returncode) + ')')
    return json.loads(result.stdout)


def deployed_images(pods):
    images = {}
    for pod in pods:
        if pod.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
            continue
        for kind, status_kind in [('containers', 'containerStatuses'), ('initContainers', 'initContainerStatuses')]:
            statuses = {s['name']: s for s in pod.get('status', {}).get(status_kind, [])}
            for container in pod['spec'].get(kind, []):
                requested = container['image']
                digest = statuses.get(container['name'], {}).get('imageID', '')
                digest = re.sub(r'^(?:docker-pullable|containerd)://', '', digest)
                if re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                    repository = re.sub(r':[^/:]+$', '', requested.split('@')[0])
                    digest = repository + '@' + digest
                reference = digest if '@sha256:' in digest else requested
                key = reference
                entry = images.setdefault(key, {'kind': 'image', 'reference': reference, 'requested_images': set(), 'namespaces': set(), 'digest_verified': '@sha256:' in reference})
                entry['requested_images'].add(requested)
                entry['namespaces'].add(pod['metadata']['namespace'])
    return [dict(e, requested_images=sorted(e['requested_images']), namespaces=sorted(e['namespaces'])) for e in images.values()]


def normalize_trivy(report, source):
    packages = {}
    findings = []
    for target in report.get('Results') or []:
        ecosystem = target.get('Type', 'unknown')
        for p in target.get('Packages') or []:
            name, version = p.get('Name', ''), p.get('Version', '')
            identifier = p.get('Identifier') or {}
            purl = identifier.get('PURL') or ''
            key = (name, version, purl, ecosystem)
            packages[key] = {'name': name, 'version': version, 'purl': purl, 'ecosystem': ecosystem, 'licenses': p.get('Licenses') or [], 'source': source}
        for v in target.get('Vulnerabilities') or []:
            name, version = v.get('PkgName', ''), v.get('InstalledVersion', '')
            identifier = v.get('PkgIdentifier') or {}
            key = (name, version, identifier.get('PURL') or '', ecosystem)
            packages.setdefault(key, {'name': name, 'version': version, 'purl': key[2], 'ecosystem': ecosystem, 'licenses': [], 'source': source})
            aliases = v.get('VendorIDs') or []
            cves = sorted(set([i for i in [v.get('VulnerabilityID', ''), *aliases] if i.startswith('CVE-')]))
            findings.append({'id': v.get('VulnerabilityID'), 'cves': cves, 'package': name, 'installed_version': version, 'fixed_version': v.get('FixedVersion', ''), 'severity': v.get('Severity', 'UNKNOWN'), 'status': v.get('Status', 'unknown'), 'url': v.get('PrimaryURL'), 'source': source, 'ecosystem': ecosystem})
    unique = {(f['source'], f['package'], f['installed_version'], f['id']): f for f in findings}
    return list(packages.values()), list(unique.values())


def validate_host_os(report, packages):
    if report.get('Metadata', {}).get('OS', {}).get('Family') not in ('ubuntu', 'debian') or not any(p['ecosystem'] in ('ubuntu', 'debian') for p in packages):
        raise RuntimeError('installed OS packages were not detected')


def safe_trivy_report(report):
    # OCI image config can contain baked ENV values and build history. Package
    # inventory needs none of it; never persist those fields even privately.
    metadata = report.get('Metadata') or {}
    return {**{key: report[key] for key in ['SchemaVersion', 'ArtifactName', 'ArtifactType', 'Results'] if key in report}, 'Metadata': {key: metadata[key] for key in ['OS', 'ImageID', 'DiffIDs', 'RepoTags', 'RepoDigests'] if key in metadata}}


def scan_source(trivy, cache, source, reports, timeout=600, registry_auth=None):
    if registry_auth:
        with tempfile.TemporaryDirectory(prefix='registry-auth-', dir=reports) as directory:
            atomic_json(Path(directory) / 'config.json', {'auths': registry_auth})
            return _scan_source(trivy, cache, source, reports, timeout, dict(os.environ, DOCKER_CONFIG=directory))
    return _scan_source(trivy, cache, source, reports, timeout)


def _scan_source(trivy, cache, source, reports, timeout, env=None):
    reference = source['reference']
    key = hashlib.sha256((source['kind'] + ':' + reference).encode()).hexdigest()
    path = reports / (key + '.json')
    marker_path = reports / (key + '.metadata.json')
    db_path = Path(cache) / 'db' / 'metadata.json'
    db_version = json.loads(db_path.read_text()).get('UpdatedAt') if db_path.exists() else None
    marker = {'db_updated_at': db_version, 'collector_schema': 3}
    if source['kind'] == 'image' and source.get('digest_verified') and db_version and path.exists() and marker_path.exists() and json.loads(marker_path.read_text()) == marker:
        report = safe_trivy_report(json.loads(path.read_text()))
        packages, findings = normalize_trivy(report, reference)
        return {'source': source, 'scanned_at': utc_now(), 'status': 'complete', 'packages': packages, 'findings': findings, 'cached_digest_and_db': True}
    base = [trivy, '--cache-dir', str(cache), '--timeout', str(timeout) + 's', source['kind']]
    flags = ['--scanners', 'vuln', '--format', 'json', '--list-all-pkgs', '--no-progress']
    if db_version:
        flags.append('--skip-db-update')
    if source['kind'] == 'fs':
        for directory in ['target', 'node_modules', '.git', 'artifacts', 'test-results']:
            flags += ['--skip-dirs', str(Path(reference) / directory)]
    attempts = 3 if source['kind'] == 'image' else 1
    for attempt in range(attempts):
        try:
            report = safe_trivy_report(command_json(base + flags + [reference], timeout=timeout + 30, env=env))
            atomic_json(path, report)
            atomic_json(marker_path, marker)
            packages, findings = normalize_trivy(report, reference)
            return {'source': source, 'scanned_at': utc_now(), 'status': 'complete', 'packages': packages, 'findings': findings}
        except (RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as error:
            category = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    return {'source': source, 'scanned_at': utc_now(), 'status': 'error', 'error': category, 'packages': [], 'findings': []}


def scoped_registry_auth(registry, auths):
    result = {}
    for name, value in auths.items():
        parsed = urllib.parse.urlsplit(name if '://' in name else 'https://' + name)
        host = parsed.netloc.lower()
        if parsed.username is not None:
            continue
        if host == registry.lower() or registry == 'docker.io' and host in ('index.docker.io', 'registry-1.docker.io'):
            result[name] = value
    return result


def registry_credentials(kubectl, pods):
    """Use only pull credentials explicitly referenced by the observed Pods.

    Values remain in memory and private transient Docker config files. They
    are never included in source records, reports, subprocess arguments or logs.
    """
    credentials, cached = {}, {}
    for pod in pods:
        if pod.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
            continue
        images = deployed_images([pod])
        for entry in images:
            registry = entry['reference'].split('/')[0]
            if '.' not in registry and ':' not in registry:
                registry = 'docker.io'
            for ref in pod['spec'].get('imagePullSecrets', []):
                key = (pod['metadata']['namespace'], ref['name'])
                if key not in cached:
                    try:
                        secret = command_json(kubectl + ['-n', key[0], 'get', 'secret', key[1], '-o', 'json'], timeout=30)
                        cached[key] = json.loads(base64.b64decode(secret['data']['.dockerconfigjson']))['auths']
                    except (OSError, KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                        cached[key] = {}
                scoped = scoped_registry_auth(registry, cached[key])
                if scoped:
                    credentials.setdefault(entry['reference'], {}).update(scoped)
    return credentials


def fetch_releases(policy, previous):
    releases = []
    old = {r['repository']: r for r in previous}
    for watch in policy.get('release_watches', []):
        repository = watch['repository']
        headers = {'User-Agent': 'HeteroCloud-OSS-Security', 'Accept': 'application/atom+xml'}
        if old.get(repository, {}).get('etag'):
            headers['If-None-Match'] = old[repository]['etag']
        try:
            # The public feed avoids the unauthenticated API's 60/hour budget
            # without distributing a permanent GitHub credential to hosts.
            request = urllib.request.Request('https://github.com/' + repository + '/releases.atom', headers=headers)
            with urllib.request.urlopen(request, timeout=20) as response:
                ns = {'a': 'http://www.w3.org/2005/Atom'}
                entries = ET.fromstring(response.read()).findall('a:entry', ns)
                stable = []
                for entry in entries:
                    link = next((link.get('href', '') for link in entry.findall('a:link', ns) if '/releases/tag/' in link.get('href', '')), '')
                    tag = urllib.parse.unquote(link.rsplit('/', 1)[-1])
                    if link and not re.search(r'(?:alpha|beta|nightly|preview|(?:^|[.-])rc[.-]?\d)', tag, re.I):
                        stable.append({'tag': tag, 'published_at': entry.findtext('a:updated', namespaces=ns), 'url': link})
                if not stable:
                    raise ValueError('no stable release in feed')
                releases.append({**watch, **stable[0], 'status': 'complete', 'checked_at': utc_now(), 'etag': response.headers.get('ETag')})
        except urllib.error.HTTPError as error:
            if error.code == 304 and repository in old:
                releases.append({**old[repository], 'status': 'complete', 'checked_at': utc_now()})
            else:
                releases.append({**watch, 'status': 'error', 'error': 'HTTP ' + str(error.code), 'checked_at': utc_now(), 'last_known': old.get(repository)})
        except (OSError, ValueError, ET.ParseError):
            releases.append({**watch, 'status': 'error', 'error': 'release lookup unavailable', 'checked_at': utc_now(), 'last_known': old.get(repository)})
    return releases


def product_advisories():
    """Track gVisor disclosures that do not have a GitHub/OSV advisory.

    A product-name result is an advisory catalogue, not proof that an installed
    release is affected. Preserve the official version conditions for review.
    """
    request = urllib.request.Request('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=gvisor', headers={'User-Agent': 'HeteroCloud-OSS-Security'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
        if data.get('totalResults', 0) > len(data.get('vulnerabilities', [])):
            raise ValueError('partial product advisory result')
        records = []
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            if cve.get('vulnStatus') == 'Rejected':
                continue
            records.append({'product': 'gvisor', 'id': cve['id'], 'published': cve['published'], 'modified': cve['lastModified'], 'url': 'https://nvd.nist.gov/vuln/detail/' + cve['id'], 'version_conditions': cve.get('configurations', []), 'requires_version_review': True})
        return records, []
    except (OSError, ValueError, KeyError):
        return [], [{'source': 'NVD:gvisor', 'error': 'product advisory lookup unavailable'}]


def fetch_hosts(inventory, ssh_key, known_hosts):
    """Read only the host agent's allowlisted package/runtime report."""
    def fetch(host):
        node, address = host['name'], host['ssh_host']
        args = ['ssh', '-i', ssh_key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'ConnectTimeout=7', 'mizuame@' + address, 'cat /var/lib/heteronetwork-security/host-report.json']
        for attempt in range(3):
            try:
                report = command_json(args, timeout=30)
                if report.get('node') != node:
                    raise ValueError('host identity mismatch')
                return report
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                if attempt < 2:
                    time.sleep(2 ** attempt)
        return {'node': node, 'status': 'error', 'error': 'host report unavailable', 'packages': [], 'findings': []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        return list(executor.map(fetch, inventory))


def match_host_packages(host, trivy, cache, directory):
    if host.get('status') != 'complete' or host.get('vulnerability_matching') != 'central':
        return host
    try:
        with tempfile.TemporaryDirectory(prefix='host-metadata-', dir=directory) as temporary:
            stage = Path(temporary)
            for name in ['etc/os-release', 'etc/lsb-release', 'etc/debian_version', 'var/lib/dpkg/status']:
                if name not in host['package_metadata']:
                    continue
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(host['package_metadata'][name])
            report = command_json([trivy, '--cache-dir', str(cache), '--timeout', '10m', 'rootfs', '--skip-db-update', '--scanners', 'vuln', '--format', 'json', '--list-all-pkgs', '--no-progress', str(stage)], timeout=660)
        packages, findings = normalize_trivy(report, 'node:' + host['node'])
        validate_host_os(report, packages)
        native = [p for p in host['packages'] if p['ecosystem'] == 'native']
        return {**host, 'packages': packages + native, 'findings': findings, 'matched_at': utc_now()}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        # Keep enumerated versions but do not mark unscanned hosts as clean.
        return {**host, 'status': 'error', 'error': 'host vulnerability matching failed'}


def live_osv(packages, existing, cache):
    """Poll OSV directly, without waiting for the next Trivy DB publication."""
    ecosystems = {'cargo': 'crates.io', 'npm': 'npm', 'gobinary': 'Go', 'gomod': 'Go', 'pip': 'PyPI', 'gemspec': 'RubyGems', 'jar': 'Maven'}
    grouped = collections.defaultdict(list)
    for package in packages:
        ecosystem = ecosystems.get(package['ecosystem'])
        if ecosystem and package['name'] and package['version']:
            grouped[(ecosystem, package['name'], package['version'])].append(package['source'])
    entries = list(grouped)
    affected = collections.defaultdict(list)
    errors = []
    cache.mkdir(mode=0o700, exist_ok=True)
    def request(url, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers={'User-Agent': 'HeteroCloud-OSS-Security', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    for start in range(0, len(entries), 500):
        batch = entries[start:start + 500]
        try:
            result = request('https://api.osv.dev/v1/querybatch', {'queries': [{'package': {'ecosystem': e, 'name': n}, 'version': v} for e, n, v in batch]})
            if len(result['results']) != len(batch):
                raise ValueError('partial OSV batch')
            for entry, result in zip(batch, result['results']):
                for vulnerability in result.get('vulns') or []:
                    affected[vulnerability['id']].append((entry, vulnerability.get('modified')))
        except (OSError, ValueError, KeyError):
            errors.append({'source': 'OSV', 'error': 'live advisory query failed'})
    def details(item):
        identifier, occurrences = item
        if not re.fullmatch(r'[A-Za-z0-9_-]+', identifier):
            return None
        path = cache / (identifier + '.json')
        try:
            data = json.loads(path.read_text()) if path.exists() else None
            if data is None or any(data.get('modified') != modified for _, modified in occurrences):
                data = request('https://api.osv.dev/v1/vulns/' + identifier)
                atomic_json(path, data)
            return data
        except (OSError, ValueError):
            return None
    existing_keys = {(f['source'], f['package'], f['installed_version'], f['id']) for f in existing}
    additions = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for (identifier, occurrences), data in zip(affected.items(), executor.map(details, affected.items())):
            if data is None:
                errors.append({'source': 'OSV:' + identifier, 'error': 'advisory detail unavailable'})
                continue
            if data.get('withdrawn'):
                continue
            aliases = [identifier, *(data.get('aliases') or [])]
            severity = (data.get('database_specific') or {}).get('severity', 'UNKNOWN').upper()
            severity = {'MODERATE': 'MEDIUM'}.get(severity, severity)
            for (ecosystem, name, version), _ in occurrences:
                relevant = [a for a in data.get('affected', []) if a.get('package', {}).get('name') == name and a.get('package', {}).get('ecosystem') == ecosystem]
                fixed = sorted({event['fixed'] for a in relevant for r in a.get('ranges', []) for event in r.get('events', []) if 'fixed' in event})
                for source in set(grouped[(ecosystem, name, version)]):
                    if any((source, name, version, alias) in existing_keys for alias in aliases):
                        continue
                    urls = [r['url'] for r in data.get('references', []) if 'url' in r]
                    additions.append({'id': identifier, 'cves': [a for a in aliases if a.startswith('CVE-')], 'package': name, 'installed_version': version, 'fixed_version': ', '.join(fixed), 'severity': severity, 'status': 'affected', 'url': urls[0] if urls else 'https://osv.dev/vulnerability/' + identifier, 'references': urls, 'source': source, 'ecosystem': ecosystem})
    return additions, errors


def write_csv(path, packages, findings):
    grouped = collections.defaultdict(list)
    for finding in findings:
        grouped[(finding['source'], finding['package'], finding['installed_version'])].append(finding)
    with open(path, 'w', newline='') as f:
        os.chmod(path, 0o600)
        writer = csv.writer(f)
        writer.writerow(['source', 'OSS', 'version', 'ecosystem', 'purl', 'CVE/advisory', 'severity', 'fixed_version', 'advisory_url'])
        for package in sorted(packages, key=lambda p: (p['source'], p['name'], p['version'])):
            vulnerabilities = grouped.get((package['source'], package['name'], package['version'])) or [None]
            for vulnerability in vulnerabilities:
                writer.writerow([package['source'], package['name'], package['version'], package.get('ecosystem', ''), package.get('purl', ''), vulnerability['id'] if vulnerability else '', vulnerability['severity'] if vulnerability else '', vulnerability['fixed_version'] if vulnerability else '', vulnerability.get('url', '') if vulnerability else ''])


def refresh(args):
    root = Path(args.output)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy = json.loads(Path(args.policy).read_text())
    kubectl = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=20s']
    nodes = command_json(kubectl + ['get', 'nodes', '-o', 'json'])['items']
    pods = command_json(kubectl + ['get', 'pods', '-A', '-o', 'json'])['items']
    sources = deployed_images(pods)
    credentials = registry_credentials(kubectl, pods)
    for repository in policy['repositories']:
        path = Path(args.repos_dir) / repository.split('/')[1]
        sources.append({'kind': 'fs', 'reference': str(path), 'repository': repository})
    # A fresh vulnerability database is mandatory; retaining cached reports on
    # failure must never make an obsolete report eligible for auto-patching.
    command_json_db = subprocess.run([args.trivy, '--cache-dir', str(root / 'cache'), 'image', '--download-db-only', '--no-progress'], capture_output=True, timeout=180)
    if command_json_db.returncode:
        atomic_json(root / 'status.json', {'status': 'error', 'observed_at': utc_now(), 'error': 'vulnerability database refresh failed'})
        raise RuntimeError('Vulnerability database refresh failed')
    reports = root / 'scan-reports'
    reports.mkdir(mode=0o700, exist_ok=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {executor.submit(scan_source, args.trivy, root / 'cache', source, reports, args.timeout, credentials.get(source['reference'])): source for source in sources}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps({'source': result['source']['reference'], 'status': result['status'], 'packages': len(result['packages']), 'findings': len(result['findings'])}), flush=True)
            atomic_json(root / 'progress.json', {'observed_at': utc_now(), 'completed_sources': len(results), 'total_sources': len(sources), 'errors': sum(r['status'] == 'error' for r in results)})
    hosts = []
    if args.hosts:
        hosts = fetch_hosts(json.loads(Path(args.hosts).read_text()), args.ssh_key, args.known_hosts)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            hosts = list(executor.map(lambda h: match_host_packages(h, args.trivy, root / 'cache', root), hosts))
    packages = [p for r in [*results, *hosts] for p in r.get('packages', [])]
    findings = [v for r in [*results, *hosts] for v in r.get('findings', [])]
    errors = [{'source': r.get('source', r.get('node')), 'error': r.get('error', 'scan incomplete')} for r in [*results, *hosts] if r.get('status') != 'complete']
    errors += [{'source': h['node'], 'error': 'host OS package enumeration missing'} for h in hosts if h.get('status') == 'complete' and not any(p.get('ecosystem') in ('ubuntu', 'debian') for p in h.get('packages', []))]
    missing_hosts = {n['metadata']['name'] for n in nodes} - {h['node'] for h in hosts}
    errors += [{'source': node, 'error': 'host inventory missing'} for node in sorted(missing_hosts)]
    max_age = policy['inventory_max_age_seconds']
    for host in hosts:
        try:
            age = time.time() - datetime.datetime.fromisoformat(host['observed_at']).timestamp()
            if age > max_age:
                errors.append({'source': host['node'], 'error': 'host inventory stale'})
        except (KeyError, ValueError):
            if host.get('status') == 'complete':
                errors.append({'source': host['node'], 'error': 'host inventory timestamp missing'})
    old = json.loads((root / 'inventory.json').read_text()) if (root / 'inventory.json').exists() else {}
    live_findings, live_errors = live_osv(packages, findings, root / 'osv-cache')
    findings += live_findings
    errors += live_errors
    releases = fetch_releases(policy, old.get('releases', []))
    errors += [{'source': r['repository'], 'error': r['error']} for r in releases if r['status'] != 'complete']
    catalog, product_errors = product_advisories()
    errors += product_errors
    report = {'schema_version': 1, 'observed_at': utc_now(), 'status': 'complete' if not errors else 'incomplete', 'sources': [{k: r[k] for k in ['source', 'scanned_at', 'status', 'error'] if k in r} for r in results], 'nodes': [{'name': n['metadata']['name'], 'versions': n['status'].get('nodeInfo'), 'ready': any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions'])} for n in nodes], 'hosts': [{k: h[k] for k in ['node', 'observed_at', 'status', 'binaries', 'active_runtimes', 'kernel', 'gpu_driver', 'error', 'containerd_patch'] if k in h} for h in hosts], 'packages': packages, 'findings': findings, 'errors': errors, 'releases': releases, 'product_advisories': catalog or old.get('product_advisories', [])}
    atomic_json(root / 'inventory.json', report)
    write_csv(root / 'oss-cve.csv', packages, findings)
    atomic_json(root / 'metrics.json', metrics_summary(report))
    atomic_json(root / 'status.json', {'status': report['status'], 'observed_at': report['observed_at'], 'sources': len(sources) + len(hosts), 'packages': len(packages), 'findings': len(findings), 'errors': len(errors)})
    print(json.dumps({'status': report['status'], 'packages': len(packages), 'findings': len(findings), 'errors': len(errors)}), flush=True)


def metrics(report, now=None):
    now = time.time() if now is None else now
    stamp = datetime.datetime.fromisoformat(report['observed_at']).timestamp()
    counts = report if 'finding_counts' in report else metrics_summary(report)
    gauges = {
        'scan_timestamp_seconds': stamp,
        'scan_complete': int(report.get('status') == 'complete'),
        'inventory_packages': counts['package_count'],
        'scan_errors': counts['error_count'],
        'fixable_findings': counts['fixable_count'],
        'scan_age_seconds': max(0, now - stamp),
        'runtime_drift_processes': counts['runtime_drift_processes'],
        'runtime_verified_nodes': counts['runtime_verified_nodes'],
    }
    lines = []
    for name, value in gauges.items():
        metric = 'heterocloud_security_' + name
        lines += ['# TYPE ' + metric + ' gauge', metric + ' ' + str(value)]
    lines.append('# TYPE heterocloud_security_findings gauge')
    for value in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        lines.append('heterocloud_security_findings{severity="' + value + '"} ' + str(counts['finding_counts'].get(value, 0)))
    return '\n'.join(lines) + '\n'


def metrics_summary(report):
    return {
        'observed_at': report['observed_at'], 'status': report['status'],
        'package_count': len(report.get('packages', [])),
        'error_count': len(report.get('errors', [])),
        'finding_counts': dict(collections.Counter(f['severity'] for f in report.get('findings', []))),
        'fixable_count': sum(bool(f.get('fixed_version')) for f in report.get('findings', [])),
        'runtime_drift_processes': sum(r.get('processes', 0) for h in report.get('hosts', []) for r in h.get('active_runtimes', []) if not r.get('matches_installed_binary', False)),
        'runtime_verified_nodes': sum((h.get('containerd_patch') or {}).get('status') == 'verified' for h in report.get('hosts', [])),
    }


def serve(args):
    root = Path(args.output)
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/metrics':
                self.send_error(404)
                return
            path = root / 'metrics.json'
            if not path.exists():
                self.send_error(503)
                return
            report = json.loads(path.read_text())
            status_path = root / 'status.json'
            status = json.loads(status_path.read_text()) if status_path.exists() else {}
            if status.get('status') == 'error':
                report['status'] = 'error'
                report['error_count'] = max(1, report.get('error_count', 0))
            body = metrics(report).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_):
            pass
    http.server.ThreadingHTTPServer((args.listen, args.port), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('refresh')
    scan.add_argument('--policy', required=True)
    scan.add_argument('--repos-dir', required=True)
    scan.add_argument('--output', required=True)
    scan.add_argument('--trivy', default='trivy')
    scan.add_argument('--kubectl', default='kubectl')
    scan.add_argument('--kubeconfig', required=True)
    scan.add_argument('--hosts')
    scan.add_argument('--ssh-key')
    scan.add_argument('--known-hosts')
    scan.add_argument('--parallel', type=int, choices=[1, 2, 3], default=2)
    scan.add_argument('--timeout', type=int, default=300)
    server = sub.add_parser('serve')
    server.add_argument('--output', required=True)
    server.add_argument('--listen', default='127.0.0.1')
    server.add_argument('--port', type=int, default=19765)
    args = parser.parse_args()
    (refresh if args.command == 'refresh' else serve)(args)


if __name__ == '__main__':
    main()
