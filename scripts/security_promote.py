#!/usr/bin/env python3
"""Reconcile signed, tested security images through Argo CD.

Only declared platform Applications can change. User Pods, generations and
runtime task identities are acceptance invariants. No arbitrary image, URL,
namespace or command is accepted from candidate metadata.
"""
import argparse
import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from security_inventory import atomic_json, command_json, deployed_images, registry_credentials, scan_source, utc_now
from security_candidate_baseline import source_baseline


def require(value, message):
    if not value:
        raise RuntimeError(message)


def canonical_image(image):
    if '@sha256:' not in image:
        return image
    repository, digest = image.split('@', 1)
    prefix, _, tail = repository.rpartition('/')
    repository = (prefix + '/' if prefix else '') + tail.split(':', 1)[0]
    return repository + '@' + digest


def image_repository(image):
    prefix, _, tail = image.split('@', 1)[0].rpartition('/')
    return (prefix + '/' if prefix else '') + tail.split(':', 1)[0]


def deployment_ready(deployment):
    status = deployment.get('status', {})
    desired = deployment['spec'].get('replicas', 1)
    return (status.get('observedGeneration', 0) >= deployment['metadata'].get('generation', 1)
            and status.get('replicas', 0) == desired
            and status.get('updatedReplicas', 0) == desired
            and status.get('readyReplicas', 0) >= desired
            and status.get('availableReplicas', 0) >= desired)


def trusted(path):
    path = Path(path)
    for parent in [path, *path.parents]:
        info = parent.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022 == 0, 'untrusted operator file')
    return path


def json_request(url, maximum=8 * 1024 * 1024):
    request = urllib.request.Request(url, headers={'User-Agent': 'HeteroCloud-Security-Reconciliation'})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(maximum + 1)
    require(len(raw) <= maximum, 'response exceeds the metadata limit')
    return json.loads(raw)


def candidate_tag(repository):
    url = 'https://github.com/' + repository + '/releases.atom'
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'HeteroCloud-Security-Reconciliation'}), timeout=20) as response:
        raw = response.read(2 * 1024 * 1024)
    for entry in ET.fromstring(raw).findall('{http://www.w3.org/2005/Atom}entry'):
        for link in entry.findall('{http://www.w3.org/2005/Atom}link'):
            parsed = urllib.parse.urlsplit(link.get('href', ''))
            expected = '/' + repository + '/releases/tag/'
            if parsed.scheme == 'https' and parsed.netloc == 'github.com' and parsed.path.startswith(expected):
                tag = urllib.parse.unquote(parsed.path[len(expected):])
                if re.fullmatch(r'security-[0-9a-f]{40}(?:-[0-9]+)?', tag):
                    return tag
    return None


def validate_identity(value, component, run):
    repository = component['repository']
    require(value.get('schema_version') == 1 and value.get('repository') == repository, 'candidate component mismatch')
    require(re.fullmatch(r'[0-9a-f]{40}', value.get('source_commit', '')) is not None, 'source commit must be exact')
    require(re.fullmatch(re.escape('ghcr.io/' + repository.lower()) + r'@sha256:[0-9a-f]{64}', value.get('image', '')) is not None, 'candidate image is outside the component repository')
    require(value.get('platforms') == ['linux/amd64'], 'unsupported candidate platform')
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'candidate CI has not succeeded')
    require(run.get('head_branch') == 'master' and run.get('event') in ('push', 'schedule', 'workflow_dispatch'), 'candidate CI is not a trusted branch event')
    require(run.get('path') == '.github/workflows/oss-security.yml', 'candidate was not built by the security workflow')
    require(value.get('ci', {}).get('source_commit') == run.get('head_sha'), 'attested source does not match CI')


def current_source(repository):
    # Public Git discovery avoids exhausting the anonymous REST API allowance
    # and cannot pick up an operator credential or interactive prompt.
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false', SSH_ASKPASS='/bin/false')
    result = subprocess.check_output(['git', '-c', 'credential.helper=', '-c', 'http.extraHeader=',
                                      'ls-remote', '--exit-code', 'https://github.com/' + repository + '.git',
                                      'refs/heads/master'], text=True, timeout=30, env=env)
    match = re.fullmatch(r'([0-9a-f]{40})\s+refs/heads/master\n?', result)
    require(match is not None, 'the current production source could not be verified')
    return match.group(1)


def verified_fixes(old, new):
    remaining = {(v['id'], v['package']) for v in new}
    return sorted({v['id'] for v in old if v.get('fixed_version') and (v['id'], v['package']) not in remaining})


def tenant_identity(pods, snapshots):
    result = {}
    for pod in pods:
        if pod.get('status', {}).get('phase') != 'Running':
            continue
        node = pod['spec']['nodeName']
        records = []
        for container in pod['status'].get('containerStatuses', []):
            if 'running' not in container.get('state', {}):
                continue
            cid = container['containerID'].split('://', 1)[-1]
            task = snapshots[node]['tasks'].get(cid)
            require(task and task.get('pid') and task.get('exe_sha256'), 'a running tenant task could not be observed')
            records.append((container['name'], cid, task['pid'], task['exe_sha256'], container.get('restartCount', 0)))
        if records:
            result[pod['metadata']['uid']] = {'node': node, 'generation': pod['metadata'].get('labels', {}).get('flash.heterocloud.io/generation'), 'containers': sorted(records)}
    return result


class Reconciler:
    def __init__(self, args, policy):
        self.args, self.policy = args, policy
        self.kubectl = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=20s']
        self.root = Path(args.output)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.hosts = json.loads(trusted(args.hosts).read_text())

    def kube(self, *args):
        return command_json(self.kubectl + list(args), timeout=30)

    def history(self, repository, before, after):
        identity = {'repository': repository, 'before': before, 'after': after}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        path = self.root / ('source-history-' + key + '.json')
        if path.exists():
            saved = json.loads(path.read_text())
            require(saved['identity'] == identity, 'source history cache identity mismatch')
            return saved['comparison']
        result = json_request('https://api.github.com/repos/' + repository + '/compare/' + before + '...' + after)
        comparison = {k: result.get(k) for k in ('status', 'ahead_by', 'behind_by')}
        atomic_json(path, {'identity': identity, 'comparison': comparison})
        return comparison

    def snapshots(self):
        def fetch(host):
            command = ['ssh', '-i', self.args.snapshot_key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                       '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + self.args.known_hosts,
                       '-o', 'ConnectTimeout=7', 'mizuame@' + host['ssh_host'], 'runtime-snapshot']
            challenge = secrets.token_hex(32)
            result = subprocess.run(command, input=challenge + '\n', capture_output=True, text=True, timeout=40)
            require(result.returncode == 0, 'runtime acceptance observation failed')
            report = json.loads(result.stdout)
            require(report.get('challenge') == challenge, 'runtime acceptance snapshot did not bind the fresh challenge')
            return host['name'], report
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            return dict(pool.map(fetch, self.hosts))

    def tenants(self):
        pods = self.kube('-n', self.policy['tenant_namespace'], 'get', 'pods', '-o', 'json')['items']
        return tenant_identity(pods, self.snapshots())

    def health(self):
        nodes = self.kube('get', 'nodes', '-o', 'json')['items']
        require(all(any(c['type'] == 'Ready' and c['status'] == 'True' for c in n['status']['conditions']) for n in nodes), 'fleet is not healthy')
        # VPN health must traverse the actual fleet path, not an inherited
        # HTTP proxy. Identify the monitor so public bot rules need not treat
        # it as an anonymous Python client.
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for probe in self.policy.get('health_probes', []):
            started = time.monotonic()
            request = urllib.request.Request(probe['url'], headers={'User-Agent': 'HeteroCloud-Security-Health/1.0'})
            with direct.open(request, timeout=probe.get('deadline_seconds', 3)) as response:
                require(response.status in probe.get('statuses', [200]), 'service health failed')
                response.read(1024 * 1024)
            require(time.monotonic() - started <= probe.get('deadline_seconds', 3), 'service health exceeded its deadline')

    def attestation(self, component, tag, value):
        directory = self.root / tag
        directory.mkdir(mode=0o700, exist_ok=True)
        url = 'https://github.com/' + component['repository'] + '/releases/download/' + tag + '/'
        for name in ['security-candidate.json', 'security-candidate.sigstore.json']:
            with urllib.request.urlopen(url + name, timeout=30) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
            require(len(raw) <= 8 * 1024 * 1024, 'candidate evidence is too large')
            path = directory / name
            path.write_bytes(raw)
            path.chmod(0o600)
        require(json.loads((directory / 'security-candidate.json').read_text()) == value, 'candidate changed during verification')
        command = [self.args.verifier, 'attestation', 'verify', str(directory / 'security-candidate.json'),
                   '--bundle', str(directory / 'security-candidate.sigstore.json'),
                   '--repo', component['repository'], '--source-ref', 'refs/heads/master',
                   '--source-digest', value['ci']['source_commit'], '--deny-self-hosted-runners',
                   '--signer-workflow', 'IPA-CyberLab/IPA-RS-HeteroNetwork/.github/workflows/oss-security-reusable.yml',
                   '--format', 'json']
        env = {k: v for k, v in os.environ.items() if k not in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN')}
        env['GH_CONFIG_DIR'] = str(directory / 'gh-verification-config')
        builders = [self.policy['trusted_builder_commit']] + self.policy.get('previous_builder_commits', [])
        require(1 <= len(builders) <= 3 and all(re.fullmatch(r'[0-9a-f]{40}', b) for b in builders), 'builder allowlist is invalid')
        for builder in builders:
            result = subprocess.run(command + ['--signer-digest', builder], capture_output=True, text=True, timeout=90, env=env)
            if result.returncode == 0:
                break
        require(result.returncode == 0, 'candidate signature, builder or source binding was not verified')
        atomic_json(directory / 'verified-attestation.json', json.loads(result.stdout))

    def reconcile(self, component):
        tag = candidate_tag(component['repository'])
        if not tag:
            return {'component': component['application'], 'status': 'awaiting-candidate'}
        value = json_request('https://github.com/' + component['repository'] + '/releases/download/' + tag + '/security-candidate.json')
        run = json_request('https://api.github.com/repos/' + component['repository'] + '/actions/runs/' + str(value['ci']['run_id']))
        validate_identity(value, component, run)
        require(value['source_commit'] == current_source(component['repository']), 'candidate source has been superseded on master')
        require(tag in ('security-' + value['source_commit'], 'security-' + value['source_commit'] + '-' + str(value['ci']['run_id'])), 'release tag does not match the signed candidate identity')
        self.attestation(component, tag, value)
        if value['source_commit'] != run['head_sha']:
            compare = json_request('https://api.github.com/repos/' + component['repository'] + '/compare/' + run['head_sha'] + '...' + value['source_commit'])
            require(compare.get('ahead_by') == 1 and {f['filename'] for f in compare.get('files', [])} == {'Cargo.lock'}, 'automatic source patch changed more than the tested lockfile')
        app = self.kube('-n', 'argocd', 'get', 'application', component['application'], '-o', 'json')
        require(app['spec']['source']['repoURL'] == 'https://github.com/' + component['repository'] + '.git', 'Application source is outside the component repository')
        old_chart = app['spec']['source']['targetRevision']
        chart = component.get('chart_revision', old_chart)
        if chart != old_chart:
            require(old_chart in component.get('chart_previous_revisions', []), 'chart revision changed outside the reviewed transition')
            comparison = self.history(component['repository'], chart, value['source_commit'])
            require(comparison['status'] in ('ahead', 'identical') and comparison['behind_by'] == 0, 'candidate does not include the reviewed chart revision')
        pods = self.kube('-n', component['namespace'], 'get', 'pods', '-o', 'json')['items']
        deployments = self.kube('-n', component['namespace'], 'get', 'deployments', '-o', 'json')['items']
        repository = 'ghcr.io/' + component['repository'].lower()
        targets = [d for d in deployments if any(image_repository(c['image']) == repository for c in d['spec']['template']['spec']['containers'])]
        require(targets, 'no declared platform Deployments use this component')
        bootstrap = False
        for deployment in targets:
            desired = deployment['spec'].get('replicas', 1)
            initial_controller = (desired == 1 and chart != old_chart
                                  and deployment['metadata']['name'] in component.get('bootstrap_controllers', [])
                                  and deployment['spec'].get('strategy', {}).get('type') == 'Recreate')
            require((desired >= 2 or initial_controller) and deployment.get('status', {}).get('availableReplicas', 0) >= desired, 'platform availability or replica reserve is insufficient')
            bootstrap = bootstrap or initial_controller
        if all(deployment_ready(d) for d in targets) and all(canonical_image(c['image']) == value['image'] for d in targets for c in d['spec']['template']['spec']['containers'] if image_repository(c['image']) == repository):
            return {'component': component['application'], 'status': 'current', 'image': value['image']}
        # Observe connections immediately before mutation, not from the periodic
        # inventory. The forced SSH observer cannot execute mutating commands.
        snapshots = self.snapshots()
        for pod in pods:
            for container in pod['status'].get('containerStatuses', []):
                if image_repository(container.get('image', '')) != repository or 'running' not in container.get('state', {}):
                    continue
                cid = container['containerID'].split('://', 1)[-1]
                tcp = snapshots[pod['spec']['nodeName']]['tasks'].get(cid, {}).get('tcp', {})
                require(tcp.get('status') == 'complete' and tcp.get('inbound_connections') == 0, 'platform connections need to drain before this update')
        before = self.tenants()
        self.health()
        inventory = json.loads(Path(self.args.inventory).read_text())
        require(inventory['status'] == 'complete' and time.time() - datetime.datetime.fromisoformat(inventory['observed_at']).timestamp() < self.policy['inventory_max_age_seconds'], 'fleet security inventory is incomplete or stale')
        references = {canonical_image(c['image']) for p in pods for c in p['spec']['containers'] if image_repository(c['image']) == repository}
        credentials = registry_credentials(self.kubectl, pods)
        old_findings = []
        source_baselines = []
        # Pod status names the architecture-specific manifest; a declared
        # multi-platform index is not the same scan reference. Refresh both
        # sides against the same DB so new advisories are not false regressions.
        for source in deployed_images(pods):
            if image_repository(source['reference']) != repository:
                continue
            old_scan = scan_source(self.args.trivy, Path(self.args.inventory).parent / 'cache', source,
                                   Path(self.args.inventory).parent / 'scan-reports', timeout=300,
                                   registry_auth=credentials.get(source['reference']))
            require(old_scan['status'] == 'complete', 'current deployed image baseline could not be re-scanned')
            old_findings.extend(old_scan['findings'])
            revision = old_scan.get('source_revision')
            if revision:
                compare = self.history(component['repository'], revision, value['source_commit'])
                require(compare.get('status') in ('ahead', 'identical') and compare.get('behind_by') == 0,
                        'candidate does not contain the deployed source history')
                source_proof = source_baseline(component['repository'], revision, source['reference'],
                                               value['inventory']['source_findings'], self.args.trivy,
                                               Path(self.args.inventory).parent / 'cache')
                old_findings.extend(source_proof['findings'])
                source_baselines.append({'image': source['reference'], 'source_commit': revision})
        auth = next((auth for ref, auth in credentials.items() if image_repository(ref) == repository), None)
        scan = scan_source(self.args.trivy, Path(self.args.inventory).parent / 'cache',
                           {'kind': 'image', 'reference': value['image'], 'digest_verified': True},
                           Path(self.args.inventory).parent / 'scan-reports', timeout=300, registry_auth=auth)
        require(scan['status'] == 'complete', 'built candidate re-scan failed')
        fixed = verified_fixes(old_findings, scan['findings'])
        baseline = value.get('baseline') or {}
        if baseline.get('image') in references:
            fixed = sorted(set(fixed) | {f['id'] for f in baseline.get('fixed_advisories', [])})
            old_findings.extend(baseline.get('findings', []))
        require(fixed or value['fixed_advisories'], 'candidate has no observed, verified remediation')
        old_critical = {(v['id'], v['package']) for v in old_findings if v['severity'] in ('CRITICAL', 'HIGH')}
        new_critical = {(v['id'], v['package']) for v in scan['findings'] if v['severity'] in ('CRITICAL', 'HIGH')}
        require(not new_critical - old_critical, 'candidate introduces a new high or critical finding')
        record = {'component': component['application'], 'status': 'eligible', 'image': value['image'],
                  'fixed_advisories': fixed, 'candidate_source': value['source_commit'], 'verified_at': utc_now(),
                  'deployed_source_baselines': source_baselines}
        if not self.args.apply:
            return record
        source = app['spec']['source']
        parameters = source.get('helm', {}).get('parameters', [])
        image_parameter = component.get('image_parameter', 'image.tag')
        require(image_parameter in ('image', 'image.tag'), 'unsupported image parameter')
        require(not any(p['name'] == 'image.repository' for p in parameters), 'an external image repository override is present')
        new_parameters = [p for p in parameters if p['name'] != image_parameter] + [
            {'name': image_parameter, 'value': (value['image'] if image_parameter == 'image' else
             tag + '@' + value['image'].split('@', 1)[1])}]
        normal_parameters = new_parameters
        if bootstrap:
            require(not any(p['name'] == 'controllerUpdateStrategy' for p in parameters), 'bootstrap strategy already has an external override')
            new_parameters = new_parameters + [{'name': 'controllerUpdateStrategy', 'value': 'Recreate'}]
        active_parameters = new_parameters
        atomic_json(self.root / (component['application'] + '-before.json'), {'source_sha256': hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest(), 'tenants': before, 'candidate': record})
        def change(parameters, expected_parameters, target_chart, expected_chart):
            current = self.kube('-n', 'argocd', 'get', 'application', component['application'], '-o', 'json')
            current_parameters = current['spec']['source'].get('helm', {}).get('parameters', [])
            patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                     {'op': 'test', 'path': '/spec/source/repoURL', 'value': source['repoURL']},
                     {'op': 'test', 'path': '/spec/source/targetRevision', 'value': expected_chart}]
            managed = [image_parameter] + (['controllerUpdateStrategy'] if bootstrap else [])
            removals, additions = [], []
            for name in managed:
                tag = next((p for p in parameters if p['name'] == name), None)
                expected = next((p for p in expected_parameters if p['name'] == name), None)
                index = next((i for i, p in enumerate(current_parameters) if p['name'] == name), None)
                require((current_parameters[index] if index is not None else None) == expected,
                        'deployment parameter changed outside security reconciliation')
                if index is not None:
                    if tag:
                        patch.append({'op': 'replace', 'path': '/spec/source/helm/parameters/' + str(index), 'value': tag})
                    else:
                        removals.append(index)
                elif tag:
                    additions.append(tag)
            patch.extend({'op': 'remove', 'path': '/spec/source/helm/parameters/' + str(i)} for i in sorted(removals, reverse=True))
            if additions:
                if 'parameters' in current['spec']['source'].get('helm', {}):
                    patch.extend({'op': 'add', 'path': '/spec/source/helm/parameters/-', 'value': p} for p in additions)
                else:
                    patch.append({'op': 'add', 'path': '/spec/source/helm/parameters', 'value': additions})
            if target_chart != expected_chart:
                patch.append({'op': 'replace', 'path': '/spec/source/targetRevision', 'value': target_chart})
            self.kube('-n', 'argocd', 'patch', 'application', component['application'], '--type=json', '-p', json.dumps(patch), '-o', 'json')
        # Building/scanning can take minutes. Recheck live socket activity at
        # the mutation boundary rather than reuse an earlier idle observation.
        snapshots = self.snapshots()
        for pod in pods:
            for container in pod['status'].get('containerStatuses', []):
                if image_repository(container.get('image', '')) == repository and 'running' in container.get('state', {}):
                    cid = container['containerID'].split('://', 1)[-1]
                    tcp = snapshots[pod['spec']['nodeName']]['tasks'].get(cid, {}).get('tcp', {})
                    require(tcp.get('status') == 'complete' and tcp.get('inbound_connections') == 0, 'platform connections became active while preparing the update')
        require(value['source_commit'] == current_source(component['repository']), 'candidate source changed while preparing the update')
        change(new_parameters, parameters, chart, old_chart)
        try:
            deadline = time.monotonic() + self.policy.get('rollout_timeout_seconds', 600)
            while time.monotonic() < deadline:
                self.health()
                current = self.kube('-n', component['namespace'], 'get', 'deployments', '-o', 'json')['items']
                names = {d['metadata']['name'] for d in targets}
                observed = [d for d in current if d['metadata']['name'] in names]
                if all(deployment_ready(d)
                       and all(canonical_image(c['image']) == value['image'] for c in d['spec']['template']['spec']['containers'] if image_repository(c['image']) == repository)
                       for d in observed) and len(observed) == len(targets):
                    require(before == self.tenants(), 'tenant state or runtime identities changed during the platform update')
                    if bootstrap:
                        require(all(d['spec'].get('replicas', 1) >= 2 for d in observed), 'controller bootstrap did not create standby capacity')
                        change(normal_parameters, new_parameters, chart, chart)
                        active_parameters = normal_parameters
                    return {**record, 'status': 'promoted', 'tenant_tasks_preserved': True, 'completed_at': utc_now()}
                time.sleep(3)
            raise RuntimeError('platform rollout did not pass acceptance before its deadline')
        except BaseException:
            change(parameters, active_parameters, old_chart, chart)
            deadline = time.monotonic() + self.policy.get('rollout_timeout_seconds', 600)
            old_images = {d['metadata']['name']: [c['image'] for c in d['spec']['template']['spec']['containers']] for d in targets}
            while time.monotonic() < deadline:
                current = self.kube('-n', component['namespace'], 'get', 'deployments', '-o', 'json')['items']
                observed = [d for d in current if d['metadata']['name'] in old_images]
                if len(observed) == len(targets) and all(deployment_ready(d) and [c['image'] for c in d['spec']['template']['spec']['containers']] == old_images[d['metadata']['name']] for d in observed):
                    atomic_json(self.root / (component['application'] + '-rollback.json'), {'status': 'rollback-verified', 'observed_at': utc_now(), 'tenant_tasks_preserved': before == self.tenants()})
                    break
                time.sleep(3)
            else:
                atomic_json(self.root / (component['application'] + '-rollback.json'), {'status': 'rollback-unverified', 'observed_at': utc_now()})
                raise RuntimeError('rollback did not recover the previous platform image before its deadline')
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ['policy', 'inventory', 'hosts', 'snapshot-key', 'known-hosts', 'kubeconfig', 'output']:
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--kubectl', default='kubectl')
    parser.add_argument('--trivy', default='/opt/heteronetwork/security/trivy')
    parser.add_argument('--verifier', default='/opt/heteronetwork/security/gh')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--component')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root operator required')
    policy = json.loads(trusted(args.policy).read_text())
    observer = Reconciler(args, policy)
    results = []
    # The hardened service permits writes only below its private output root.
    lock = os.open(Path(args.output) / 'reconciliation.lock', os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for component in policy['components']:
            if args.component and component['application'] != args.component:
                continue
            try:
                result = observer.reconcile(component)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
                result = {'component': component['application'], 'status': 'held', 'reason': type(error).__name__ + ': ' + str(error)[:200]}
            results.append(result)
            atomic_json(Path(args.output) / 'status.json', {'observed_at': utc_now(), 'components': results})
            print(json.dumps(result), flush=True)
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
