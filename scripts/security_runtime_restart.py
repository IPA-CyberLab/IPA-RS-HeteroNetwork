#!/usr/bin/env python3
"""Activate an installed gVisor patch by restarting one sandbox at a time.

The Pod and its PVCs are retained. Each node first passes a real restart canary.
Intent is persisted on the host before stopping a sandbox; a failed artifact is
held rather than retried by the timer. This is deliberately not live migration.
"""
import argparse
import contextlib
import datetime
import decimal
import fcntl
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import time
import urllib.request

from security_inventory import atomic_json, utc_now
from security_runtime_restart_host import require, trusted
from security_update_gate import fingerprint


IMAGE = 'alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8'
OWNER = 'security.heteronetwork.io/restart-canary'


def ready(pod):
    return (pod and not pod['metadata'].get('deletionTimestamp')
            and pod.get('status', {}).get('phase') == 'Running'
            and any(c['type'] == 'Ready' and c['status'] == 'True'
                    for c in pod.get('status', {}).get('conditions', [])))


def eligible(node):
    labels = node['metadata'].get('labels', {})
    return (labels.get('heteronetwork.io/control-plane-only') != 'true'
            and not any(t['key'] in ('node-role.kubernetes.io/control-plane', 'heteronetwork.io/control-plane-only')
                        and t.get('effect') in ('NoSchedule', 'NoExecute') for t in node.get('spec', {}).get('taints', []))
            and labels.get('flash.heterocloud.io/gvisor-ready') == 'true'
            and not node.get('spec', {}).get('unschedulable')
            and any(c['type'] == 'Ready' and c['status'] == 'True'
                    for c in node.get('status', {}).get('conditions', [])))


def memory_bytes(value):
    match = re.fullmatch(r'(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E|m)?', str(value))
    require(match, 'invalid memory limit')
    suffix = match[2] or ''
    scale = {'': 1, 'm': decimal.Decimal('.001'), 'k': 1000, 'M': 1000**2, 'G': 1000**3,
             'T': 1000**4, 'P': 1000**5, 'E': 1000**6,
             **{s + 'i': 1024 ** i for i, s in enumerate('KMGTPE', 1)}}[suffix]
    return int(decimal.Decimal(match[1]) * scale)


def pod_memory_limit(pod):
    def limit(container):
        value = container.get('resources', {}).get('limits', {}).get('memory')
        require(value, 'every restarted container needs a memory limit')
        return memory_bytes(value)
    regular = sum(limit(c) for c in pod['spec']['containers'])
    sidecars, init = 0, 0
    for container in pod['spec'].get('initContainers', []):
        if container.get('restartPolicy') == 'Always':
            sidecars += limit(container)
            init = max(init, sidecars)
        else:
            # Nonrestartable init processes have exited before Ready. An
            # unbounded completed initializer cannot exempt the running Sentry
            # from the application memory bound checked after activation.
            value = container.get('resources', {}).get('limits', {}).get('memory')
            init = max(init, sidecars + (memory_bytes(value) if value else 0))
    declared = pod['spec'].get('resources', {}).get('limits', {}).get('memory')
    maximum = memory_bytes(declared) if declared else max(regular + sidecars, init)
    return maximum + memory_bytes(pod['spec'].get('overhead', {}).get('memory', 0))


class Controller:
    def __init__(self, args, config):
        self.args, self.config, self.policy = args, config, config['restart']
        self.root = Path(args.output)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.hosts = {h['name']: h for h in json.loads(trusted(args.hosts).read_text())}
        self.base = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=15s']
        require(config.get('allow_restart_fallback') is True and config.get('require_live_migration') is False,
                'bounded restart is not authorized')
        require(self.policy['max_parallel_workloads'] == 1 and self.policy['max_attempts_per_artifact'] == 1,
                'only serial, single-attempt restarts are supported')
        require(30 <= self.policy['recovery_timeout_seconds'] <= 600, 'invalid restart deadline')

    def kube(self, *args, body=None, text=False):
        result = subprocess.run(self.base + list(args), input=None if body is None else json.dumps(body),
                                capture_output=True, text=True, timeout=25)
        require(result.returncode == 0, 'Kubernetes restart operation failed')
        return result.stdout if text else (json.loads(result.stdout) if result.stdout.strip() else None)

    def get(self, kind, name, namespace):
        return self.kube('get', kind, name, '-n', namespace, '--ignore-not-found', '-o', 'json')

    def remote(self, node, action='inspect', **fields):
        challenge = secrets.token_hex(32)
        request = {'action': action, 'challenge': challenge, **fields}
        command = ['ssh', '-i', self.args.restart_key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                   '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + self.args.known_hosts,
                   '-o', 'ConnectTimeout=7', 'mizuame@' + self.hosts[node]['ssh_host'], 'runtime-restart']
        response = subprocess.run(command, input=json.dumps(request) + '\n', capture_output=True, text=True,
                                  timeout=self.policy['grace_seconds'] + 60)
        value = json.loads(response.stdout)
        require(response.returncode == 0 and value.get('status') != 'error',
                'worker refused bounded restart: ' + value.get('reason', 'observation unavailable'))
        require(value.get('challenge') == challenge, 'worker did not bind the fresh restart challenge')
        return value

    def health(self):
        nodes = self.kube('get', 'nodes', '-o', 'json')['items']
        require(all(any(c['type'] == 'Ready' and c['status'] == 'True'
                        for c in n.get('status', {}).get('conditions', [])) for n in nodes), 'fleet is not healthy')
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for probe in json.loads(trusted(self.args.health_policy).read_text()).get('health_probes', []):
            started = time.monotonic()
            request = urllib.request.Request(probe['url'], headers={'User-Agent': 'HeteroCloud-Security-Health/1.0'})
            with direct.open(request, timeout=probe['deadline_seconds']) as response:
                require(response.status in probe.get('statuses', [200]), 'platform health failed')
                response.read(1024 * 1024)
            require(time.monotonic() - started <= probe['deadline_seconds'], 'platform health exceeded its deadline')

    def volumes(self, pod):
        claims = [v['persistentVolumeClaim']['claimName'] for v in pod['spec'].get('volumes', [])
                  if 'persistentVolumeClaim' in v]
        require(claims or not self.policy['require_persistent_volume'], 'persistent disk is required for automatic restart')
        result = {}
        for name in claims:
            claim = self.get('pvc', name, pod['metadata']['namespace'])
            require(claim and claim.get('status', {}).get('phase') == 'Bound', 'persistent disk is not bound')
            result[name] = {'uid': claim['metadata']['uid'], 'volume': claim['spec']['volumeName']}
        return result

    def sandbox(self, observation, uid):
        records = [s for s in observation['sandboxes'] if s['metadata']['uid'] == uid]
        require(len(records) == 1, 'exactly one ready sandbox is required')
        return records[0]

    def restart(self, pod, observation, probe=False, recovering=False):
        namespace, name, uid = (pod['metadata'][k] for k in ('namespace', 'name', 'uid'))
        node = pod['spec']['nodeName']
        require((ready(pod) or recovering) and pod['spec'].get('restartPolicy', 'Always') == 'Always', 'only ready, restartable Pods are eligible')
        before = self.get('pod', name, namespace)
        require(before and before['metadata']['uid'] == uid and before['spec'] == pod['spec']
                and (ready(before) or recovering), 'Pod changed before restart')
        volumes = self.volumes(before)
        memory = pod_memory_limit(before)
        source = self.sandbox(observation, uid)
        target = observation['artifact']
        started = time.monotonic()
        self.remote(node, 'restart', pod_uid=uid, sandbox_id=source['id'],
                    source_sha256=source['exe_sha256'], artifact_sha256=target['sha256'], probe=probe)
        deadline = started + self.policy['recovery_timeout_seconds']
        while time.monotonic() < deadline:
            current = self.get('pod', name, namespace)
            require(current and current['metadata']['uid'] == uid and current['spec'] == before['spec'],
                    'Pod configuration changed during restart')
            if ready(current):
                observed = self.remote(node, pod_uid=uid, artifact_sha256=target['sha256'])
                if observed['artifact']['sha256'] != target['sha256']:
                    raise RuntimeError('installed runtime changed during restart')
                matching = [s for s in observed['sandboxes'] if s['metadata']['uid'] == uid and s['id'] != source['id']]
                if len(matching) == 1:
                    active = matching[0]
                    require(active['exe_sha256'] == target['sentry_sha256'], 'new sandbox is not running the target Sentry')
                    require(not any(s['id'] == source['id'] for s in observed['sandboxes']), 'old sandbox is still ready')
                    require(observed.get('source_fenced') is True, 'old sandbox process is still active')
                    require(isinstance(active.get('memory_max'), int) and 0 < active['memory_max'] <= memory,
                            'new sandbox does not enforce the Pod memory limit')
                    require(self.volumes(current) == volumes, 'persistent volume identity changed')
                    seconds = time.monotonic() - started
                    require(seconds <= self.policy['recovery_timeout_seconds'], 'restart recovery deadline exceeded')
                    return {'status': 'restarted', 'strategy': 'bounded_restart', 'restart_fallback': True,
                            'pod_uid': uid, 'pod': name, 'node': node, 'target_artifact': target['sha256'],
                            'source_sandbox': source['id'], 'target_sandbox': active['id'],
                            'target_sentry_sha256': active['exe_sha256'], 'persistent_volumes_retained': True,
                            'source_fenced': True, 'resource_limits_verified': True,
                            'same_pod_uid': True, 'recovery_seconds': round(seconds, 3), 'completed_at': utc_now()}
            time.sleep(2)
        raise RuntimeError('restart recovery deadline exceeded; further automatic restarts are held')

    def canary(self, node, observation):
        identity = observation['artifact']['sha256']
        path = self.root / ('canary-' + node + '-' + identity + '.json')
        if path.exists() and not self.args.probe_only:
            proof = json.loads(path.read_text())
            age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(proof['completed_at'])).total_seconds()
            if proof.get('persistent_data_canary_passed') and 0 <= age <= self.policy['canary_max_age_seconds']:
                return proof
        namespace = self.policy['probe_namespace']
        if not self.get('namespace', namespace, namespace):
            self.kube('create', '-f', '-', '-o', 'json', body={'apiVersion': 'v1', 'kind': 'Namespace',
                      'metadata': {'name': namespace, 'labels': {'pod-security.kubernetes.io/enforce': 'restricted'}}})
        token = secrets.token_hex(16)
        name = 'runtime-restart-' + token[:12]
        labels = {OWNER: token}
        resources = [
            {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
             'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '100Mi'}},
                      **({'storageClassName': self.args.storage_class} if self.args.storage_class else {})}},
            {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
             'spec': {'nodeSelector': {'kubernetes.io/hostname': node}, 'runtimeClassName': self.policy['runtime_class'], 'restartPolicy': 'Always',
                      'terminationGracePeriodSeconds': self.policy['grace_seconds'], 'automountServiceAccountToken': False,
                      'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'fsGroup': 65532,
                                          'seccompProfile': {'type': 'RuntimeDefault'}},
                      'volumes': [{'name': 'persistent', 'persistentVolumeClaim': {'claimName': name}}, {'name': 'temporary', 'emptyDir': {}}],
                      'containers': [{'name': 'probe', 'image': IMAGE,
                                      'command': ['/bin/sh', '-ec', 'test -f /persistent/marker || printf %s ' + token + ' > /persistent/marker; '
                                                  'dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 > /temporary/boot; '
                                                  'exec httpd -f -p 8080 -h /persistent'],
                                      'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                      'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
                                      'readinessProbe': {'httpGet': {'path': '/marker', 'port': 8080}, 'periodSeconds': 2},
                                      'volumeMounts': [{'name': 'persistent', 'mountPath': '/persistent'}, {'name': 'temporary', 'mountPath': '/temporary'}]}]}}
        ]
        created = []
        try:
            for body in resources:
                value = self.kube('create', '-f', '-', '-o', 'json', body=body)
                created.append((value['kind'].lower(), value['metadata']['uid']))
            deadline = time.monotonic() + self.policy['recovery_timeout_seconds']
            while time.monotonic() < deadline:
                pod = self.get('pod', name, namespace)
                if ready(pod):
                    break
                time.sleep(2)
            else:
                raise RuntimeError('restart canary did not become ready')
            boot_before = self.kube('exec', name, '-n', namespace, '--', 'cat', '/temporary/boot', text=True).strip()
            result = self.restart(pod, self.remote(node), probe=True)
            marker = self.kube('exec', name, '-n', namespace, '--', 'cat', '/persistent/marker', text=True).strip()
            boot_after = self.kube('exec', name, '-n', namespace, '--', 'cat', '/temporary/boot', text=True).strip()
            require(marker == token and boot_before and boot_after and boot_before != boot_after,
                    'restart canary did not preserve disk data across a real process restart')
            result.update(persistent_data_canary_passed=True)
            atomic_json(path, result)
            return result
        finally:
            for kind, uid in reversed(created):
                current = self.get(kind, name, namespace)
                if current and current['metadata']['uid'] == uid and current['metadata'].get('labels', {}).get(OWNER) == token:
                    self.kube('delete', kind, name, '-n', namespace, '--wait=false', text=True)
                    if kind == 'pod':
                        deadline = time.monotonic() + 60
                        while self.get(kind, name, namespace) and time.monotonic() < deadline:
                            time.sleep(2)
                        require(not self.get(kind, name, namespace), 'canary cleanup did not finish; its disk was retained')

    def recover(self, pod, rollback):
        namespace, name, uid = (pod['metadata'][k] for k in ('namespace', 'name', 'uid'))
        volumes = self.volumes(pod)
        deadline = time.monotonic() + self.policy['recovery_timeout_seconds']
        stopped = False
        while time.monotonic() < deadline:
            current = self.get('pod', name, namespace)
            require(current and current['metadata']['uid'] == uid and current['spec'] == pod['spec'], 'Pod changed during recovery')
            observation = self.remote(pod['spec']['nodeName'])
            sources = [s for s in observation['sandboxes'] if s['metadata']['uid'] == uid]
            if len(sources) == 1 and sources[0]['exe_sha256'] == rollback['sentry_sha256'] and ready(current):
                require(self.volumes(current) == volumes, 'persistent volume changed during recovery')
                return {'status': 'rollback-verified', 'pod_uid': uid, 'artifact': rollback['sha256'], 'persistent_volumes_retained': True}
            if len(sources) == 1 and sources[0]['exe_sha256'] != rollback['sentry_sha256'] and not stopped:
                # One recovery stop is separate from the failed target's single
                # attempt. A timer never repeats either operation automatically.
                self.restart(current, observation, recovering=True)
                stopped = True
            time.sleep(2)
        raise RuntimeError('previous runtime did not recover before its deadline')

    def reconcile(self, node):
        observed = self.remote(node)
        artifact = observed['artifact']['sha256']
        hold = self.root / ('held-' + node + '-' + artifact + '.json')
        require(not hold.exists(), 'artifact is held after an earlier failure; inspect its recovery record')
        pods = self.kube('get', 'pods', '-n', self.policy['namespace'],
                         '--field-selector=spec.nodeName=' + node, '-o', 'json')['items']
        workloads = []
        for pod in pods:
            if pod['spec'].get('runtimeClassName') != self.policy['runtime_class'] or not ready(pod):
                continue
            source = self.sandbox(observed, pod['metadata']['uid'])
            if source['exe_sha256'] != observed['artifact']['sentry_sha256']:
                workloads.append(pod)
        if not workloads and not self.args.probe_only:
            return {'node': node, 'status': 'current', 'artifact': artifact}
        pending = None
        try:
            proof = self.canary(node, observed)
            results = []
            if workloads and not self.args.probe_only:
                require(observed.get('rollback_sha256') and observed['rollback_sha256'] != artifact,
                        'a verified previous runtime bundle is required before restarting users')
                for pod in workloads:
                    self.health()
                    pending = pod
                    # A single sandbox holds its existing node resource allocation.
                    results.append(self.restart(pod, self.remote(node)))
                    self.health()
                    pending = None
            result = {'node': node, 'status': 'canary-verified' if self.args.probe_only else 'verified',
                      'artifact': artifact, 'canary': proof, 'workloads': results, 'completed_at': utc_now()}
            atomic_json(self.root / (node + '-last-accepted.json'), result)
            return result
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record = {'node': node, 'status': 'held', 'artifact': artifact,
                      'reason': str(error)[:200], 'observed_at': utc_now()}
            if observed.get('rollback_sha256') and observed['rollback_sha256'] != artifact:
                try:
                    rollback = self.remote(node, 'rollback', artifact_sha256=artifact)
                    record['rollback'] = {'status': rollback['status'], 'artifact': rollback['artifact']['sha256']}
                    if pending:
                        record['recovery'] = self.recover(pending, rollback['artifact'])
                    self.health()
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    record['rollback'] = {'status': 'unverified'}
            atomic_json(hold, record)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', default='/opt/heteronetwork/security/policy.json')
    parser.add_argument('--health-policy', default='/opt/heteronetwork/security/promotion.json')
    parser.add_argument('--hosts', default='/etc/heteronetwork/security/hosts.json')
    parser.add_argument('--restart-key', default='/etc/heteronetwork/security/restart.key')
    parser.add_argument('--known-hosts', default='/etc/heteronetwork/security/known_hosts')
    parser.add_argument('--kubeconfig', default='/etc/kubernetes/admin.conf')
    parser.add_argument('--kubectl', default='kubectl')
    parser.add_argument('--output', default='/var/lib/heteronetwork-security/runtime-restart')
    parser.add_argument('--promotion-output', default='/var/lib/heteronetwork-security/promotion')
    parser.add_argument('--inventory', default='/var/lib/heteronetwork-security/cluster/status.json')
    parser.add_argument('--storage-class')
    parser.add_argument('--node')
    parser.add_argument('--probe-only', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root operator required')
    controller = Controller(args, json.loads(trusted(args.policy).read_text()))
    with contextlib.ExitStack() as stack:
        for path in [controller.root / 'reconciliation.lock', Path(args.promotion_output) / 'reconciliation.lock']:
            handle = stack.enter_context(open(path, 'a'))
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inventory = json.loads(trusted(args.inventory).read_text())
        age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(inventory['observed_at'])).total_seconds()
        require(inventory['status'] == 'complete' and 0 <= age <= controller.config['inventory_max_age_seconds'], 'complete, recent inventory required')
        controller.health()
        results = []
        for node in controller.kube('get', 'nodes', '-o', 'json')['items']:
            name = node['metadata']['name']
            if not eligible(node) or name not in controller.hosts or (args.node and name != args.node):
                continue
            try:
                result = controller.reconcile(name)
                results.append(result)
                atomic_json(controller.root / 'status.json', {'observed_at': utc_now(), 'nodes': results})
                print(json.dumps(result), flush=True)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                results.append({'node': name, 'status': 'held', 'reason': str(error)[:200]})
                atomic_json(controller.root / 'status.json', {'observed_at': utc_now(), 'nodes': results})
                raise  # Do not continue to another node after a failure.
        require(results, 'no eligible workload worker matched; no restart acceptance was performed')


if __name__ == '__main__':
    main()
