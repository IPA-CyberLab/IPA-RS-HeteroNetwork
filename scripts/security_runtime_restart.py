#!/usr/bin/env python3
"""Activate an installed gVisor patch by restarting one sandbox at a time.

PVCs are retained; legacy unlimited Pods are replaced after source fencing.
Each node first passes a real restart canary.
Intent is persisted on the host before stopping a sandbox; a failed artifact is
held rather than retried by the timer. This is deliberately not live migration.
"""
import argparse
import contextlib
import datetime
import decimal
import fcntl
import hashlib
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


def probe_command(token):
    require(re.fullmatch(r'[0-9a-f]{32}', token), 'invalid canary marker')
    # Alpine's base BusyBox has nc but deliberately omits the httpd applet.
    # This small HTTP responder uses only commands present in the pinned image.
    return ['/bin/sh', '-ec', 'test -f /persistent/marker || printf %s ' + token + ' > /persistent/marker; '
            'dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 > /temporary/boot; '
            "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 32\\r\\nConnection: close\\r\\n\\r\\n%s' "
            + token + ' | nc -l -p 8080; done']


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


HELPER_RESOURCES = {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}}


def legacy_helper(spec):
    for index, container in enumerate(spec.get('initContainers', [])):
        if (container['name'] == 'flash-secret-launcher'
                and not container.get('resources', {}).get('limits', {}).get('memory')):
            require(container.get('command') == ['/bin/cp', '/usr/local/bin/flash-secret-env-launcher', '/run/flash-helper/launcher'],
                    'unrecognized secret initializer cannot be automatically resized')
            return index
    return None


def template_identity(template):
    value = json.loads(json.dumps(template))
    value.get('metadata', {}).get('labels', {}).pop('pod-template-hash', None)
    for container in value['spec'].get('initContainers', []):
        if container['name'] == 'flash-secret-launcher':
            container.pop('resources', None)
    return fingerprint(value)


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

    def recovery_health(self):
        # A restarted process may be Running before its HTTP listener is ready.
        # Wait within the existing recovery budget; each individual request
        # must still satisfy its configured (three-second) health deadline.
        try:
            self.health()
            return True
        except (OSError, ValueError, RuntimeError):
            return False

    def preflight_storage(self, pod):
        """Refuse a stop while terminal PVC references can block remounting.

        Longhorn versions affected by upstream #13723 reject an existing
        Running Pod's remount when failed/succeeded historical Pods also refer
        to its PVC. A fresh-volume canary alone cannot detect this condition.
        """
        namespace = pod['metadata']['namespace']
        volumes = self.volumes(pod)
        others = self.kube('get', 'pods', '-n', namespace, '-o', 'json')['items']
        for other in others:
            if other.get('status', {}).get('phase') not in ('Failed', 'Succeeded'):
                continue
            claims = {v['persistentVolumeClaim']['claimName'] for v in other['spec'].get('volumes', []) if 'persistentVolumeClaim' in v}
            require(not claims.intersection(volumes), 'terminal Pod references must be cleaned up before stopping a workload with persistent storage')
        for volume in volumes.values():
            pv = self.get('pv', volume['volume'], namespace)
            csi = pv.get('spec', {}).get('csi', {}) if pv else {}
            if csi.get('driver') != 'driver.longhorn.io':
                continue
            record = self.get('volumes.longhorn.io', csi['volumeHandle'], 'longhorn-system')
            require(record and record.get('status', {}).get('robustness') == 'healthy', 'persistent volume is not healthy before restart')
            tracked = record.get('status', {}).get('kubernetesStatus', {}).get('workloadsStatus', [])
            require(not any(p.get('podStatus') in ('Failed', 'Succeeded') for p in tracked),
                    'Longhorn still tracks terminal Pods; wait for storage reconciliation before stopping the workload')

    def sandbox(self, observation, uid):
        records = [s for s in observation['sandboxes'] if s['metadata']['uid'] == uid]
        require(len(records) == 1, 'exactly one ready sandbox is required')
        return records[0]

    def repair_initializer(self, pod, observation):
        if legacy_helper(pod['spec']) is None:
            return pod
        source = self.sandbox(observation, pod['metadata']['uid'])
        usage = source.get('pod_memory')
        require(usage and usage['nonreclaimable'] < pod_memory_limit(pod) * 0.9,
                'initializer resize needs a graceful maintenance window: current resident memory exceeds the declared budget')
        namespace, name, uid = (pod['metadata'][k] for k in ('namespace', 'name', 'uid'))
        owners = [o for o in pod['metadata'].get('ownerReferences', []) if o.get('controller') and o['kind'] == 'ReplicaSet']
        require(len(owners) == 1, 'legacy initializer repair requires a managed workload')
        replica = self.get('replicaset', owners[0]['name'], namespace)
        require(replica and replica['metadata']['uid'] == owners[0]['uid'], 'ReplicaSet identity changed')
        parents = [o for o in replica['metadata'].get('ownerReferences', []) if o.get('controller') and o['kind'] == 'Deployment']
        require(len(parents) == 1, 'legacy initializer repair requires a Deployment')
        deployment = self.get('deployment', parents[0]['name'], namespace)
        require(deployment and deployment['metadata']['uid'] == parents[0]['uid'], 'Deployment identity changed')
        identity = template_identity(deployment['spec']['template'])
        require(template_identity(replica['spec']['template']) == identity, 'wait for the existing workload rollout to finish')
        token = secrets.token_hex(16)
        marker = 'security.heteronetwork.io/initializer-repair'
        paused = deployment['spec'].get('paused', False)

        def patch(kind, resource, operation, subresource=None):
            command = ['patch', kind, resource['metadata']['name'], '-n', namespace, '--type=json',
                       '--field-manager=heteronetwork-security-runtime', '--patch-file=/dev/stdin', '-o', 'json']
            if subresource:
                command += ['--subresource=' + subresource]
            return self.kube(*command, body=[{'op': 'test', 'path': '/metadata/resourceVersion',
                                             'value': resource['metadata']['resourceVersion']}, *operation])

        def set_limit(kind, resource, subresource=None):
            spec = resource['spec'] if kind == 'pod' else resource['spec']['template']['spec']
            index = legacy_helper(spec)
            if index is None:
                return resource
            path = '/spec/initContainers/' if kind == 'pod' else '/spec/template/spec/initContainers/'
            return patch(kind, resource, [{'op': 'add', 'path': path + str(index) + '/resources', 'value': HELPER_RESOURCES}], subresource)

        # Pausing does not stop Pods. Update the existing ReplicaSet before the
        # Deployment so it remains the matching revision (hash label ignored by
        # Kubernetes), then unpause. The /resize subresource preserves Pod UID.
        annotations = dict(deployment['metadata'].get('annotations', {}))
        owned_marker = str(int(paused)) + ':' + token
        annotations[marker] = owned_marker
        deployment = patch('deployment', deployment, [
            {'op': 'add', 'path': '/metadata/annotations', 'value': annotations},
            {'op': 'add', 'path': '/spec/paused', 'value': True}])
        try:
            current = self.get('pod', name, namespace)
            require(current and current['metadata']['uid'] == uid and current['spec'] == pod['spec'], 'Pod changed before initializer repair')
            updated = set_limit('pod', current, 'resize')
            require(legacy_helper(updated['spec']) is None, 'API did not retain the initializer resource limit')
            replica = self.get('replicaset', owners[0]['name'], namespace)
            require(replica and replica['metadata']['uid'] == owners[0]['uid']
                    and template_identity(replica['spec']['template']) == identity, 'ReplicaSet changed during initializer repair')
            set_limit('replicaset', replica)
            deployment = self.get('deployment', parents[0]['name'], namespace)
            require(deployment and template_identity(deployment['spec']['template']) == identity,
                    'workload configuration changed during initializer repair')
            set_limit('deployment', deployment)
        finally:
            current = self.get('deployment', parents[0]['name'], namespace)
            if current and current['metadata']['uid'] == parents[0]['uid'] and current['metadata'].get('annotations', {}).get(marker) == owned_marker:
                values = dict(current['metadata']['annotations'])
                values.pop(marker)
                patch('deployment', current, [{'op': 'add', 'path': '/spec/paused', 'value': paused},
                                              {'op': 'add', 'path': '/metadata/annotations', 'value': values}])
        current = self.get('pod', name, namespace)
        require(current and current['metadata']['uid'] == uid and ready(current), 'initializer repair must retain the running Pod')
        require(self.volumes(current) == self.volumes(pod), 'initializer repair changed persistent storage')
        return current

    def resume_repairs(self):
        """Complete template alignment after an interrupted initializer repair."""
        namespace = self.policy['namespace']
        marker = 'security.heteronetwork.io/initializer-repair'
        deployments = self.kube('get', 'deployments', '-n', namespace, '-o', 'json')['items']
        for deployment in deployments:
            owned = deployment['metadata'].get('annotations', {}).get(marker, '')
            if not re.fullmatch(r'[01]:[0-9a-f]{32}', owned):
                continue
            identity = template_identity(deployment['spec']['template'])
            replicas = self.kube('get', 'replicasets', '-n', namespace, '-o', 'json')['items']
            matched = [r for r in replicas if any(o.get('uid') == deployment['metadata']['uid'] and o.get('controller')
                                                for o in r['metadata'].get('ownerReferences', []))
                       and template_identity(r['spec']['template']) == identity]
            for kind, resource in [('replicaset', r) for r in matched] + [('deployment', deployment)]:
                index = legacy_helper(resource['spec']['template']['spec'])
                if index is not None:
                    self.kube('patch', kind, resource['metadata']['name'], '-n', namespace, '--type=json',
                              '--field-manager=heteronetwork-security-runtime', '--patch-file=/dev/stdin', '-o', 'json', body=[
                                  {'op': 'test', 'path': '/metadata/resourceVersion', 'value': resource['metadata']['resourceVersion']},
                                  {'op': 'add', 'path': '/spec/template/spec/initContainers/' + str(index) + '/resources', 'value': HELPER_RESOURCES}])
            current = self.get('deployment', deployment['metadata']['name'], namespace)
            require(current and current['metadata']['uid'] == deployment['metadata']['uid']
                    and current['metadata'].get('annotations', {}).get(marker) == owned, 'initializer repair ownership changed')
            annotations = dict(current['metadata']['annotations'])
            annotations.pop(marker)
            self.kube('patch', 'deployment', current['metadata']['name'], '-n', namespace, '--type=json',
                      '--field-manager=heteronetwork-security-runtime', '--patch-file=/dev/stdin', '-o', 'json', body=[
                          {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                          {'op': 'add', 'path': '/spec/paused', 'value': owned.startswith('1:')},
                          {'op': 'add', 'path': '/metadata/annotations', 'value': annotations}])

    def restart(self, pod, observation, probe=False, recovering=False):
        if not recovering:
            self.preflight_storage(pod)
        source = self.sandbox(observation, pod['metadata']['uid'])
        if (not recovering and (source.get('memory_max') is None or source['memory_max'] > pod_memory_limit(pod))):
            return self.replace_pod(pod, observation, probe=probe)
        namespace, name, uid = (pod['metadata'][k] for k in ('namespace', 'name', 'uid'))
        node = pod['spec']['nodeName']
        require((ready(pod) or recovering) and pod['spec'].get('restartPolicy', 'Always') == 'Always', 'only ready, restartable Pods are eligible')
        require(not any(c.get('lifecycle', {}).get('preStop') for c in pod['spec']['containers']),
                'preStop hooks require kubelet-managed maintenance; refusing to bypass the declared hook')
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
                    if not self.recovery_health():
                        time.sleep(2)
                        continue
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

    def release_replacement(self, record):
        """Idempotently release an owned scheduling gate, only after fencing.

        This also runs after interruptions. An eviction still in progress keeps
        the gate and Deployment pause in place; a later timer resumes cleanup.
        No second eviction or sandbox stop is issued by this recovery path.
        """
        namespace = record['namespace']
        marker = 'security.heteronetwork.io/runtime-replacement'
        gate = 'security.heteronetwork.io/runtime-maintenance'
        deployment = self.get('deployment', record['deployment'], namespace)
        require(deployment and deployment['metadata']['uid'] == record['deployment_uid'], 'replacement parent identity changed')
        owned = deployment['metadata'].get('annotations', {}).get(marker) == record['token']
        if not owned:
            require(record.get('status') in ('admitted', 'completed', 'aborted'), 'replacement ownership marker changed')
            return self.replacement_candidate(record)
        fence = self.remote(record['source_node'], pod_uid=record['source_pod_uid'], artifact_sha256=record['target_artifact'])
        fenced = fence.get('source_fenced') and not any(s['metadata']['uid'] == record['source_pod_uid'] for s in fence['sandboxes'])
        old = self.get('pod', record['source_pod'], namespace)
        unchanged = old and old['metadata']['uid'] == record['source_pod_uid'] and ready(old)
        require(fenced or unchanged, 'replacement eviction is still draining; maintenance gate retained')
        replica = self.get('replicaset', record['replicaset'], namespace)
        require(replica and replica['metadata']['uid'] == record['replicaset_uid'], 'replacement ReplicaSet identity changed')
        if replica['spec']['template']['spec'].get('schedulingGates') == [{'name': gate}]:
            self.kube('patch', 'replicaset', replica['metadata']['name'], '-n', namespace, '--type=json',
                      '--patch-file=/dev/stdin', '-o', 'json', body=[
                          {'op': 'test', 'path': '/metadata/resourceVersion', 'value': replica['metadata']['resourceVersion']},
                          {'op': 'remove', 'path': '/spec/template/spec/schedulingGates'}])
        candidate = self.replacement_candidate(record)
        if fenced and candidate and candidate['spec'].get('schedulingGates') == [{'name': gate}]:
            candidate = self.kube('patch', 'pod', candidate['metadata']['name'], '-n', namespace, '--type=json',
                                  '--patch-file=/dev/stdin', '-o', 'json', body=[
                                      {'op': 'test', 'path': '/metadata/resourceVersion', 'value': candidate['metadata']['resourceVersion']},
                                      {'op': 'remove', 'path': '/spec/schedulingGates'}])
        require(fenced or candidate is None, 'an unfenced source cannot release a replacement')
        annotations = dict(deployment['metadata']['annotations'])
        annotations.pop(marker)
        record['status'] = 'admitted' if fenced else 'aborted'
        atomic_json(self.root / ('replacement-' + record['source_pod_uid'] + '.json'), record)
        self.kube('patch', 'deployment', deployment['metadata']['name'], '-n', namespace, '--type=json',
                  '--patch-file=/dev/stdin', '-o', 'json', body=[
                      {'op': 'test', 'path': '/metadata/resourceVersion', 'value': deployment['metadata']['resourceVersion']},
                      {'op': 'add', 'path': '/spec/paused', 'value': record['token'].startswith('1:')},
                      {'op': 'add', 'path': '/metadata/annotations', 'value': annotations}])
        return candidate

    def replacement_candidate(self, record):
        pods = self.kube('get', 'pods', '-n', record['namespace'], '-o', 'json')['items']
        candidates = [p for p in pods if p['metadata']['uid'] != record['source_pod_uid']
                      and not p['metadata'].get('deletionTimestamp')
                      and any(o.get('uid') == record['replicaset_uid'] and o.get('controller')
                              for o in p['metadata'].get('ownerReferences', []))]
        require(len(candidates) <= 1, 'replacement has more than one candidate')
        return candidates[0] if candidates else None

    def resume_replacements(self):
        for path in self.root.glob('replacement-*.json'):
            record = json.loads(trusted(path).read_text())
            if record.get('status') == 'completed':
                deployment = self.get('deployment', record['deployment'], record['namespace'])
                if deployment and deployment['metadata'].get('annotations', {}).get('security.heteronetwork.io/runtime-replacement') == record['token']:
                    self.release_replacement(record)
                    record['status'] = 'completed'
                    atomic_json(path, record)
                continue
            self.release_replacement(record)
            atomic_json(self.root / ('held-' + record['source_node'] + '-' + record['target_artifact'] + '.json'),
                        {'status': 'held', 'reason': 'an interrupted Pod replacement requires review; cleanup resumed without repeating its stop',
                         'observed_at': utc_now()})

    def replace_pod(self, pod, observation, probe=False):
        """Recreate a legacy Pod whose kubelet allocation cached an unlimited init.

        A temporary scheduling gate prevents the replacement from starting
        before the old sandbox is fenced. The Deployment stays paused while its
        ReplicaSet template is temporarily gated; no extra revision is created.
        """
        namespace, name, uid = (pod['metadata'][k] for k in ('namespace', 'name', 'uid'))
        source_node = pod['spec']['nodeName']
        target = observation['artifact']
        require(ready(pod), 'replacement requires a ready source Pod')
        require(pod['spec'].get('terminationGracePeriodSeconds', 30) <= self.policy['recovery_timeout_seconds'] - 30,
                'declared termination grace exceeds the bounded maintenance window')
        owners = [o for o in pod['metadata'].get('ownerReferences', []) if o.get('controller') and o['kind'] == 'ReplicaSet']
        require(len(owners) == 1, 'bounded replacement requires a managed ReplicaSet')
        replica = self.get('replicaset', owners[0]['name'], namespace)
        require(replica and replica['metadata']['uid'] == owners[0]['uid'], 'replacement ReplicaSet changed')
        require(replica['spec'].get('replicas', 1) == 1, 'bounded legacy replacement currently requires one replica')
        parents = [o for o in replica['metadata'].get('ownerReferences', []) if o.get('controller') and o['kind'] == 'Deployment']
        require(len(parents) == 1, 'replacement requires a Deployment')
        deployment = self.get('deployment', parents[0]['name'], namespace)
        require(deployment and deployment['metadata']['uid'] == parents[0]['uid'], 'replacement Deployment changed')
        require(template_identity(deployment['spec']['template']) == template_identity(replica['spec']['template']),
                'an existing rollout must finish before replacement')
        volumes = self.volumes(pod)
        before_template = fingerprint(deployment['spec']['template'])
        marker = 'security.heteronetwork.io/runtime-replacement'
        gate = 'security.heteronetwork.io/runtime-maintenance'
        require(not replica['spec']['template']['spec'].get('schedulingGates'), 'another scheduling gate is already present')
        paused = deployment['spec'].get('paused', False)
        token = str(int(paused)) + ':' + secrets.token_hex(16)
        annotations = dict(deployment['metadata'].get('annotations', {}))
        annotations[marker] = token

        def patch(kind, resource, operations):
            return self.kube('patch', kind, resource['metadata']['name'], '-n', namespace, '--type=json',
                             '--field-manager=heteronetwork-security-runtime', '--patch-file=/dev/stdin', '-o', 'json', body=[
                                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': resource['metadata']['resourceVersion']}, *operations])

        # The reservation is durable before API deletion. Its source PID and
        # start time provide fencing evidence even after the Pod object is gone.
        self.remote(source_node, 'reserve', pod_uid=uid,
                    sandbox_id=self.sandbox(observation, uid)['id'],
                    source_sha256=self.sandbox(observation, uid)['exe_sha256'], artifact_sha256=target['sha256'], probe=probe)
        journal = {'namespace': namespace, 'source_node': source_node, 'source_pod': name, 'source_pod_uid': uid,
                   'target_artifact': target['sha256'], 'deployment': deployment['metadata']['name'],
                   'deployment_uid': deployment['metadata']['uid'], 'replicaset': replica['metadata']['name'],
                   'replicaset_uid': replica['metadata']['uid'], 'token': token, 'status': 'prepared', 'started_at': utc_now()}
        journal_path = self.root / ('replacement-' + uid + '.json')
        atomic_json(journal_path, journal)
        deployment = patch('deployment', deployment, [
            {'op': 'add', 'path': '/metadata/annotations', 'value': annotations}, {'op': 'add', 'path': '/spec/paused', 'value': True}])
        started = time.monotonic()
        candidate = None
        try:
            replica = self.get('replicaset', replica['metadata']['name'], namespace)
            patch('replicaset', replica, [{'op': 'add', 'path': '/spec/template/spec/schedulingGates', 'value': [{'name': gate}]}])
            eviction = {'apiVersion': 'policy/v1', 'kind': 'Eviction', 'metadata': {'namespace': namespace, 'name': name},
                        'deleteOptions': {'preconditions': {'uid': uid}}}
            self.kube('create', '--raw=/api/v1/namespaces/' + namespace + '/pods/' + name + '/eviction', '-f', '-', body=eviction)
            deadline = started + self.policy['recovery_timeout_seconds']
            while time.monotonic() < deadline:
                fence = self.remote(source_node, pod_uid=uid, artifact_sha256=target['sha256'])
                if fence.get('source_fenced') and not any(s['metadata']['uid'] == uid for s in fence['sandboxes']):
                    break
                time.sleep(2)
            else:
                raise RuntimeError('old sandbox could not be fenced before replacement')
            while time.monotonic() < deadline:
                pods = self.kube('get', 'pods', '-n', namespace, '-o', 'json')['items']
                candidates = [p for p in pods if p['metadata']['uid'] != uid and not p['metadata'].get('deletionTimestamp')
                              and any(o.get('uid') == replica['metadata']['uid'] and o.get('controller')
                                      for o in p['metadata'].get('ownerReferences', []))]
                if len(candidates) == 1:
                    candidate = candidates[0]
                    break
                time.sleep(2)
            require(candidate, 'replacement Pod was not created')
            require(candidate['spec'].get('schedulingGates') == [{'name': gate}], 'replacement did not inherit the maintenance gate')
            replica = self.get('replicaset', replica['metadata']['name'], namespace)
            patch('replicaset', replica, [{'op': 'remove', 'path': '/spec/template/spec/schedulingGates'}])
            candidate = patch('pod', candidate, [{'op': 'remove', 'path': '/spec/schedulingGates'}])
            while time.monotonic() < deadline:
                current = self.get('pod', candidate['metadata']['name'], namespace)
                if ready(current):
                    active_node = current['spec']['nodeName']
                    observed = self.remote(active_node)
                    active = self.sandbox(observed, current['metadata']['uid'])
                    require(observed['artifact']['sha256'] == target['sha256'] and active['exe_sha256'] == target['sentry_sha256'],
                            'replacement started on an unverified runtime artifact')
                    require(isinstance(active.get('memory_max'), int) and 0 < active['memory_max'] <= pod_memory_limit(current),
                            'replacement did not enforce the workload memory limit')
                    require(self.volumes(current) == volumes, 'replacement changed persistent storage')
                    latest = self.get('deployment', deployment['metadata']['name'], namespace)
                    require(fingerprint(latest['spec']['template']) == before_template, 'replacement changed the user workload template')
                    if not self.recovery_health():
                        time.sleep(2)
                        continue
                    require(time.monotonic() <= deadline, 'replacement recovery deadline exceeded')
                    journal['status'] = 'completed'
                    atomic_json(journal_path, journal)
                    return {'status': 'restarted', 'strategy': 'bounded_pod_replacement', 'restart_fallback': True,
                            'source_pod_uid': uid, 'pod_uid': current['metadata']['uid'], 'pod': current['metadata']['name'], 'node': active_node,
                            'source_node': source_node, 'target_artifact': target['sha256'], 'target_sentry_sha256': active['exe_sha256'],
                            'persistent_volumes_retained': True, 'source_fenced': True, 'resource_limits_verified': True,
                            'same_pod_uid': False, 'workload_identity_preserved': True, 'template_preserved': True,
                            'replacement_resources_ready': True, 'restart_budget_respected': True,
                            'recovery_seconds': round(time.monotonic() - started, 3), 'completed_at': utc_now()}
                time.sleep(2)
            raise RuntimeError('replacement did not become ready before the recovery deadline')
        finally:
            completed = journal['status'] == 'completed'
            self.release_replacement(journal)
            if completed:
                journal['status'] = 'completed'
                atomic_json(journal_path, journal)

    def canary(self, node, observation):
        identity = observation['artifact']['sha256']
        code = fingerprint({'controller': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            'host_endpoint': hashlib.sha256(Path(__file__).with_name('security_runtime_restart_host.py').read_bytes()).hexdigest(),
                            'policy': self.policy, 'image': IMAGE})
        path = self.root / ('canary-' + node + '-' + identity + '.json')
        if path.exists() and not self.args.probe_only:
            proof = json.loads(path.read_text())
            age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(proof['completed_at'])).total_seconds()
            if (proof.get('persistent_data_canary_passed') and proof.get('acceptance_code_sha256') == code
                    and 0 <= age <= self.policy['canary_max_age_seconds']):
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
                                      'command': probe_command(token),
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
            result.update(persistent_data_canary_passed=True, acceptance_code_sha256=code)
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
        atomic_json(path, result)
        return result

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
                if not self.recovery_health():
                    time.sleep(2)
                    continue
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
        require(self.args.probe_only or observed['artifact']['version'] == 'runsc version ' + self.policy['target_runtime_version'],
                'the approved target must be reinstalled after rollback; healthy workloads are never downgraded by the timer')
        artifact = observed['artifact']['sha256']
        hold = self.root / ('held-' + node + '-' + artifact + '.json')
        require(self.args.probe_only or not hold.exists(), 'artifact is held after an earlier failure; inspect its recovery record')
        pods = self.kube('get', 'pods', '-n', self.policy['namespace'],
                         '--field-selector=spec.nodeName=' + node, '-o', 'json')['items']
        workloads = []
        for pod in pods:
            if pod['spec'].get('runtimeClassName') != self.policy['runtime_class'] or not ready(pod):
                continue
            source = self.sandbox(observed, pod['metadata']['uid'])
            if source['exe_sha256'] != observed['artifact']['sentry_sha256']:
                workloads.append(pod)
        for pod in workloads:
            self.preflight_storage(pod)
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
                    pod = self.repair_initializer(pod, self.remote(node))
                    pending = pod
                    print(json.dumps({'event': 'workload-restart-started', 'node': node, 'pod': pod['metadata']['name'],
                                      'pod_uid': pod['metadata']['uid'], 'started_at': utc_now()}), flush=True)
                    # A single sandbox holds its existing node resource allocation.
                    restarted = self.restart(pod, self.remote(node))
                    results.append(restarted)
                    atomic_json(self.root / ('workload-' + restarted['pod_uid'] + '-last-accepted.json'), restarted)
                    print(json.dumps({'event': 'workload-restart-verified', **restarted}), flush=True)
                    if not restarted['same_pod_uid']:
                        pending = self.get('pod', restarted['pod'], pod['metadata']['namespace'])
                    self.health()
                    pending = None
            result = {'node': node, 'status': 'canary-verified' if self.args.probe_only else 'verified',
                      'artifact': artifact, 'canary': proof, 'workloads': results, 'completed_at': utc_now()}
            atomic_json(self.root / (node + '-last-accepted.json'), result)
            return result
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record = {'node': node, 'status': 'held', 'artifact': artifact,
                      'reason': str(error)[:200], 'observed_at': utc_now()}
            if not self.args.probe_only and observed.get('rollback_sha256') and observed['rollback_sha256'] != artifact:
                try:
                    rollback = self.remote(node, 'rollback', artifact_sha256=artifact)
                    record['rollback'] = {'status': rollback['status'], 'artifact': rollback['artifact']['sha256']}
                    if pending:
                        replacement_path = self.root / ('replacement-' + pending['metadata']['uid'] + '.json')
                        if replacement_path.exists():
                            journal = json.loads(trusted(replacement_path).read_text())
                            candidate = self.release_replacement(journal)
                            if candidate:
                                pending = candidate
                        active_node = pending['spec'].get('nodeName')
                        deadline = time.monotonic() + self.policy['recovery_timeout_seconds']
                        while not active_node and time.monotonic() < deadline:
                            pending = self.get('pod', pending['metadata']['name'], pending['metadata']['namespace'])
                            active_node = pending['spec'].get('nodeName')
                            time.sleep(2)
                        require(active_node, 'replacement recovery has not been scheduled')
                        if active_node != node:
                            current = self.remote(active_node)
                            if current['artifact']['sha256'] == artifact:
                                rollback = self.remote(active_node, 'rollback', artifact_sha256=artifact)
                            else:
                                require(current['artifact']['sha256'] == rollback['artifact']['sha256'], 'recovery runtime differs on the destination node')
                        record['recovery'] = self.recover(pending, rollback['artifact'])
                    self.health()
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    record['rollback'] = {'status': 'unverified'}
            atomic_json(self.root / (node + '-probe-failed.json') if self.args.probe_only else hold, record)
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
        controller.resume_replacements()
        controller.resume_repairs()
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
