#!/usr/bin/env python3
"""Verify a live standard node, including scheduled Pods and network traffic."""
import argparse
import copy
import datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time


def k(args, obj=None, check=True):
    return subprocess.run(['kubectl', '--request-timeout=15s', *args],
                          input=None if obj is None else json.dumps(obj),
                          text=True, capture_output=True, check=check, timeout=30)


def get(resource, *args):
    return json.loads(k(['get', resource, *args, '-o', 'json']).stdout)


def endpoint_slice_has_ready_address(slices, address):
    """Return whether an EndpointSlice publishes address as usable."""
    for endpoint_slice in slices.get('items', []):
        for endpoint in endpoint_slice.get('endpoints', []):
            conditions = endpoint.get('conditions', {})
            if (address in endpoint.get('addresses', []) and
                    conditions.get('ready') is not False and
                    conditions.get('terminating') is not True):
                return True
    return False


def wait_for_service_endpoint(namespace, service, address, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        slices = get('endpointslices.discovery.k8s.io', '-n', namespace, '-l',
                     'kubernetes.io/service-name=' + service)
        if endpoint_slice_has_ready_address(slices, address):
            return
        time.sleep(1)
    raise RuntimeError('Service did not publish the ready server endpoint')


_AUTHORIZATION_HEADER = re.compile(r'(?im)\bauthorization\s*:\s*[^\r\n]*')
_SENSITIVE_LOG_VALUE = re.compile(
    r'(?i)\b(bearer|token|password|passwd|secret|api[_-]?key)'
    r'(\s*[:=]\s*|\s+)([^\s]+)')


def safe_log(text, limit=16384):
    """Bound diagnostics and redact common credential-shaped log values."""
    text = ''.join(c for c in text if c in '\n\r\t' or ord(c) >= 32)
    text = _AUTHORIZATION_HEADER.sub('Authorization: [redacted]', text)
    text = _SENSITIVE_LOG_VALUE.sub(lambda match:
        match.group(1) + match.group(2) + '[redacted]', text)
    encoded = text.encode('utf-8')
    if len(encoded) > limit:
        text = encoded[:limit].decode('utf-8', errors='ignore') + '\n[truncated]'
    return text


def pod_diagnostics(namespace):
    """Collect bounded, non-secret diagnostics before the test namespace is removed."""
    try:
        response = k(['get', 'pods', '-n', namespace, '-o', 'json'], check=False)
    except Exception as error:
        return {'collection_error': safe_log(type(error).__name__ + ': ' + str(error), 2048)}
    if response.returncode:
        return {'collection_error': safe_log(response.stderr, 2048)}
    try:
        pods = json.loads(response.stdout).get('items', [])
    except (json.JSONDecodeError, AttributeError) as error:
        return {'collection_error': safe_log(type(error).__name__ + ': ' + str(error), 2048)}
    diagnostics = {}
    for pod in pods:
        name = pod.get('metadata', {}).get('name', '')
        if not name:
            continue
        statuses = []
        for container in pod.get('status', {}).get('containerStatuses', []):
            state = container.get('state', {})
            state_name = next((kind for kind in ('terminated', 'waiting', 'running')
                               if kind in state), 'unknown')
            details = state.get(state_name, {})
            statuses.append({
                'name': container.get('name'),
                'ready': container.get('ready', False),
                'restart_count': container.get('restartCount', 0),
                'state': state_name,
                'reason': details.get('reason'),
                'exit_code': details.get('exitCode'),
                'signal': details.get('signal'),
            })
        entry = {
            'phase': pod.get('status', {}).get('phase'),
            'node': pod.get('spec', {}).get('nodeName'),
            'containers': statuses,
        }
        try:
            logs = k(['logs', name, '-n', namespace, '--all-containers=true',
                      '--tail=100', '--limit-bytes=16384'], check=False)
            if logs.stdout:
                entry['log'] = safe_log(logs.stdout)
            if logs.returncode and logs.stderr:
                entry['log_error'] = safe_log(logs.stderr, 2048)
        except Exception as error:
            entry['log_error'] = safe_log(type(error).__name__ + ': ' + str(error), 2048)
        diagnostics[name] = entry
    return diagnostics


def write_report(path, report):
    if not path:
        return
    output = Path(path)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    output.chmod(0o600)


def record_failure(report, output, namespace, error):
    report.update({
        'passed': False,
        'failure': {'type': type(error).__name__, 'message': safe_log(str(error), 1024)},
        'pod_diagnostics': pod_diagnostics(namespace),
    })
    write_report(output, report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', default='uc-k8sp4')
    parser.add_argument('--peer', default='uc-k8sp5')
    parser.add_argument('--output')
    parser.add_argument('--exercise-storage', action='store_true')
    parser.add_argument('--allow-onboarding-pending', action='store_true')
    args = parser.parse_args()
    node = get('node', args.node)
    assert any(c['type'] == 'Ready' and c['status'] == 'True'
               for c in node['status']['conditions'])
    assert not node['spec'].get('unschedulable', False)
    assert 'node-role.kubernetes.io/control-plane' in node['metadata']['labels']
    assert node['metadata']['labels']['heteronetwork.io/control-plane-only'] == 'false'
    assert node['metadata']['labels']['networking.heteronetwork.io/public-ingress'] == 'true'
    assert 'node.kubernetes.io/exclude-from-external-load-balancers' not in node['metadata']['labels']
    onboarding_taint = {'key': 'heteronetwork.io/onboarding', 'value': 'pending', 'effect': 'NoSchedule'}
    if args.allow_onboarding_pending:
        assert onboarding_taint in node['spec'].get('taints', [])
        assert node['metadata']['annotations']['heteronetwork.io/onboarding-status'] == 'pending'
    assert not any(t['effect'] in ['NoSchedule', 'NoExecute'] and
                   not (args.allow_onboarding_pending and t == onboarding_taint)
                   for t in node['spec'].get('taints', []))
    storage_node = get('nodes.longhorn.io', args.node, '-n', 'longhorn-system')
    assert storage_node['spec']['allowScheduling']
    disks = storage_node['status'].get('diskStatus', {})
    assert disks and any(all(any(c['type'] == kind and c['status'] == 'True'
                                for c in d.get('conditions', [])) for kind in ['Ready', 'Schedulable'])
                         for d in disks.values())
    app = get('application', 'standard-nodes', '-n', 'argocd')
    assert app['status']['sync']['status'] == 'Synced'
    assert app['status']['health']['status'] == 'Healthy'
    fixture = copy.deepcopy(node)
    fixture.pop('status', None)
    fixture['metadata'].pop('managedFields', None)
    kept = {'key': 'hnn-e2e-preserved', 'value': 'true', 'effect': 'PreferNoSchedule'}
    fixture['spec']['taints'] = [kept,
        {'key': 'node-role.kubernetes.io/control-plane', 'effect': 'NoSchedule'},
        {'key': 'heteronetwork.io/control-plane-only', 'value': 'true', 'effect': 'NoExecute'}]
    fixture['metadata']['labels']['node.kubernetes.io/exclude-from-external-load-balancers'] = ''
    mutated = json.loads(k(['replace', '--dry-run=server', '-f', '-', '-o', 'json'], fixture).stdout)
    assert mutated['spec']['taints'] == [kept]
    assert 'node.kubernetes.io/exclude-from-external-load-balancers' not in mutated['metadata']['labels']
    ns = 'hnn-standard-e2e-' + str(int(time.time()))
    k(['create', '-f', '-'], {'apiVersion': 'v1', 'kind': 'Namespace',
                            'metadata': {'name': ns}})
    report = {'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'node': args.node, 'schedulable_control_plane': True, 'longhorn_scheduling': True,
              'standard_admission_preserves_other_taints': True,
              'argocd': {'sync': 'Synced', 'health': 'Healthy',
                         'revision': app['status']['sync']['revision']}}
    try:
        def pod(name, host, image, command, labels=None):
            p = {'apiVersion': 'v1', 'kind': 'Pod',
                    'metadata': {'name': name, 'namespace': ns, 'labels': labels or {}},
                    'spec': {'restartPolicy': 'Never',
                             'nodeSelector': {'kubernetes.io/hostname': host},
                             'containers': [{'name': 'test', 'image': image, 'command': command,
                                             'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                                           'limits': {'memory': '64Mi'}}}]}}
            if args.allow_onboarding_pending and host == args.node:
                p['spec']['tolerations'] = [{**onboarding_taint, 'operator': 'Equal'}]
            return p
        if args.allow_onboarding_pending:
            probe = pod('quarantine-check', args.node, 'busybox:1.37', ['true'])
            probe['spec'].pop('tolerations')
            k(['create', '-f', '-'], probe)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                p = get('pod', 'quarantine-check', '-n', ns)
                if any(c['type'] == 'PodScheduled' and c['status'] == 'False' and
                       c.get('reason') == 'Unschedulable' and 'untolerated taint' in c.get('message', '')
                       for c in p['status'].get('conditions', [])):
                    assert not p['spec'].get('nodeName')
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Onboarding quarantine did not block ordinary Pod placement')
            report['quarantine_blocks_ordinary_pod_placement'] = True
        server = pod('server', args.node, 'busybox:1.37', ['sh', '-ec',
                     'mkdir /tmp/web; echo hnn-standard-node-ok >/tmp/web/index.html; '
                     'exec httpd -f -p 8080 -h /tmp/web'], {'hnn-standard-e2e': 'server'})
        k(['create', '-f', '-'], server)
        k(['create', '-f', '-'], {'apiVersion': 'v1', 'kind': 'Service',
            'metadata': {'name': 'server', 'namespace': ns},
            'spec': {'selector': {'hnn-standard-e2e': 'server'},
                     'ports': [{'port': 80, 'targetPort': 8080}]}})
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            p = get('pod', 'server', '-n', ns)
            if any(c['type'] == 'Ready' and c['status'] == 'True'
                   for c in p['status'].get('conditions', [])):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Standard node could not start the ordinary server Pod')
        server_ip = p['status']['podIP']
        wait_for_service_endpoint(ns, 'server', server_ip)
        for name, host in [('local-client', args.node), ('peer-client', args.peer)]:
            command = ['sh', '-ec',
                'curl -fsS --connect-timeout 5 --max-time 15 http://server/; '
                'curl -fsS --connect-timeout 5 --max-time 15 http://' + server_ip + ':8080/; '
                'curl -fsS --connect-timeout 5 --max-time 15 '
                '--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt '
                'https://kubernetes.default.svc/version; echo HNN_E2E_OK']
            k(['create', '-f', '-'], pod(name, host, 'curlimages/curl:8.12.1', command))
        results = []
        deadline = time.monotonic() + 600
        for name, host in [('local-client', args.node), ('peer-client', args.peer)]:
            while time.monotonic() < deadline:
                p = get('pod', name, '-n', ns)
                if p['status']['phase'] in ['Succeeded', 'Failed']:
                    break
                time.sleep(2)
            assert p['status']['phase'] == 'Succeeded', (name, p['status']['phase'])
            assert p['spec']['nodeName'] == host
            log = k(['logs', name, '-n', ns]).stdout
            assert log.count('hnn-standard-node-ok') == 2 and 'HNN_E2E_OK' in log
            results.append({'node': host, 'default_scheduler_placement': True,
                            'dns_and_service_http': True, 'direct_pod_http': True,
                            'kubernetes_service_tls_with_cluster_ca': True})
        report.update({'pod_network_e2e': results, 'passed': True})
        if args.exercise_storage:
            k(['create', '-f', '-'], {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
                'metadata': {'name': 'data', 'namespace': ns},
                'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'longhorn-syouyu-local',
                         'resources': {'requests': {'storage': '1Gi'}}}})
            def storage_pod(name, command):
                p = pod(name, args.node, 'busybox:1.37', ['sh', '-ec', command])
                p['spec']['volumes'] = [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'data'}}]
                p['spec']['containers'][0]['volumeMounts'] = [{'name': 'data', 'mountPath': '/data'}]
                p['spec']['terminationGracePeriodSeconds'] = 1
                return p
            def ready(name):
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    p = get('pod', name, '-n', ns)
                    if any(c['type'] == 'Ready' and c['status'] == 'True'
                           for c in p['status'].get('conditions', [])):
                        assert p['spec']['nodeName'] == args.node
                        return
                    time.sleep(2)
                raise RuntimeError('Storage Pod did not become Ready: ' + name)
            k(['create', '-f', '-'], storage_pod('writer',
                'echo hnn-standard-pvc-ok >/data/probe; sync; exec sleep 600'))
            ready('writer')
            claim = get('pvc', 'data', '-n', ns)
            assert claim['status']['phase'] == 'Bound'
            volume = claim['spec']['volumeName']
            replicas = [r for r in get('replicas.longhorn.io', '-n', 'longhorn-system')['items']
                        if r['spec']['volumeName'] == volume]
            assert len(replicas) == 1 and replicas[0]['spec']['nodeID'] == args.node
            k(['delete', 'pod', 'writer', '-n', ns, '--wait=true', '--timeout=20s'])
            k(['create', '-f', '-'], storage_pod('reader',
                'test "$(cat /data/probe)" = hnn-standard-pvc-ok; exec sleep 600'))
            ready('reader')
            assert k(['exec', 'reader', '-n', ns, '--', 'cat', '/data/probe']).stdout.strip() == 'hnn-standard-pvc-ok'
            report['storage_e2e'] = {'pvc_bound': True, 'replica_node': args.node,
                                     'write_sync_and_read_after_pod_recreation': True}
    except Exception as error:
        failure_report = record_failure(report, args.output, ns, error)
        print(json.dumps(failure_report, ensure_ascii=False), file=sys.stderr)
        raise
    finally:
        k(['delete', 'namespace', ns, '--wait=false'], check=False)
    write_report(args.output, report)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
