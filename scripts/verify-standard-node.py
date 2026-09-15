#!/usr/bin/env python3
"""Verify a live standard node, including scheduled Pods and network traffic."""
import argparse
import copy
import datetime
import json
from pathlib import Path
import subprocess
import time


def k(args, obj=None, check=True):
    return subprocess.run(['kubectl', '--request-timeout=15s', *args],
                          input=None if obj is None else json.dumps(obj),
                          text=True, capture_output=True, check=check, timeout=30)


def get(resource, *args):
    return json.loads(k(['get', resource, *args, '-o', 'json']).stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', default='uc-k8sp4')
    parser.add_argument('--peer', default='uc-k8sp5')
    parser.add_argument('--output')
    args = parser.parse_args()
    node = get('node', args.node)
    assert any(c['type'] == 'Ready' and c['status'] == 'True'
               for c in node['status']['conditions'])
    assert not node['spec'].get('unschedulable', False)
    assert 'node-role.kubernetes.io/control-plane' in node['metadata']['labels']
    assert node['metadata']['labels']['heteronetwork.io/control-plane-only'] == 'false'
    assert node['metadata']['labels']['networking.heteronetwork.io/public-ingress'] == 'true'
    assert 'node.kubernetes.io/exclude-from-external-load-balancers' not in node['metadata']['labels']
    assert not any(t['effect'] in ['NoSchedule', 'NoExecute'] for t in node['spec'].get('taints', []))
    assert get('nodes.longhorn.io', args.node, '-n', 'longhorn-system')['spec']['allowScheduling']
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
            return {'apiVersion': 'v1', 'kind': 'Pod',
                    'metadata': {'name': name, 'namespace': ns, 'labels': labels or {}},
                    'spec': {'restartPolicy': 'Never',
                             'nodeSelector': {'kubernetes.io/hostname': host},
                             'containers': [{'name': 'test', 'image': image, 'command': command,
                                             'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                                                           'limits': {'memory': '64Mi'}}}]}}
        server = pod('server', args.node, 'busybox:1.37', ['sh', '-ec',
                     'mkdir /tmp/web; echo hnn-standard-node-ok >/tmp/web/index.html; '
                     'exec httpd -f -p 8080 -h /tmp/web'], {'hnn-standard-e2e': 'server'})
        k(['create', '-f', '-'], server)
        k(['create', '-f', '-'], {'apiVersion': 'v1', 'kind': 'Service',
            'metadata': {'name': 'server', 'namespace': ns},
            'spec': {'selector': {'hnn-standard-e2e': 'server'},
                     'ports': [{'port': 80, 'targetPort': 8080}]}})
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            p = get('pod', 'server', '-n', ns)
            if any(c['type'] == 'Ready' and c['status'] == 'True'
                   for c in p['status'].get('conditions', [])):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Standard node could not start the ordinary server Pod')
        server_ip = p['status']['podIP']
        for name, host in [('local-client', args.node), ('peer-client', args.peer)]:
            command = ['sh', '-ec',
                'curl -fsS --connect-timeout 5 --max-time 15 http://server/; '
                'curl -fsS --connect-timeout 5 --max-time 15 http://' + server_ip + ':8080/; '
                'curl -fsS --connect-timeout 5 --max-time 15 '
                '--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt '
                'https://kubernetes.default.svc/version; echo HNN_E2E_OK']
            k(['create', '-f', '-'], pod(name, host, 'curlimages/curl:8.12.1', command))
        results = []
        deadline = time.monotonic() + 180
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
    finally:
        k(['delete', 'namespace', ns, '--wait=false'], check=False)
    if args.output:
        p = Path(args.output)
        p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        p.chmod(0o600)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
