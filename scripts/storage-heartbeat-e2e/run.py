#!/usr/bin/env python3
"""Exercise real kubelet leases, Longhorn RWX and Envoy in a disposable cluster with KVM storage workers."""
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.request
import vms

CLUSTER = 'hnn-heartbeat-e2e'
CONTEXT = 'kind-' + CLUSTER
CP = CLUSTER + '-control-plane'
ROOT = Path('/tmp/hnn-heartbeat-e2e')
REPORT = {'scenarios': [], 'result': 'failed'}
MARKER = None
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args, timeout=20):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:6]) + ': ' + result.stderr[-1200:])
    return result.stdout


def kube(*args):
    return run(['kubectl', '--context', CONTEXT, '--request-timeout=10s', *args])


def get(kind, name=None, ns=None, selector=None):
    args = ['get', kind]
    if name:
        args.append(name)
    if ns:
        args += ['-n', ns]
    if selector:
        args += ['-l', selector]
    return json.loads(kube(*args, '-o', 'json'))


def wait_for(description, check, timeout=360):
    deadline = time.monotonic() + timeout
    last = ''
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (RuntimeError, KeyError, IndexError) as error:
            last = str(error)
        time.sleep(2)
    raise AssertionError('Timed out: ' + description + ' ' + last)


def ready(pod):
    return (not pod['metadata'].get('deletionTimestamp') and
            any(c['type'] == 'Ready' and c['status'] == 'True'
                for c in pod.get('status', {}).get('conditions', [])))


def service_pod():
    pods = get('pods', ns='heartbeat-e2e', selector='app=persistent-web')['items']
    current = [p for p in pods if ready(p)]
    return current[0] if len(current) == 1 else None


def snapshot():
    pod = service_pod()
    if not pod:
        raise RuntimeError('Persistent web has no ready pod')
    pvc = get('pvc', 'persistent-home', 'heartbeat-e2e')
    pv = pvc['spec']['volumeName']
    share = get('pod', 'share-manager-' + pv, 'longhorn-system')
    if not ready(share):
        raise RuntimeError('RWX share manager not ready')
    return {'pod_uid': pod['metadata']['uid'], 'pod_name': pod['metadata']['name'],
            'restarts': sum(c['restartCount'] for c in pod['status']['containerStatuses']),
            'pvc_uid': pvc['metadata']['uid'], 'volume': pv,
            'share_uid': share['metadata']['uid'], 'share_node': share['spec']['nodeName']}


def probe(url):
    started = time.monotonic()
    try:
        with OPENER.open(url, timeout=3) as response:
            status = response.status
            body = response.read(4096)
            matches = body == MARKER if MARKER is not None else body.startswith(b'heartbeat-e2e-')
    except urllib.error.HTTPError as error:
        status, matches = error.code, False
    except (OSError, urllib.error.URLError):
        status, matches = 0, False
    return {'status': status, 'data_preserved': matches,
            'elapsed_ms': round((time.monotonic() - started) * 1000)}


def set_grace(seconds):
    # The only mutable manifest belongs to this job's fixed-name kind container.
    # kind images need no Python: stream the already-rendered exact replacement.
    original = run(['docker', 'exec', CP, 'cat', '/etc/kubernetes/manifests/kube-controller-manager.yaml'])
    import re
    updated, count = re.subn(r'--node-monitor-grace-period=\d+s',
                             '--node-monitor-grace-period=' + str(seconds) + 's', original)
    assert count == 1
    process = subprocess.run(['docker', 'exec', '-i', CP, 'sh', '-c',
                              'umask 077; cat > /etc/kubernetes/hnn-controller-health.tmp && '
                              'mv /etc/kubernetes/hnn-controller-health.tmp /etc/kubernetes/manifests/kube-controller-manager.yaml'],
                             input=updated, text=True, capture_output=True, timeout=10)
    assert process.returncode == 0
    def applied():
        pod = get('pod', 'kube-controller-manager-' + CP, 'kube-system')
        return ready(pod) and ('--node-monitor-grace-period=' + str(seconds) + 's') in pod['spec']['containers'][0]['command']
    wait_for('new controller manager policy', applied, 120)
    # Allow a newly elected leader to observe an up-to-date node lease first.
    time.sleep(12)


def scenario(name, seconds, duration, expect_outage, url):
    set_grace(seconds)
    before = wait_for('healthy RWX workload', snapshot, 600)
    assert probe(url)['data_preserved']
    node = before['share_node']
    assert node in (CLUSTER + '-worker', CLUSTER + '-worker2')
    result = {'name': name, 'grace_seconds': seconds, 'heartbeat_pause_seconds': duration,
              'before': before, 'http': [], 'node_states': []}
    REPORT['scenarios'].append(result)
    stop = threading.Event()
    def monitor():
        while not stop.is_set():
            result['http'].append(probe(url))
            stop.wait(0.5)
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    try:
        # Pause only heartbeats. Application, storage, network and containerd keep running.
        vms.ssh(node, ['systemctl', 'stop', 'kubelet'], timeout=30)
        started = time.monotonic()
        while time.monotonic() - started < duration:
            actual = get('node', node)
            state = next(c['status'] for c in actual['status']['conditions'] if c['type'] == 'Ready')
            result['node_states'].append(state)
            time.sleep(2)
    finally:
        vms.ssh(node, ['systemctl', 'start', 'kubelet'], timeout=30)
        stop.set()
        monitor_thread.join(timeout=5)
    if expect_outage:
        assert any(s != 'True' for s in result['node_states']), 'Failure detector was disabled or fault was ineffective'
        # Envoy must really expose the failure in the negative control.
        assert any(p['status'] == 503 for p in result['http']), 'Old-policy outage was not reproduced through Envoy'
    else:
        assert all(s == 'True' for s in result['node_states']), 'Brief heartbeat interruption fenced a live node'
        assert result['http'] and all(p['status'] == 200 and p['data_preserved'] for p in result['http']), 'HTTP or persistent storage interrupted'
    wait_for('node recovered', lambda: any(c['type'] == 'Ready' and c['status'] == 'True'
             for c in get('node', node)['status']['conditions']), 120)
    # Longhorn must converge automatically, without a manual pod deletion/restart.
    wait_for('automatic application and data recovery', lambda: probe(url)['data_preserved'], 600)
    after = wait_for('healthy RWX after recovery', snapshot, 180)
    assert before['pvc_uid'] == after['pvc_uid'] and before['volume'] == after['volume']
    if not expect_outage:
        assert before['pod_uid'] == after['pod_uid']
        assert before['restarts'] == after['restarts']
        assert before['share_uid'] == after['share_uid']
    else:
        assert before['share_uid'] != after['share_uid'], 'Longhorn share-manager recovery was not exercised'
    result['after'] = after
    result['passed'] = True
    print(json.dumps({'scenario': name, 'passed': True, 'http_samples': len(result['http']),
                      'http_503': sum(p['status'] == 503 for p in result['http']), 'data_preserved': True}), flush=True)


def main():
    global MARKER
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('HNN_FAULT_E2E') == 'isolated-vms-only'
    assert os.environ.get('KUBECONFIG') == str(ROOT / 'kubeconfig')
    assert run(['kubectl', 'config', 'current-context']).strip() == CONTEXT
    cluster_nodes = get('nodes')['items']
    assert {n['metadata']['name'] for n in cluster_nodes} == {CP, CLUSTER+'-worker', CLUSTER+'-worker2'}
    inspected = json.loads(run(['docker', 'inspect', CP]))[0]
    assert inspected['Config']['Labels']['io.x-k8s.kind.cluster'] == CLUSTER
    for node in (CLUSTER + '-worker', CLUSTER + '-worker2'):
        vms.assert_owned(node)
    svc = wait_for('Envoy NodePort', lambda: next((s for s in get('svc', ns='envoy-gateway-system')['items']
                       if s['metadata'].get('labels', {}).get('gateway.envoyproxy.io/owning-gateway-name') == 'fixture'), None), 120)
    node_port = next(p['nodePort'] for p in svc['spec']['ports'] if p.get('port') == 8080)
    inspected = json.loads(run(['docker', 'inspect', CP]))[0]
    address = inspected['NetworkSettings']['Networks']['kind']['IPAddress']
    url = f'http://{address}:{node_port}/'
    wait_for('initial Envoy HTTP response', lambda: probe(url)['data_preserved'], 180)
    with OPENER.open(url, timeout=3) as response:
        MARKER = response.read(4096)
    # A recreated empty filesystem must not be mistaken for retained user data.
    assert len(MARKER) == len(b'heartbeat-e2e-') + 32
    seconds = json.loads(Path('deploy/terraform/master-only/node-health-policy.json').read_text())['node_monitor_grace_seconds']
    assert seconds >= 50
    scenario('fixed_policy_brief_heartbeat_loss', seconds, 35, False, url)
    scenario('old_policy_reproduces_503_and_rwx_remount', 20, 35, True, url)
    scenario('fixed_policy_still_detects_sustained_failure', seconds, seconds + 35, True, url)
    set_grace(seconds)
    REPORT['result'] = 'passed'


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        REPORT['failure'] = str(error)
        raise
    finally:
        (ROOT / 'results').mkdir(parents=True, exist_ok=True)
        (ROOT / 'results' / 'report.json').write_text(json.dumps(REPORT, indent=2) + '\n')
