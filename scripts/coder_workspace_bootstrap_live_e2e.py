#!/usr/bin/env python3
"""Create a real Coder workspace, verify its agent/IDE, then remove its resources.

CODER_SESSION_TOKEN is supplied by a short-lived operator session. No image
metadata, PVC or readiness status is injected to make the workspace pass.
Only the newly created workspace's fenced resources may be cleaned up.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ['endpoint', 'template-id', 'image', 'kubectl', 'kubeconfig', 'browser-script', 'report']:
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    endpoint = urllib.parse.urlsplit(args.endpoint)
    if endpoint.scheme != 'https' or endpoint.username or endpoint.query or endpoint.fragment:
        parser.error('Use a credential-free HTTPS Coder endpoint')
    uuid.UUID(args.template_id)
    token = os.environ['CODER_SESSION_TOKEN']
    run = uuid.uuid4().hex
    name, ns = 'agent-e2e-' + run[:12], 'heterocloud-flash-workloads'
    report = {'run_id': run, 'result': 'incomplete', 'checks': {}, 'cleanup': {}}
    stage, workspace, flash, claim, volume = 'preflight', None, None, None, None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    child_env = {k: v for k, v in os.environ.items() if k != 'CODER_SESSION_TOKEN'}

    def api(path, method='GET', body=None, statuses=(200,)):
        request = urllib.request.Request(args.endpoint.rstrip('/') + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Coder-Session-Token': token, 'Content-Type': 'application/json'})
        try:
            with opener.open(request, timeout=60) as response:
                code, data = response.status, response.read(8 * 1024 * 1024)
        except urllib.error.HTTPError as response:
            code, data = response.code, response.read(65536)
        if code not in statuses:
            raise RuntimeError('coder_api_http_' + str(code))
        return json.loads(data) if data else None

    def kube(*parts, body=None, raw=False):
        result = subprocess.run([args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=20s'] + list(parts),
            input=json.dumps(body) if body is not None else None, text=True, capture_output=True, timeout=40, env=child_env)
        if result.returncode:
            raise RuntimeError('fixture_kubernetes_operation_failed')
        return result.stdout if raw else json.loads(result.stdout) if result.stdout.strip() else None

    def get(kind, identifier, namespace=ns):
        return kube('-n', namespace, 'get', kind, identifier, '-o', 'json', '--ignore-not-found=true')

    def wait(label, condition, seconds=600):
        nonlocal stage
        stage = label
        print(json.dumps({'stage': stage}), flush=True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = condition()
            if value:
                return value
            time.sleep(3)
        raise RuntimeError('fixture_timeout')

    def owned_service():
        if not workspace:
            return None
        matches = [f for f in kube('-n', ns, 'get', 'flashservices', '-o', 'json')['items']
                   if f['spec']['workload'].get('metadata', {}).get('coder_workspace') == workspace['id']]
        if len(matches) > 1:
            raise RuntimeError('ambiguous_fixture_service')
        return matches[0] if matches else None

    try:
        workspace = api('/api/v2/users/me/workspaces', 'POST', {'name': name, 'template_id': args.template_id}, (201,))
        report['workspace_id'] = workspace['id']
        print(json.dumps({'stage': 'workspace_created', 'name': name, 'id': workspace['id']}), flush=True)

        def ready():
            w = api('/api/v2/workspaces/' + workspace['id'])
            if w['name'] != name:
                raise RuntimeError('fixture_identity_mismatch')
            build = w['latest_build']
            if build['status'] in ['failed', 'canceled']:
                raise RuntimeError('fixture_build_failed')
            agents = [a for r in build.get('resources', []) for a in r.get('agents') or []]
            return w if build['status'] == 'running' and agents and all(
                a['status'] == 'connected' and a['lifecycle_state'] == 'ready' and any(
                    app['slug'] == 'code-server' and app['health'] == 'healthy' for app in a.get('apps', [])) for a in agents) else None

        workspace = wait('new_workspace_agent_connected', ready)
        flash = owned_service()
        assert flash and flash['spec']['workload']['image'] == args.image and flash['status']['phase'] == 'ready'
        sid = flash['spec']['service_instance_id']
        report['service_id'] = sid
        claim = get('pvc', flash['metadata']['name'] + '-home')
        assert claim['metadata']['labels']['flash.heterocloud.io/instance'] == sid
        volume = get('pv', claim['spec']['volumeName'])
        assert volume['spec']['claimRef']['uid'] == claim['metadata']['uid']
        storage = get('volumes.longhorn.io', volume['spec']['csi']['volumeHandle'], 'longhorn-system')
        assert storage['spec']['numberOfReplicas'] >= 2 and storage['status']['robustness'] == 'healthy'
        report['checks']['automatic_image_inspection_and_replicated_home'] = True
        report['checks']['agent_connected_and_ready'] = True
        pods = kube('-n', ns, 'get', 'pods', '-l', 'flash.heterocloud.io/instance=' + sid, '-o', 'json')['items']
        pod = next(p for p in pods if p.get('status', {}).get('phase') == 'Running')
        kube('-n', ns, 'exec', pod['metadata']['name'], '-c', 'workload', '--', '/bin/sh', '-ec',
             'mkdir -p /root/agent-e2e; printf "%s\\n" ' + run + ' > /root/agent-e2e/e2e-note.txt', raw=True)
        browser_report = str(Path(args.report).with_suffix('.browser.json'))
        config = {'url': args.endpoint.rstrip('/') + '/@' + urllib.parse.quote(workspace['owner_name'], safe='') +
                  '/' + name + '.main/apps/code-server/?folder=/root/agent-e2e',
                  'file': 'e2e-note.txt', 'session_token': token, 'report_path': browser_report, 'timeout_ms': 60000}
        stage = 'chromium_ide_file_and_reload'
        result = subprocess.run(['node', args.browser_script], input=json.dumps(config), text=True,
                                capture_output=True, env=child_env, timeout=180)
        if result.returncode or not json.loads(Path(browser_report).read_text()).get('passed'):
            raise RuntimeError('fixture_browser_failed')
        report['checks']['chromium_file_websocket_and_reload'] = True
        report['result'] = 'passed'
    except (Exception, KeyboardInterrupt):
        report.update(result='failed', failure_stage=stage)
    finally:
        try:
            if workspace:
                # Discover identities even when bootstrap failed before readiness.
                flash = owned_service()
                if flash:
                    claim = get('pvc', flash['metadata']['name'] + '-home')
                    if claim:
                        assert claim['metadata']['labels']['flash.heterocloud.io/instance'] == flash['spec']['service_instance_id']
                        volume = get('pv', claim['spec'].get('volumeName')) if claim['spec'].get('volumeName') else None
                        if volume:
                            assert volume['spec']['claimRef']['uid'] == claim['metadata']['uid']
                            kube('patch', 'pv', volume['metadata']['name'], '--type=merge', '--patch-file=/dev/stdin', '-o', 'json', body={
                                'metadata': {'resourceVersion': volume['metadata']['resourceVersion']},
                                'spec': {'persistentVolumeReclaimPolicy': 'Delete'}})
                current = api('/api/v2/workspaces/' + workspace['id'])
                assert current['name'] == name
                build = api('/api/v2/workspaces/' + workspace['id'] + '/builds', 'POST', {'transition': 'delete'}, (200, 201))
                wait('fixture_workspace_deleted', lambda: api('/api/v2/workspacebuilds/' + build['id'])['job']['status'] == 'succeeded', 300)
                wait('fixture_service_removed', lambda: owned_service() is None, 180)
                if flash:
                    wait('fixture_pods_removed', lambda: not kube('-n', ns, 'get', 'pods', '-l',
                         'flash.heterocloud.io/instance=' + flash['spec']['service_instance_id'], '-o', 'json')['items'], 180)
                    wait('fixture_deployment_and_policy_removed', lambda:
                         get('deployment', flash['metadata']['name']) is None and
                         get('networkpolicy', flash['metadata']['name']) is None, 180)
                if claim:
                    wait('fixture_home_removed', lambda: get('pvc', claim['metadata']['name']) is None, 180)
                if volume:
                    wait('fixture_storage_removed', lambda: get('pv', volume['metadata']['name']) is None and
                         get('volumes.longhorn.io', volume['spec']['csi']['volumeHandle'], 'longhorn-system') is None, 300)
            report['cleanup']['all_new_resources_removed'] = True
        except Exception:
            report['cleanup']['all_new_resources_removed'] = False
            report['result'] = 'failed'
            report['cleanup_failure_stage'] = stage
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output, indent=2)
        print(json.dumps(report), flush=True)
    return 0 if report['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
