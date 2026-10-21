#!/usr/bin/env python3
"""Exercise CSI rounding and retained legacy ReplicaSet recovery on new fixtures.

Only fresh nonce-owned resources in the managed workload namespace are mutated.
The image must be a pinned official provider image already cached on a worker.
No user disk, credential, service, host setting or image cache is modified.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl', required=True)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--node', default='uc-k8sp4')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash(?::[^@]+)?@sha256:[a-f0-9]{64}', args.image):
        raise SystemExit('An immutable official provider image is required')
    ns = 'heterocloud-flash-workloads'
    run = uuid.uuid4().hex
    sid = str(uuid.uuid4())
    name = 'flash-' + sid
    label = {'operations-e2e/run': run}
    command = [args.kubectl, '--kubeconfig=' + args.kubeconfig, '--request-timeout=15s']
    report = {'schema_version': 1, 'run_id': run, 'service_id': sid, 'result': 'incomplete', 'checks': {}, 'cleanup': {}}
    stage, service_uid, claim = 'preflight', None, None

    def kube(*parts, body=None, raw=False):
        r = subprocess.run(command + list(parts), input=json.dumps(body) if body is not None else None,
                           capture_output=True, text=True, timeout=40)
        if r.returncode:
            reason = next((v.lower() for v in ('Conflict', 'Forbidden', 'Invalid', 'BadRequest',
                                               'NotFound', 'Timeout', 'InternalError')
                           if '(' + v + ')' in r.stderr), 'operation_failed')
            raise RuntimeError('fixture_kubernetes_' + reason)
        return r.stdout if raw else json.loads(r.stdout) if r.stdout.strip() else None

    def get(kind, resource, namespace=ns):
        return kube('-n', namespace, 'get', kind, resource, '-o', 'json', '--ignore-not-found=true')

    def wait(description, condition, seconds=300):
        nonlocal stage
        stage = description
        print(json.dumps({'stage': stage}), flush=True)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            value = condition()
            if value:
                return value
            time.sleep(2)
        raise RuntimeError('fixture_step_timeout')

    def service():
        f = get('flashservice', name)
        if f:
            assert f['metadata']['uid'] == service_uid and f['metadata']['labels'].get('operations-e2e/run') == run
        return f

    def pod():
        values = kube('-n', ns, 'get', 'pods', '-l', 'flash.heterocloud.io/instance=' + sid, '-o', 'json')['items']
        return next((p for p in values if not p['metadata'].get('deletionTimestamp') and p['status'].get('phase') == 'Running'
                     and any(c['name'] == 'workload' and c.get('ready') for c in p['status'].get('containerStatuses', []))), None)

    def execute(p, text):
        assert p['metadata']['labels']['flash.heterocloud.io/instance'] == sid
        return kube('-n', ns, 'exec', p['metadata']['name'], '-c', 'workload', '--', '/bin/sh', '-ec', text, raw=True).strip()

    def change(workload):
        for attempt in range(8):
            f = service()
            try:
                return kube('-n', ns, 'patch', 'flashservice', name, '--type=merge', '--patch-file=/dev/stdin', '-o', 'json', body={
                    'metadata': {'resourceVersion': f['metadata']['resourceVersion']},
                    'spec': {'desired_generation': f['spec']['desired_generation'] + 1, 'workload': workload}})
            except RuntimeError as error:
                if str(error) != 'fixture_kubernetes_conflict' or attempt == 7:
                    raise
                time.sleep(0.5)

    try:
        node = get('node', args.node)
        assert node['metadata']['labels'].get('heteronetwork.io/control-plane-only') != 'true'
        assert any(args.image.split('@')[1] == image.split('@')[-1] for entry in node['status']['images'] for image in entry['names'])
        workers = [n for n in kube('get', 'nodes', '-o', 'json')['items']
                   if n['metadata']['labels'].get('heteronetwork.io/control-plane-only') != 'true'
                   and any(c['type'] == 'Ready' and c['status'] == 'True'
                           for c in n['status'].get('conditions', []))]
        assert workers and all(any(args.image.split('@')[1] == image.split('@')[-1]
                                   for entry in n['status']['images'] for image in entry['names'])
                               for n in workers)
        obj = {'apiVersion': 'flash.heterocloud.io/v1alpha1', 'kind': 'FlashService',
               'metadata': {'name': name, 'namespace': ns, 'labels': label},
               'spec': {'desired_generation': 1, 'display_name': 'legacy-recovery-e2e-' + run[:8],
                        'organization_id': str(uuid.uuid4()), 'project_id': str(uuid.uuid4()), 'service_instance_id': sid,
                        'workload': {'region': 'heteronet-global', 'image': args.image, 'replicas': 1, 'stopped': False,
                                     'cpu_millis': 100, 'memory_mib': 128, 'ephemeral_storage_gib': 3, 'rootfs_storage_gib': 1,
                                     'ports': [], 'exposure': {'type': 'internal', 'traffic_mode': 'forwarded'},
                                     'egress': {'mode': 'disabled', 'allow_same_organization': False},
                                     'env': {}, 'command': ['/bin/sh', '-ec'], 'args': ['sleep 3600'],
                                     'metadata': {'purpose': 'isolated-legacy-recovery-e2e', 'run_id': run}}}}
        created = kube('create', '-f', '-', '-o', 'json', body=obj)
        service_uid = created['metadata']['uid']
        def automatic_ready():
            status = service().get('status', {})
            if status.get('phase') == 'error':
                raise RuntimeError('automatic_home_rejected_after_provisioning')
            return status.get('phase') == 'ready' and pod()
        wait('automatic_home_ready', automatic_ready, 600)
        pvc = get('pvc', name + '-home')
        assert pvc['metadata']['labels']['flash.heterocloud.io/instance'] == sid
        claim = {'uid': pvc['metadata']['uid'], 'pv': pvc['spec']['volumeName']}
        requested = int(pvc['spec']['resources']['requests']['storage'])
        assert requested % (1024 ** 2) == 0
        assert requested + 1024 ** 3 + service()['status']['image_size_bytes'] <= 3 * 1024 ** 3
        first = pod()
        execute(first, "printf '%s' '" + run + "' > /root/recovery-marker; sync")
        for tick in range(8):
            time.sleep(5)
            f = service()
            assert f['status']['phase'] == 'ready' and pod()['metadata']['uid'] == first['metadata']['uid']
            kube('-n', ns, 'annotate', 'flashservice', name, 'operations-e2e/tick=' + str(tick), '--overwrite', raw=True)
        report['checks']['automatic_csi_allocation_stays_ready_and_inside_budget'] = True
        # Keep the basic schema valid, but leave less space than the retained
        # automatic home requires. This must reach the post-inspection storage
        # allocator, not the earlier input validator.
        stage = 'invalid_storage_update'
        change({'rootfs_storage_gib': 2})
        wait('invalid_storage_retains_image_metadata', lambda: service()['status'].get('phase') == 'error' and service()['status'].get('image_size_bytes', 0) > 0)
        report['checks']['invalid_storage_retains_verified_image_budget'] = True
        stage = 'failed_inspection_update'
        change({'image': 'invalid image reference'})
        wait('failed_inspection_without_image_budget', lambda: service()['status'].get('phase') == 'error' and not service()['status'].get('image_size_bytes'))
        old = pod()
        deployment = get('deployment', name)
        assert deployment['metadata']['labels']['flash.heterocloud.io/instance'] == sid
        stage = 'legacy_deployment_replacement'
        kube('-n', ns, 'patch', 'deployment', name, '--type=json', '--patch-file=/dev/stdin', '-o', 'json', body=[
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': deployment['metadata']['resourceVersion']},
            {'op': 'remove', 'path': '/spec/template/metadata/annotations/flash.heterocloud.io~1image-size-bytes'}])
        replacement = wait('cached_legacy_replacement_running', lambda: (p if (p := pod()) and p['metadata']['uid'] != old['metadata']['uid'] else None), 300)
        container = next(c for c in replacement['spec']['containers'] if c['name'] == 'workload')
        assert container['imagePullPolicy'] == 'Never'
        assert execute(replacement, 'cat /root/recovery-marker') == run
        assert get('pvc', name + '-home')['metadata']['uid'] == claim['uid']
        report['checks']['legacy_replacement_uses_cache_only_and_retains_data'] = True
        missing = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name + '-uncached', 'namespace': ns,
                   'labels': {**label, 'flash.heterocloud.io/instance': sid}},
                   'spec': {'runtimeClassName': 'gvisor', 'nodeSelector': {'kubernetes.io/hostname': args.node},
                            'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                            'containers': [{'name': 'workload', 'image': args.image.split('@')[0] + '@sha256:' + '0' * 64,
                                'command': ['/bin/sh', '-c', 'exit 0'], 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi', 'ephemeral-storage': '32Mi'}}}]}}
        denied = subprocess.run(command + ['create', '--dry-run=server', '-f', '-'], input=json.dumps(missing), capture_output=True, text=True, timeout=30)
        assert denied.returncode and 'image_capacity_unknown' in denied.stderr
        assert get('pod', name + '-uncached') is None
        report['checks']['uncached_unknown_image_denied_without_pull'] = True
        report['result'] = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        report.update(result='failed', failure_stage=stage,
                      failure_code=('fixture_interrupted' if isinstance(error, KeyboardInterrupt)
                                    else str(error) if isinstance(error, RuntimeError)
                                    else 'fixture_assertion_or_operation_failed'))
    finally:
        try:
            if service_uid:
                service()
                pvc = get('pvc', name + '-home')
                if pvc:
                    assert pvc['metadata']['labels']['flash.heterocloud.io/instance'] == sid
                    claim = {'uid': pvc['metadata']['uid'], 'pv': pvc['spec'].get('volumeName')}
                    # Keep this owned claim until its reclaim policy is fenced,
                    # including a provisioning failure before a PV was bound.
                    kube('-n', ns, 'patch', 'pvc', name + '-home', '--type=json', '--patch-file=/dev/stdin', '-o', 'json', body=[
                        {'op': 'test', 'path': '/metadata/uid', 'value': claim['uid']},
                        {'op': 'remove', 'path': '/metadata/ownerReferences'}])
                    pv = get('pv', claim['pv']) if claim['pv'] else None
                    if pv:
                        assert pv['spec']['claimRef']['uid'] == claim['uid'] and pv['spec']['claimRef']['namespace'] == ns
                        claim['volume'] = pv['spec']['csi']['volumeHandle']
                        kube('patch', 'pv', claim['pv'], '--type=merge', '-p', json.dumps({'metadata': {'resourceVersion': pv['metadata']['resourceVersion']}, 'spec': {'persistentVolumeReclaimPolicy': 'Delete'}}), '-o', 'json')
                kube('-n', ns, 'delete', 'flashservice', name, '--wait=false', raw=True)
                wait('fixture_service_removed', lambda: service() is None)
                if get('pvc', name + '-home'):
                    kube('-n', ns, 'delete', 'pvc', name + '-home', '--wait=false', raw=True)
                if claim and claim['pv']:
                    wait('fixture_volume_removed', lambda: get('pv', claim['pv']) is None, 600)
                if claim and claim.get('volume'):
                    wait('fixture_storage_removed', lambda: get('volumes.longhorn.io', claim['volume'], 'longhorn-system') is None, 300)
                wait('fixture_pods_removed', lambda: not kube('-n', ns, 'get', 'pods', '-l', 'flash.heterocloud.io/instance=' + sid, '-o', 'json')['items'])
                wait('fixture_network_and_deployment_removed', lambda: get('deployment', name) is None and get('networkpolicy', name) is None)
            report['cleanup']['all_new_resources_removed'] = True
        except Exception:
            report['cleanup']['all_new_resources_removed'] = False
            report['result'] = 'failed'
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output, indent=2)
        print(json.dumps(report), flush=True)
    return 0 if report['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
