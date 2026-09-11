#!/usr/bin/env python3
"""Actual DEV-only Garage placement and authenticated S3 round-trip probe."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
NS = 'heterocloud-syouyu-dev'
IMAGE = 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-syouyu:0.1.7-dev.2@sha256:2021bc7161146b212e41ec51ae5f1e127d11cfa03ad03d588e05de2335a0d1d6'
SCRIPT = r'''
set -eu
admin=http://heterocloud-syouyu-dev-garage-admin:3903
s3=http://heterocloud-syouyu-dev-s3:3900
token="$(cat /run/secrets/syouyu/garage-admin-token)"
admin_call() {
  printf 'header = "Authorization: Bearer %s"\n' "$token" |
    curl --config - --fail --silent --show-error --connect-timeout 5 --max-time 15 \
    -H 'Content-Type: application/json' "$@"
}
s3_call() {
  payload_hash="$1"
  shift
  printf 'user = "%s:%s"\n' "$access" "$secret" |
    curl --config - --aws-sigv4 aws:amz:heteronet-global:s3 \
    -H "x-amz-content-sha256: $payload_hash" \
    --fail --silent --show-error --connect-timeout 5 --max-time 15 "$@"
}
empty_hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bucket_id=''
access=''
secret=''
stage=cluster-status
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ -n "$access" ] && [ -n "$bucket_id" ]; then
    s3_call "$empty_hash" -X DELETE "$s3/$PROBE/object" >/dev/null || result=1
  fi
  if [ -n "$access" ]; then
    admin_call -X POST "$admin/v2/DeleteKey?id=$access" >/dev/null || result=1
  fi
  if [ -n "$bucket_id" ]; then
    admin_call -X POST "$admin/v2/DeleteBucket?id=$bucket_id" >/dev/null || result=1
  fi
  if [ "$result" -eq 0 ]; then
    printf '{"s3_put_get_delete":true,"probe_credentials_deleted":true,"probe_bucket_deleted":true}\n'
  else
    printf '{"failed_stage":"%s","cleanup_attempted":true}\n' "$stage"
  fi
  exit "$result"
}
trap cleanup EXIT
# Newly created pod policies are reconciled asynchronously. Retry only this read;
# mutation retries could create untracked credentials after a lost response.
attempt=0
until status="$(admin_call "$admin/v2/GetClusterStatus")"; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 10 ] || exit 1
  sleep 2
done
printf '%s' "$status" | jq -e '.layoutVersion > 0 and ([.nodes[] | select(.isUp == true and .role != null)] | length == 3)' >/dev/null
stage=create-bucket
bucket="$(admin_call -X POST --data "{\"globalAlias\":\"$PROBE\"}" "$admin/v2/CreateBucket")"
bucket_id="$(printf '%s' "$bucket" | jq -er '.id')"
stage=create-key
expiration="$(date -u -d '+10 minutes' '+%Y-%m-%dT%H:%M:%SZ')"
key="$(admin_call -X POST --data "{\"name\":\"$PROBE\",\"expiration\":\"$expiration\",\"neverExpires\":false}" "$admin/v2/CreateKey")"
access="$(printf '%s' "$key" | jq -er '.accessKeyId')"
secret="$(printf '%s' "$key" | jq -er '.secretAccessKey')"
stage=grant-bucket
payload="$(jq -cn --arg bucket "$bucket_id" --arg key "$access" '{bucketId:$bucket,accessKeyId:$key,permissions:{read:true,write:true,owner:false}}')"
admin_call -X POST --data "$payload" "$admin/v2/AllowBucketKey" >/dev/null
stage=s3-put
digest="$(printf '%s' "$PROBE" | sha256sum)"
s3_call "${digest%% *}" -X PUT --data-binary "$PROBE" "$s3/$PROBE/object" >/dev/null
stage=s3-get
actual="$(s3_call "$empty_hash" "$s3/$PROBE/object")"
[ "$actual" = "$PROBE" ]
stage=cleanup
'''


def main():
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006':
        raise ValueError('Unreviewed DEV guard')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()

    def get(kind, name):
        return json.loads(helper.run(['get', kind, name, '-n', NS, '-o', 'json']))

    sts = get('statefulset', NS + '-garage')
    helper.require(sts['status'].get('readyReplicas') == 3 and sts['status'].get('updatedReplicas') == 3)
    placements = {}
    for i in range(3):
        name = NS + '-garage-' + str(i)
        pod = get('pod', name)
        helper.require(any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status']['conditions']))
        placements[name] = pod['spec']['nodeName']
        for volume in ('meta', 'data'):
            pvc = get('pvc', volume + '-' + name)
            helper.require(pvc['status']['phase'] == 'Bound' and
                           pvc['spec']['volumeName'] == f'dev-app-garage-{volume}-{i + 1}')
    helper.require(set(placements.values()) == {f'hetero-dev-{i}' for i in range(1, 4)})
    name = 'garage-probe-' + uuid.uuid4().hex
    label = {'heteronetwork.dev/garage-probe': name}
    labels = {**label, 'app.kubernetes.io/name': 'heterocloud-syouyu',
              'app.kubernetes.io/instance': NS, 'app.kubernetes.io/component': 'layout-bootstrap'}
    metadata = {'name': name, 'namespace': NS, 'labels': label}
    garage = {'matchLabels': {'app.kubernetes.io/instance': NS, 'app.kubernetes.io/component': 'garage'}}
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': metadata,
              'spec': {'podSelector': {'matchLabels': label}, 'policyTypes': ['Ingress', 'Egress'],
                       'egress': [{'to': [{'podSelector': garage}],
                                   'ports': [{'protocol': 'TCP', 'port': p} for p in (3900, 3903)]}]}}
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {**metadata, 'labels': labels},
           'spec': {'restartPolicy': 'Never', 'activeDeadlineSeconds': 180, 'automountServiceAccountToken': False,
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                                        'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'containers': [{'name': 'probe', 'image': IMAGE, 'command': ['/bin/sh', '-ec', SCRIPT],
                                    'env': [{'name': 'PROBE', 'value': name}],
                                    'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'},
                                                  'limits': {'cpu': '100m', 'memory': '128Mi'}},
                                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                                        'capabilities': {'drop': ['ALL']}},
                                    'volumeMounts': [{'name': 'token', 'mountPath': '/run/secrets/syouyu', 'readOnly': True}]}],
                    'volumes': [{'name': 'token', 'secret': {'secretName': NS + '-secrets', 'defaultMode': 0o440,
                                'items': [{'key': 'garage-admin-token', 'path': 'garage-admin-token'}]}}]}}
    created = []
    try:
        for item in (policy, pod):
            actual = json.loads(helper.run(['create', '-f', '-', '-o', 'json'], data=json.dumps(item).encode()))
            created.append(actual)
        deadline = time.monotonic() + 210
        while time.monotonic() < deadline:
            actual = get('pod', name)
            phase = actual['status']['phase']
            if phase in ('Succeeded', 'Failed'):
                break
            time.sleep(2)
        if phase != 'Succeeded':
            diagnostics = helper.run(['logs', '-n', NS, name, '--tail=20'])
            directory = Path('/var/lib/heteronetwork-dev-garage-probes')
            directory.mkdir(mode=0o700, exist_ok=True)
            import os
            metadata = directory.lstat()
            helper.require(directory.is_dir() and not directory.is_symlink()
                           and metadata.st_uid == 0 and metadata.st_mode & 0o777 == 0o700)
            fd = os.open(directory / (name + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(diagnostics)
            print(json.dumps({'failed': True, 'phase': phase, 'diagnostic_record': str(directory / (name + '.log'))}), flush=True)
            raise ValueError('DEV S3 round-trip failed')
        result = json.loads(helper.run(['logs', '-n', NS, name, '--tail=1']))
        helper.require(result == {'s3_put_get_delete': True, 'probe_credentials_deleted': True, 'probe_bucket_deleted': True})
        helper.require(get('cluster.postgresql.cnpg.io', 'dev-postgres')['status']['readyInstances'] == 3)
        print(json.dumps({'placements': placements, **result, 'postgres_ready': 3}), flush=True)
    finally:
        for item in reversed(created):
            resource = 'pods' if item['kind'] == 'Pod' else 'networkpolicies'
            prefix = '/api/v1' if item['kind'] == 'Pod' else '/apis/networking.k8s.io/v1'
            options = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                       'preconditions': {'uid': item['metadata']['uid']}}
            helper.run(['delete', '--raw', f'{prefix}/namespaces/{NS}/{resource}/{name}', '-f', '-'],
                       data=json.dumps(options).encode())


if __name__ == '__main__':
    main()
