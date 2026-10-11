#!/usr/bin/env bash
# Runs only on a disposable GitHub runner; no production credentials are used.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${HNN_FAULT_E2E:-}" == isolated-vms-only ]]
[[ "${KUBECONFIG:-}" == /tmp/hnn-heartbeat-e2e/kubeconfig ]]
mkdir -p /tmp/hnn-heartbeat-e2e/results
sudo apt-get update -qq
sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --retry 2 https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 -o /tmp/hnn-heartbeat-e2e/kind
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --retry 2 https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64.sha256sum -o /tmp/hnn-heartbeat-e2e/kind.sha256sum
python3 - <<'PY'
from pathlib import Path
import hashlib
p = Path('/tmp/hnn-heartbeat-e2e')
assert hashlib.sha256((p/'kind').read_bytes()).hexdigest() == (p/'kind.sha256sum').read_text().split()[0]
PY
sudo install -m 0755 /tmp/hnn-heartbeat-e2e/kind /usr/local/bin/kind
python3 - <<'PY'
import json, re, yaml
from pathlib import Path
policy = json.loads(Path('deploy/terraform/master-only/node-health-policy.json').read_text())
seconds = policy['node_monitor_grace_seconds']
assert 50 <= seconds <= 300
assert f'NODE_MONITOR_GRACE_PERIOD="{seconds}s"' in Path('scripts/kubeadm-ha-node.sh').read_text()
nodes = [{'role':'control-plane','kubeadmConfigPatches':[f'''kind: ClusterConfiguration
controllerManager:
  extraArgs:
  - name: node-monitor-grace-period
    value: "{seconds}s"
''']}]
Path('/tmp/hnn-heartbeat-e2e/kind.yaml').write_text(yaml.safe_dump({'kind':'Cluster','apiVersion':'kind.x-k8s.io/v1alpha4','nodes':nodes}))
for app in ['longhorn', 'envoy-gateway']:
    manifest = yaml.safe_load(Path(f'deploy/gitops/applications/{app}.yaml').read_text())
    values = yaml.safe_load(manifest['spec']['source']['helm']['values'])
    if app == 'longhorn':
        values['persistence']['defaultClassReplicaCount'] = 2
        values['defaultSettings']['defaultReplicaCount'] = '2'
        # Leave all failure/recovery policies identical to production.
        values['defaultSettings']['storageReservedPercentageForDefaultDisk'] = '5'
        values['csi'] = {key:1 for key in values['csi']}
        values['longhornUI']['replicas'] = 1
    else:
        values['deployment']['replicas'] = 1
        values['podDisruptionBudget'] = {'minAvailable':0}
        gateway = values['config']['envoyGateway']
        # This fixture has no rate-limit policy or Redis dependency.
        gateway.pop('rateLimit', None)
        gateway['provider']['kubernetes'].pop('rateLimitDeployment', None)
        gateway['provider']['kubernetes'].pop('rateLimitPDB', None)
    Path(f'/tmp/hnn-heartbeat-e2e/{app}.yaml').write_text(yaml.safe_dump(values))
    Path(f'/tmp/hnn-heartbeat-e2e/{app}.version').write_text(manifest['spec']['source']['targetRevision'])
PY
kind create cluster --name hnn-heartbeat-e2e --wait 180s \
  --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed \
  --config /tmp/hnn-heartbeat-e2e/kind.yaml
python3 scripts/storage-heartbeat-e2e/vms.py create
helm repo add longhorn https://charts.longhorn.io
helm upgrade --install longhorn longhorn/longhorn --version "$(cat /tmp/hnn-heartbeat-e2e/longhorn.version)" \
  --namespace longhorn-system --create-namespace --values /tmp/hnn-heartbeat-e2e/longhorn.yaml --wait --timeout 8m
helm upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
  --version "$(cat /tmp/hnn-heartbeat-e2e/envoy-gateway.version)" \
  --namespace envoy-gateway-system --create-namespace --values /tmp/hnn-heartbeat-e2e/envoy-gateway.yaml --wait --timeout 5m
kubectl wait --for=condition=Ready node --all --timeout=120s
kubectl apply -f scripts/storage-heartbeat-e2e/fixture.yaml
kubectl -n heartbeat-e2e rollout status deployment/persistent-web --timeout=300s
kubectl -n heartbeat-e2e wait --for=condition=Programmed gateway/fixture --timeout=180s
