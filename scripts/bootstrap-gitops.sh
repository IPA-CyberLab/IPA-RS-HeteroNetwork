#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECONFIG="${KUBECONFIG:-/etc/kubernetes/admin.conf}"
export KUBECONFIG

ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
ARGOCD_RELEASE="${ARGOCD_RELEASE:-argocd}"
ARGOCD_CHART_VERSION="${ARGOCD_CHART_VERSION:-10.2.2}"
TIMEOUT="${GITOPS_BOOTSTRAP_TIMEOUT:-15m}"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo --preserve-env=KUBECONFIG,ARGOCD_NAMESPACE,ARGOCD_RELEASE,ARGOCD_CHART_VERSION,GITOPS_BOOTSTRAP_TIMEOUT \
    "${BASH_SOURCE[0]}" "$@"
fi

for command in helm kubectl openssl psql; do
  command -v "${command}" >/dev/null || {
    printf 'required command is missing: %s\n' "${command}" >&2
    exit 1
  }
done
test -r "${KUBECONFIG}"

helm upgrade --install heteronetwork "${ROOT_DIR}/charts/ipars" \
  --namespace heteronetwork-system \
  --create-namespace \
  --reuse-values \
  --values "${ROOT_DIR}/deploy/environments/heteronet/values.yaml" \
  --atomic \
  --timeout "${TIMEOUT}" \
  --history-max 10

"${ROOT_DIR}/scripts/reconcile-flow-monitoring.sh"
"${ROOT_DIR}/scripts/reconcile-harbor-runtime.sh"

helm repo add argo https://argoproj.github.io/argo-helm --force-update >/dev/null
helm repo update argo >/dev/null
helm upgrade --install "${ARGOCD_RELEASE}" argo/argo-cd \
  --version "${ARGOCD_CHART_VERSION}" \
  --namespace "${ARGOCD_NAMESPACE}" \
  --create-namespace \
  --values "${ROOT_DIR}/deploy/gitops/argocd-values.yaml" \
  --atomic \
  --timeout "${TIMEOUT}" \
  --history-max 10

# Keep Sentinel discovery available while every Redis replica is recovering.
# The bundled redis-ha chart does not expose this Service field as a value.
kubectl -n "${ARGOCD_NAMESPACE}" patch service "${ARGOCD_RELEASE}-redis-ha" \
  --type=merge \
  --patch '{"spec":{"publishNotReadyAddresses":true}}'

kubectl apply --server-side --field-manager=heteronetwork-bootstrap \
  --force-conflicts \
  -f "${ROOT_DIR}/deploy/gitops/argocd-overlay-service.yaml" \
  -f "${ROOT_DIR}/deploy/gitops/project.yaml" \
  -f "${ROOT_DIR}/deploy/gitops/applications"

while IFS= read -r workload; do
  kubectl -n "${ARGOCD_NAMESPACE}" rollout status "${workload}" --timeout="${TIMEOUT}"
done < <(kubectl -n "${ARGOCD_NAMESPACE}" get deployment -o name)
while IFS= read -r workload; do
  kubectl -n "${ARGOCD_NAMESPACE}" rollout status "${workload}" --timeout="${TIMEOUT}"
done < <(kubectl -n "${ARGOCD_NAMESPACE}" get statefulset -o name)

for application in longhorn-prerequisites longhorn heterocloud-registry-redis heterocloud-registry cluster-dns envoy-gateway heterocloud-edge heterocloud heterocloud-flow heterocloud-flash; do
  kubectl -n "${ARGOCD_NAMESPACE}" wait "application/${application}" \
    --for=jsonpath='{.status.sync.status}'=Synced \
    --timeout="${TIMEOUT}"
  kubectl -n "${ARGOCD_NAMESPACE}" wait "application/${application}" \
    --for=jsonpath='{.status.health.status}'=Healthy \
    --timeout="${TIMEOUT}"
done

printf '%s\n' \
  'GitOps bootstrap completed.' \
  'Argo CD:    http://argocd.heteronetwork.internal:8088' \
  'Grafana:    http://grafana.heteronetwork.internal:13000' \
  'Prometheus: http://prometheus.heteronetwork.internal:9090' \
  'Registry:   https://registry.heterocloud.mizuame.app'
