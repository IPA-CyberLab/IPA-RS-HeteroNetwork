#!/usr/bin/env bash
set -euo pipefail

readonly NAMESPACE="livekit"
readonly REDIS_RELEASE="livekit-redis"
readonly REDIS_CHART="oci://registry-1.docker.io/bitnamicharts/redis"
readonly REDIS_CHART_VERSION="27.0.18"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
deployment_dir="${repo_root}/deploy/kubernetes/livekit"

for command in kubectl helm openssl base64 sha256sum; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "${command}" >&2
    exit 1
  fi
done

umask 077
work_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml |
  kubectl apply -f -

if ! kubectl -n "${NAMESPACE}" get secret livekit-redis-auth >/dev/null 2>&1; then
  redis_password="$(openssl rand -hex 32)"
  kubectl -n "${NAMESPACE}" create secret generic livekit-redis-auth \
    --from-literal=redis-password="${redis_password}"
fi

helm upgrade --install "${REDIS_RELEASE}" "${REDIS_CHART}" \
  --version "${REDIS_CHART_VERSION}" \
  --namespace "${NAMESPACE}" \
  --values "${deployment_dir}/redis-values.yaml" \
  --wait \
  --timeout 10m

if ! kubectl -n "${NAMESPACE}" get secret livekit-keys >/dev/null 2>&1; then
  api_key="LK$(openssl rand -hex 12)"
  api_secret="$(openssl rand -hex 32)"
  printf '%s: %s\n' "${api_key}" "${api_secret}" >"${work_dir}/keys.yaml"
  kubectl -n "${NAMESPACE}" create secret generic livekit-keys \
    --from-file=keys.yaml="${work_dir}/keys.yaml" \
    --from-literal=api-key="${api_key}" \
    --from-literal=api-secret="${api_secret}"
else
  for key in keys.yaml api-key api-secret; do
    if [[ -z "$(kubectl -n "${NAMESPACE}" get secret livekit-keys \
      -o "go-template={{ index .data \"${key}\" }}")" ]]; then
      printf 'secret livekit/livekit-keys is missing key %s\n' "${key}" >&2
      exit 1
    fi
  done
fi

redis_password="$(
  kubectl -n "${NAMESPACE}" get secret livekit-redis-auth \
    -o jsonpath='{.data.redis-password}' | base64 -d
)"

cat >"${work_dir}/livekit.yaml" <<EOF
port: 7880
redis:
  password: ${redis_password}
  sentinel_master_name: livekit
  sentinel_addresses:
    - livekit-redis-node-0.livekit-redis-headless.livekit.svc.cluster.local:26379
    - livekit-redis-node-1.livekit-redis-headless.livekit.svc.cluster.local:26379
    - livekit-redis-node-2.livekit-redis-headless.livekit.svc.cluster.local:26379
  sentinel_password: ${redis_password}
rtc:
  tcp_port: 7881
  udp_port: 7882
  use_external_ip: true
logging:
  level: info
  json: true
node_selector:
  kind: sysload
  sort_by: sysload
  algorithm: twochoice
  sysload_limit: 0.85
EOF

kubectl -n "${NAMESPACE}" create secret generic livekit-config \
  --from-file=livekit.yaml="${work_dir}/livekit.yaml" \
  --dry-run=client -o yaml |
  kubectl apply -f -

kubectl apply -f "${deployment_dir}/livekit.yaml"

config_checksum="$(sha256sum "${work_dir}/livekit.yaml" | awk '{print $1}')"
keys_checksum="$(
  kubectl -n "${NAMESPACE}" get secret livekit-keys \
    -o jsonpath='{.data.keys\.yaml}' | sha256sum | awk '{print $1}'
)"
kubectl -n "${NAMESPACE}" patch deployment livekit --type merge -p \
  "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"networking.heteronetwork.io/config-checksum\":\"${config_checksum}\",\"networking.heteronetwork.io/keys-checksum\":\"${keys_checksum}\"}}}}}"

kubectl -n "${NAMESPACE}" rollout status statefulset/livekit-redis-node \
  --timeout=10m
kubectl -n "${NAMESPACE}" rollout status deployment/livekit --timeout=10m

wait_for_ingress() {
  local service="$1"
  local expected="$2"
  local attempt addresses count

  for ((attempt = 0; attempt < 60; attempt++)); do
    addresses="$(
      kubectl -n "${NAMESPACE}" get service "${service}" \
        -o jsonpath='{.status.loadBalancer.ingress[*].ip}'
    )"
    count="$(wc -w <<<"${addresses}")"
    if [[ "${count}" -eq "${expected}" ]]; then
      return 0
    fi
    sleep 2
  done

  printf 'service %s did not receive %s ingress addresses\n' \
    "${service}" "${expected}" >&2
  return 1
}

wait_for_ingress livekit-signal 3
wait_for_ingress livekit-rtc 2

kubectl -n "${NAMESPACE}" get pods -o wide
kubectl -n "${NAMESPACE}" get service livekit-signal livekit-rtc -o wide
