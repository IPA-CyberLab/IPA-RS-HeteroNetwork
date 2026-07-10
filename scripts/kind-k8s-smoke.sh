#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker_bin="${DOCKER:-docker}"
kind_bin="${KIND:-kind}"
kubectl_bin="${KUBECTL:-kubectl}"
helm_bin="${HELM:-helm}"
ipars_bin="${IPARS_K8S_SMOKE_IPARS_BIN:-}"
cargo_bin="${CARGO:-cargo}"
suffix="$$-$(date +%s%N)"
cluster_name="${IPARS_KIND_K8S_SMOKE_CLUSTER_NAME:-ipars-kind-${suffix}}"
image_repository="ipars-kind-smoke"
image_tag="run-${suffix}"
image_ref="${image_repository}:${image_tag}"
cluster_wait_seconds="${IPARS_KIND_K8S_SMOKE_CLUSTER_WAIT_SECONDS:-180}"
agent_runtime_backend="${IPARS_KIND_K8S_SMOKE_AGENT_RUNTIME_BACKEND:-dry-run}"
keep_cluster="${IPARS_KIND_K8S_SMOKE_KEEP_CLUSTER:-0}"
tmp_dir=""
cluster_requested=0
image_built=0

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command '${command_name}' is not available in PATH" >&2
    exit 1
  fi
}

require_dns_label() {
  local value="$1"
  local name="$2"
  local max_length="$3"
  if [[ ${#value} -gt $max_length || ! "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "${name} must be a DNS label of at most ${max_length} lowercase ASCII characters" >&2
    exit 1
  fi
}

cleanup() {
  local status=$?
  trap - EXIT

  if [[ "$keep_cluster" == "1" ]]; then
    if [[ $cluster_requested -eq 1 ]]; then
      echo "retaining kind cluster ${cluster_name}" >&2
    fi
  else
    if [[ $cluster_requested -eq 1 ]]; then
      "$kind_bin" delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
    fi
    if [[ $image_built -eq 1 ]]; then
      "$docker_bin" image rm "$image_ref" >/dev/null 2>&1 || true
    fi
  fi

  if [[ -n "$tmp_dir" ]]; then
    rm -rf "$tmp_dir"
  fi
  exit "$status"
}

if [[ ! "$cluster_wait_seconds" =~ ^[0-9]+$ || "$cluster_wait_seconds" -lt 30 || "$cluster_wait_seconds" -gt 900 ]]; then
  echo "IPARS_KIND_K8S_SMOKE_CLUSTER_WAIT_SECONDS must be an integer between 30 and 900" >&2
  exit 1
fi
if [[ "$agent_runtime_backend" != "linux-command" && "$agent_runtime_backend" != "dry-run" ]]; then
  echo "IPARS_KIND_K8S_SMOKE_AGENT_RUNTIME_BACKEND must be linux-command or dry-run" >&2
  exit 1
fi
if [[ "$keep_cluster" != "0" && "$keep_cluster" != "1" ]]; then
  echo "IPARS_KIND_K8S_SMOKE_KEEP_CLUSTER must be 0 or 1" >&2
  exit 1
fi

require_dns_label "$cluster_name" "IPARS_KIND_K8S_SMOKE_CLUSTER_NAME" 63
require_command "$docker_bin"
require_command "$kind_bin"
require_command "$kubectl_bin"
require_command "$helm_bin"
require_command jq
if [[ -n "$ipars_bin" ]]; then
  if [[ ! -x "$ipars_bin" ]]; then
    echo "IPARS_K8S_SMOKE_IPARS_BIN must be an executable file" >&2
    exit 1
  fi
else
  require_command "$cargo_bin"
fi

trap cleanup EXIT
umask 077
tmp_dir="$(mktemp -d)"
kind_config="$tmp_dir/kind.yaml"
kubeconfig="$tmp_dir/kubeconfig"

"$docker_bin" version >/dev/null
"$kind_bin" version >/dev/null
"$helm_bin" version --short >/dev/null
if "$kind_bin" get clusters | grep -Fx -- "$cluster_name" >/dev/null; then
  echo "refusing to reuse existing kind cluster ${cluster_name}" >&2
  exit 1
fi

cat >"$kind_config" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
EOF

cluster_requested=1
"$kind_bin" create cluster \
  --name "$cluster_name" \
  --config "$kind_config" \
  --kubeconfig "$kubeconfig" \
  --wait "${cluster_wait_seconds}s"

DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}" \
  "$docker_bin" build -t "$image_ref" -f "$repo_root/docker/Dockerfile" "$repo_root"
image_built=1
"$kind_bin" load docker-image --name "$cluster_name" "$image_ref"

KUBECONFIG="$kubeconfig" \
KUBECTL="$kubectl_bin" \
HELM="$helm_bin" \
IPARS_K8S_SMOKE_IMAGE_REPOSITORY="$image_repository" \
IPARS_K8S_SMOKE_IMAGE_TAG="$image_tag" \
IPARS_K8S_SMOKE_IMAGE_PULL_POLICY=Never \
IPARS_K8S_SMOKE_AGENT_RUNTIME_BACKEND="$agent_runtime_backend" \
IPARS_K8S_SMOKE_KEEP_RESOURCES="$keep_cluster" \
"$repo_root/scripts/k8s-live-smoke.sh"

echo "kind Kubernetes smoke checks completed"
