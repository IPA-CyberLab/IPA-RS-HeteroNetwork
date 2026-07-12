#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kubectl_bin="${KUBECTL:-kubectl}"
helm_bin="${HELM:-helm}"
cargo_bin="${CARGO:-cargo}"
ipars_bin="${IPARS_K8S_SMOKE_IPARS_BIN:-}"
image_repository="${IPARS_K8S_SMOKE_IMAGE_REPOSITORY:-}"
image_tag="${IPARS_K8S_SMOKE_IMAGE_TAG:-}"
image_pull_policy="${IPARS_K8S_SMOKE_IMAGE_PULL_POLICY:-IfNotPresent}"
agent_runtime_backend="${IPARS_K8S_SMOKE_AGENT_RUNTIME_BACKEND:-linux-command}"
timeout_seconds="${IPARS_K8S_SMOKE_TIMEOUT_SECONDS:-300}"
keep_resources="${IPARS_K8S_SMOKE_KEEP_RESOURCES:-0}"
suffix="$$-$(date +%s%N)"
namespace="${IPARS_K8S_SMOKE_NAMESPACE:-ipars-live-${suffix}}"
release="${IPARS_K8S_SMOKE_RELEASE:-ipars-live-${suffix}}"
bootstrap_name="ipars-bootstrap"
token_secret="ipars-live-join"
agent_api_token="ipars-k8s-smoke-agent-api-${suffix}-secret"
control_plane_operator_api_token="ipars-k8s-smoke-control-plane-operator-${suffix}-secret"
chart_fullname=""
tmp_dir=""
namespace_created=0
helm_installed=0

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

json_string() {
  jq -cn --arg value "$1" '$value'
}

run_ipars() {
  if [[ -n "$ipars_bin" ]]; then
    "$ipars_bin" "$@"
  else
    "$cargo_bin" run --locked -q -p ipars-cli -- "$@"
  fi
}

dump_diagnostics() {
  echo "Kubernetes live smoke diagnostics for namespace ${namespace}:" >&2
  "$kubectl_bin" -n "$namespace" get all,configmap,secret,role,rolebinding,serviceaccount 2>&1 || true
  if [[ -n "$chart_fullname" ]]; then
    "$kubectl_bin" -n "$namespace" describe daemonset "$chart_fullname" 2>&1 || true
  fi
  "$kubectl_bin" -n "$namespace" logs "deployment/${bootstrap_name}" -c control-plane --tail=200 2>&1 || true
  "$kubectl_bin" -n "$namespace" logs "deployment/${bootstrap_name}" -c signal --tail=200 2>&1 || true
  local pod
  while IFS= read -r pod; do
    [[ -n "$pod" ]] || continue
    "$kubectl_bin" -n "$namespace" logs "$pod" -c agent --tail=200 2>&1 || true
  done < <("$kubectl_bin" -n "$namespace" get pods \
    -l "app.kubernetes.io/name=ipars,app.kubernetes.io/instance=${release}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
}

cleanup() {
  local status=$?
  trap - EXIT

  if [[ $status -ne 0 && $namespace_created -eq 1 ]]; then
    dump_diagnostics
  fi

  if [[ "$keep_resources" == "1" ]]; then
    if [[ $namespace_created -eq 1 ]]; then
      echo "retaining Kubernetes live smoke namespace ${namespace}" >&2
    fi
  else
    if [[ $helm_installed -eq 1 ]]; then
      "$helm_bin" uninstall "$release" --namespace "$namespace" >/dev/null 2>&1 || true
    fi
    if [[ $namespace_created -eq 1 ]]; then
      "$kubectl_bin" delete namespace "$namespace" --wait=false >/dev/null 2>&1 || true
    fi
  fi

  if [[ -n "$tmp_dir" ]]; then
    rm -rf "$tmp_dir"
  fi
  exit "$status"
}

wait_for_bootstrap_health() {
  local pod=""
  local attempt
  for attempt in $(seq 1 60); do
    pod="$("$kubectl_bin" -n "$namespace" get pods \
      -l app.kubernetes.io/component=ipars-bootstrap \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -n "$pod" ]] \
      && "$kubectl_bin" -n "$namespace" exec "$pod" -c control-plane -- \
        curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8443/healthz >/dev/null \
      && "$kubectl_bin" -n "$namespace" exec "$pod" -c signal -- \
        curl --fail --silent --show-error --max-time 5 http://127.0.0.1:9443/healthz >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "bootstrap control-plane and signal services did not become healthy" >&2
  return 1
}

wait_for_agent_runtime() {
  local pod="$1"
  local status_json
  local metrics_json
  local attempt
  for attempt in $(seq 1 60); do
    status_json="$("$kubectl_bin" -n "$namespace" exec "$pod" -c agent -- \
      curl --fail --silent --show-error --max-time 5 \
        -H "Authorization: Bearer ${agent_api_token}" \
        http://127.0.0.1:9780/v1/status 2>/dev/null || true)"
    metrics_json="$("$kubectl_bin" -n "$namespace" exec "$pod" -c agent -- \
      curl --fail --silent --show-error --max-time 5 \
        -H "Authorization: Bearer ${agent_api_token}" \
        http://127.0.0.1:9780/v1/metrics 2>/dev/null || true)"
    if jq -e '(.node_id | type == "string") and (.candidate_count | type == "number")' \
      >/dev/null 2>&1 <<<"$status_json" \
      && jq -e '.peer_map_synced == true and (.node_id | type == "string")' \
        >/dev/null 2>&1 <<<"$metrics_json"; then
      printf '%s\n' "$status_json"
      return 0
    fi
    sleep 2
  done
  echo "agent pod ${pod} did not report a synchronized peer map" >&2
  return 1
}

wait_for_control_plane_metrics() {
  local minimum_nodes="$1"
  local metrics_json
  local attempt
  for attempt in $(seq 1 60); do
    metrics_json="$("$kubectl_bin" -n "$namespace" exec "deployment/${bootstrap_name}" -c control-plane -- \
      /usr/local/bin/ipars \
        --control-plane-operator-api-bearer-token-path /run/secrets/control-plane/operator-api-token \
        status --control-plane-url http://127.0.0.1:8443 2>/dev/null || true)"
    if jq -e --argjson minimum "$minimum_nodes" \
      '.metrics.node_count >= $minimum and .metrics.healthy_node_count >= $minimum and .metrics.token_ledger_use_count >= $minimum' \
      >/dev/null 2>&1 <<<"$metrics_json"; then
      return 0
    fi
    sleep 2
  done
  echo "control-plane metrics did not report every DaemonSet agent as healthy" >&2
  return 1
}

if [[ -z "$image_repository" || -z "$image_tag" ]]; then
  echo "set IPARS_K8S_SMOKE_IMAGE_REPOSITORY and IPARS_K8S_SMOKE_IMAGE_TAG to an image reachable by the target cluster" >&2
  exit 1
fi
if [[ ! "$image_repository" =~ ^[a-z0-9]([a-z0-9._:/-]*[a-z0-9])?$ ]]; then
  echo "IPARS_K8S_SMOKE_IMAGE_REPOSITORY must be a lowercase image repository" >&2
  exit 1
fi
if [[ ! "$image_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
  echo "IPARS_K8S_SMOKE_IMAGE_TAG must be a valid image tag" >&2
  exit 1
fi
if [[ ! "$image_pull_policy" =~ ^(Always|IfNotPresent|Never)$ ]]; then
  echo "IPARS_K8S_SMOKE_IMAGE_PULL_POLICY must be Always, IfNotPresent, or Never" >&2
  exit 1
fi
if [[ "$agent_runtime_backend" != "linux-command" && "$agent_runtime_backend" != "dry-run" ]]; then
  echo "IPARS_K8S_SMOKE_AGENT_RUNTIME_BACKEND must be linux-command or dry-run" >&2
  exit 1
fi
if [[ ! "$timeout_seconds" =~ ^[0-9]+$ || "$timeout_seconds" -lt 1 || "$timeout_seconds" -gt 1800 ]]; then
  echo "IPARS_K8S_SMOKE_TIMEOUT_SECONDS must be an integer between 1 and 1800" >&2
  exit 1
fi
if [[ "$keep_resources" != "0" && "$keep_resources" != "1" ]]; then
  echo "IPARS_K8S_SMOKE_KEEP_RESOURCES must be 0 or 1" >&2
  exit 1
fi

require_dns_label "$namespace" "IPARS_K8S_SMOKE_NAMESPACE" 63
require_dns_label "$release" "IPARS_K8S_SMOKE_RELEASE" 53
if [[ "$release" == *ipars* ]]; then
  chart_fullname="$release"
else
  chart_fullname="${release}-ipars"
  chart_fullname="${chart_fullname:0:53}"
  chart_fullname="${chart_fullname%-}"
fi
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

"$kubectl_bin" version --request-timeout=15s >/dev/null
"$kubectl_bin" get nodes --no-headers | grep -q .
"$helm_bin" version --short >/dev/null

if "$kubectl_bin" get namespace "$namespace" >/dev/null 2>&1; then
  echo "refusing to reuse existing namespace ${namespace}" >&2
  exit 1
fi
"$kubectl_bin" create namespace "$namespace" >/dev/null
namespace_created=1

"$kubectl_bin" -n "$namespace" apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${bootstrap_name}
  labels:
    app.kubernetes.io/component: ipars-bootstrap
    ipars.io/live-smoke: "true"
spec:
  selector:
    app.kubernetes.io/component: ipars-bootstrap
  ports:
    - name: control-plane
      port: 8443
      targetPort: control-plane
    - name: signal
      port: 9443
      targetPort: signal
EOF

bootstrap_cluster_ip="$("$kubectl_bin" -n "$namespace" get service "$bootstrap_name" -o jsonpath='{.spec.clusterIP}')"
if [[ ! "$bootstrap_cluster_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "live smoke currently requires an IPv4 bootstrap Service clusterIP, got ${bootstrap_cluster_ip:-<empty>}" >&2
  exit 1
fi

init_output="$tmp_dir/init.json"
issuer_key="$tmp_dir/issuer.key"
run_ipars init \
  --public-endpoint "${bootstrap_cluster_ip}:8443" \
  --issuer-private-key-path "$issuer_key" \
  --issuer-key-id live-smoke \
  --token-ttl-seconds "$timeout_seconds" \
  --default-role kubernetes-node \
  --allowed-route "${bootstrap_cluster_ip}/32" \
  --unlimited-uses >"$init_output"

cluster_id="$(jq -er '.cluster_id | strings' "$init_output")"
issuer_node_id="$(jq -er '.issuer_node_id | strings' "$init_output")"
issuer_public_key="$(jq -er '.issuer_public_key | strings' "$init_output")"
token_file="$tmp_dir/join-token.json"
agent_api_token_file="$tmp_dir/agent-api.token"
control_plane_operator_api_token_file="$tmp_dir/control-plane-operator-api.token"
jq -ce '.join_token' "$init_output" >"$token_file"
printf '%s' "$agent_api_token" >"$agent_api_token_file"
printf '%s' "$control_plane_operator_api_token" >"$control_plane_operator_api_token_file"

"$kubectl_bin" -n "$namespace" create secret generic "$token_secret" \
  --from-file=token="$token_file" \
  --from-file=agent-api-token="$agent_api_token_file" \
  --from-file=control-plane-operator-api-token="$control_plane_operator_api_token_file" \
  --dry-run=client -o yaml | "$kubectl_bin" -n "$namespace" apply -f - >/dev/null

image_ref="${image_repository}:${image_tag}"
image_ref_json="$(json_string "$image_ref")"
cluster_id_json="$(json_string "$cluster_id")"
issuer_node_id_json="$(json_string "$issuer_node_id")"
issuer_public_key_json="$(json_string "$issuer_public_key")"

"$kubectl_bin" -n "$namespace" apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${bootstrap_name}
  labels:
    app.kubernetes.io/component: ipars-bootstrap
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/component: ipars-bootstrap
  template:
    metadata:
      labels:
        app.kubernetes.io/component: ipars-bootstrap
    spec:
      containers:
        - name: control-plane
          image: ${image_ref_json}
          command: ["/usr/local/bin/iparsd"]
          args:
            - control-plane
            - --listen
            - 0.0.0.0:8443
            - --cluster-id
            - ${cluster_id_json}
            - --issuer-node-id
            - ${issuer_node_id_json}
            - --issuer-key-id
            - live-smoke
            - --issuer-public-key
            - ${issuer_public_key_json}
            - --database-url
            - sqlite:///var/lib/ipars/control-plane.sqlite?mode=rwc
            - --operator-api-bearer-token-path
            - /run/secrets/control-plane/operator-api-token
          ports:
            - name: control-plane
              containerPort: 8443
          volumeMounts:
            - name: control-plane-state
              mountPath: /var/lib/ipars
            - name: control-plane-operator-api-token
              mountPath: /run/secrets/control-plane/operator-api-token
              subPath: operator-api-token
              readOnly: true
        - name: signal
          image: ${image_ref_json}
          command: ["/usr/local/bin/iparsd"]
          args:
            - signal
            - --listen
            - 0.0.0.0:9443
          ports:
            - name: signal
              containerPort: 9443
      volumes:
        - name: control-plane-state
          emptyDir: {}
        - name: control-plane-operator-api-token
          secret:
            secretName: ${token_secret}
            defaultMode: 0400
            items:
              - key: control-plane-operator-api-token
                path: operator-api-token
EOF

"$kubectl_bin" -n "$namespace" rollout status "deployment/${bootstrap_name}" --timeout="${timeout_seconds}s"
wait_for_bootstrap_health

control_plane_url="http://${bootstrap_name}.${namespace}.svc:8443"
signal_url="http://${bootstrap_name}.${namespace}.svc:9443"
agent_state_path="/var/lib/ipars-live/${release}"
"$helm_bin" upgrade --install "$release" "$repo_root/charts/ipars" \
  --namespace "$namespace" \
  --wait \
  --timeout "${timeout_seconds}s" \
  --set-string "image.repository=${image_repository}" \
  --set-string "image.tag=${image_tag}" \
  --set-string "image.pullPolicy=${image_pull_policy}" \
  --set-string "agent.joinTokenSecretName=${token_secret}" \
  --set-string "agent.joinTokenSecretKey=token" \
  --set-string "agent.runtimeBackend=${agent_runtime_backend}" \
  --set agent.hostNetwork=false \
  --set-string "agent.dnsPolicy=ClusterFirst" \
  --set-string "agent.state.hostPath=${agent_state_path}" \
  --set-string "cluster.controlPlaneUrl=${control_plane_url}" \
  --set-string "cluster.signalUrl=${signal_url}" \
  --set serviceExposure.enabled=true \
  --set serviceExposure.discoverServices=true \
  --set serviceExposure.discoverApiServer=false \
  --set-json 'serviceExposure.serviceCidrs=[]' \
  --set-string "serviceExposure.namespaces[0]=${namespace}" \
  --set-string 'serviceExposure.serviceLabelSelector=ipars.io/live-smoke=true'
helm_installed=1

"$kubectl_bin" -n "$namespace" rollout status "daemonset/${chart_fullname}" --timeout="${timeout_seconds}s"

service_account="$chart_fullname"
if [[ "$("$kubectl_bin" auth can-i list services \
  --as="system:serviceaccount:${namespace}:${service_account}" -n "$namespace")" != "yes" ]]; then
  echo "agent ServiceAccount cannot list Services in its configured namespace" >&2
  exit 1
fi

mapfile -t agent_pods < <("$kubectl_bin" -n "$namespace" get pods \
  -l "app.kubernetes.io/name=ipars,app.kubernetes.io/instance=${release}" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
desired_agents="$("$kubectl_bin" -n "$namespace" get daemonset "$chart_fullname" -o jsonpath='{.status.desiredNumberScheduled}')"
if [[ ! "$desired_agents" =~ ^[1-9][0-9]*$ || ${#agent_pods[@]} -ne $desired_agents ]]; then
  echo "DaemonSet did not create the expected number of agent pods" >&2
  exit 1
fi

node_ids=()
for pod in "${agent_pods[@]}"; do
  "$kubectl_bin" -n "$namespace" wait --for=condition=Ready "pod/${pod}" --timeout="${timeout_seconds}s"
  status_json="$(wait_for_agent_runtime "$pod")"
  node_id="$(jq -er '.node_id | strings | select(test("^node-[A-Za-z0-9._-]+$"))' <<<"$status_json")"
  node_ids+=("$node_id")
done

wait_for_control_plane_metrics "$desired_agents"

for index in "${!node_ids[@]}"; do
  node_id="${node_ids[$index]}"
  pod="${agent_pods[$index]}"
  peer_map_json="$("$kubectl_bin" -n "$namespace" exec "pod/${pod}" -c agent -- \
    /usr/local/bin/ipars --agent-state-path /var/lib/ipars/agent.json peers \
      --control-plane-url "$control_plane_url" --node-id "$node_id")"
  jq -e --arg cluster_id "$cluster_id" '.cluster_id == $cluster_id and (.peers | type == "array")' \
    >/dev/null <<<"$peer_map_json"
done

echo "Kubernetes live smoke checks completed for ${#agent_pods[@]} agent pod(s)"
