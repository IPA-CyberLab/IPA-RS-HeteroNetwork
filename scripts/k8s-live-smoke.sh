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
agent_host_network="${IPARS_K8S_SMOKE_AGENT_HOST_NETWORK:-true}"
suffix="$$-$(date +%s%N)"
namespace="${IPARS_K8S_SMOKE_NAMESPACE:-ipars-live-${suffix}}"
release="${IPARS_K8S_SMOKE_RELEASE:-ipars-live-${suffix}}"
bootstrap_name="ipars-bootstrap"
token_secret="ipars-live-join"
agent_api_token="ipars-k8s-smoke-agent-api-${suffix}-secret"
control_plane_operator_api_token="ipars-k8s-smoke-control-plane-operator-${suffix}-secret"
service_route_name="ipars-route-target"
service_route_port="18080"
service_cidr="${IPARS_K8S_SMOKE_SERVICE_CIDR:-10.96.0.0/12}"
stale_kubernetes_route_cidr="198.18.0.0/15"
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
  "$kubectl_bin" -n "$namespace" logs "deployment/${bootstrap_name}" -c stun --tail=200 2>&1 || true
  local pod
  while IFS= read -r pod; do
    [[ -n "$pod" ]] || continue
    echo "--- agent network diagnostics: ${pod} ---" >&2
    "$kubectl_bin" -n "$namespace" exec "$pod" -c agent -- sh -ec '
      set +e
      echo "[ip link]"
      ip -br link
      echo "[ip address]"
      ip -br address
      echo "[ip route]"
      ip route
      echo "[wg show]"
      wg show "$1"
      echo "[wg endpoints]"
      wg show "$1" endpoints
      echo "[wg allowed-ips]"
      wg show "$1" allowed-ips
      echo "[wg latest-handshakes]"
      wg show "$1" latest-handshakes
      echo "[route to remote VPN]"
      ip route get "$2"
      echo "[remote healthz]"
      curl --noproxy "*" --silent --show-error --max-time 5 \
        -o /dev/null -w "http_code=%{http_code}\n" "http://${2}:9780/healthz"
    ' sh ipars0 100.64.0.2 2>&1 || true
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
        curl --fail --silent --show-error --max-time 5 http://127.0.0.1:9443/healthz >/dev/null \
      && "$kubectl_bin" -n "$namespace" exec "$pod" -c stun -- \
        curl --fail --silent --show-error --max-time 5 http://127.0.0.1:3479/healthz >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "bootstrap control-plane, signal, and STUN services did not become healthy" >&2
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
    if jq -e --arg backend "$agent_runtime_backend" \
      '(.node_id | type == "string")
       and (.vpn_ip | type == "string")
       and (.candidate_count | type == "number")
       and ($backend != "linux-command" or .candidate_count >= 1)' \
      >/dev/null 2>&1 <<<"$status_json" \
      && jq -e '.peer_map_synced == true and (.node_id | type == "string")' \
        >/dev/null 2>&1 <<<"$metrics_json"; then
      printf '%s\n' "$status_json"
      return 0
    fi
    sleep 2
  done
  echo "agent pod ${pod} did not report a synchronized peer map, VPN IP, and required endpoint candidate" >&2
  return 1
}

wait_for_agent_api_service() {
  local pod="$1"
  local service_name="$2"
  local service_ip
  local endpoint_ips
  local unauthorized_status
  local status_json
  local attempt

  service_ip="$($kubectl_bin -n "$namespace" get service "$service_name" -o jsonpath='{.spec.clusterIP}')"
  if [[ -z "$service_ip" || "$service_ip" == "None" ]]; then
    echo "agent API Service ${service_name} did not receive a ClusterIP" >&2
    return 1
  fi

  for attempt in $(seq 1 60); do
    endpoint_ips="$($kubectl_bin -n "$namespace" get endpoints "$service_name" \
      -o jsonpath='{range .subsets[*].addresses[*]}{.ip}{"\n"}{end}' 2>/dev/null || true)"
    if [[ -n "$endpoint_ips" ]]; then
      unauthorized_status="$($kubectl_bin -n "$namespace" exec "$pod" -c agent -- \
        sh -ec '
          curl --noproxy "*" --silent --show-error --max-time 5 \
            -o /dev/null -w "%{http_code}" "http://${1}:${2}/v1/status"
        ' sh "$service_name" 9780 2>/dev/null || true)"
      if [[ "$unauthorized_status" == "401" ]]; then
        status_json="$($kubectl_bin -n "$namespace" exec "$pod" -c agent -- \
          curl --noproxy "*" --fail --silent --show-error --max-time 5 \
            -H "Authorization: Bearer ${agent_api_token}" \
            "http://${service_name}:9780/v1/status" 2>/dev/null || true)"
        if jq -e '.node_id | type == "string" and length > 0' \
          >/dev/null 2>&1 <<<"$status_json"; then
          echo "agent API Service ${service_name} routed an authenticated request to ${endpoint_ips//$'\n'/, }"
          return 0
        fi
      fi
    fi
    sleep 2
  done
  echo "agent API Service ${service_name} did not expose an authenticated status endpoint" >&2
  return 1
}

activate_agent_peer() {
  local pod="$1"
  local peer_id="$2"
  local response
  response="$("$kubectl_bin" -n "$namespace" exec "$pod" -c agent -- \
    curl --fail --silent --show-error --max-time 5 \
      -H "Authorization: Bearer ${agent_api_token}" \
      -H 'Content-Type: application/json' \
      -X POST \
      --data "{\"peer\":\"${peer_id}\",\"pin\":true}" \
      http://127.0.0.1:9780/v1/peer-activity)"
  jq -e --arg peer "$peer_id" '.peer == $peer and .pinned == true' >/dev/null <<<"$response"
}

wait_for_wireguard_path() {
  local pod="$1"
  local local_vpn_ip="$2"
  local remote_vpn_ip="$3"
  local remote_url_host="$remote_vpn_ip"
  local attempt
  if [[ "$remote_url_host" == *:* ]]; then
    remote_url_host="[${remote_url_host}]"
  fi
  for attempt in $(seq 1 90); do
    if "$kubectl_bin" -n "$namespace" exec "$pod" -c agent -- \
      sh -ec '
        interface="$1"
        local_cidr="$2"
        remote_cidr="$3"
        remote_url="$4"
        test "$(wg show "$interface" listen-port)" = "51820"
        ip -o address show dev "$interface" | grep -F -- "$local_cidr" >/dev/null
        wg show "$interface" allowed-ips | grep -F -- "$remote_cidr" >/dev/null
        curl --noproxy "*" --fail --silent --show-error --max-time 5 "$remote_url" >/dev/null
        wg show "$interface" latest-handshakes | awk '\''$2 > 0 { found = 1 } END { exit !found }'\''
      ' sh ipars0 "${local_vpn_ip}/32" "${remote_vpn_ip}/32" \
        "http://${remote_url_host}:9780/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "agent pod ${pod} did not establish a WireGuard path to ${remote_vpn_ip}" >&2
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
if [[ "$agent_host_network" != "true" && "$agent_host_network" != "false" ]]; then
  echo "IPARS_K8S_SMOKE_AGENT_HOST_NETWORK must be true or false" >&2
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

if [[ "$agent_host_network" == "true" ]]; then
  agent_dns_policy="ClusterFirstWithHostNet"
else
  agent_dns_policy="ClusterFirst"
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
    ipars.io/live-smoke-bootstrap: "true"
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
    - name: stun
      protocol: UDP
      port: 3478
      targetPort: stun
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
  --allowed-route "$service_cidr" \
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
        - name: stun
          image: ${image_ref_json}
          command: ["/usr/local/bin/iparsd"]
          args:
            - stun
            - --listen
            - 0.0.0.0:3478
            - --http-listen
            - 0.0.0.0:3479
          ports:
            - name: stun
              protocol: UDP
              containerPort: 3478
            - name: stun-http
              containerPort: 3479
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
agent_api_service_name="${chart_fullname}-agent"
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
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set agent.apiService.port=9780 \
  --set agent.apiService.targetPort=9780 \
  --set agent.peerMap.pollIntervalSeconds=2 \
  --set serviceExposure.routeIntervalSeconds=2 \
  --set-string 'agent.tolerations[0].operator=Exists' \
  --set "agent.hostNetwork=${agent_host_network}" \
  --set-string "agent.dnsPolicy=${agent_dns_policy}" \
  --set-string "agent.state.hostPath=${agent_state_path}" \
  --set-string "cluster.controlPlaneUrl=${control_plane_url}" \
  --set-string "cluster.signalUrl=${signal_url}" \
  --set-string "cluster.stunEndpoint=${bootstrap_cluster_ip}:3478" \
  --set serviceExposure.enabled=true \
  --set serviceExposure.discoverServices=true \
  --set serviceExposure.discoverApiServer=true \
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
if [[ "$agent_runtime_backend" == "linux-command" && "$desired_agents" -lt 2 ]]; then
  echo "linux-command live smoke requires at least two scheduled agent pods" >&2
  exit 1
fi

node_ids=()
vpn_ips=()
for pod in "${agent_pods[@]}"; do
  "$kubectl_bin" -n "$namespace" wait --for=condition=Ready "pod/${pod}" --timeout="${timeout_seconds}s"
  status_json="$(wait_for_agent_runtime "$pod")"
  node_id="$(jq -er '.node_id | strings | select(test("^node-[A-Za-z0-9._-]+$"))' <<<"$status_json")"
  vpn_ip="$(jq -er '.vpn_ip | strings' <<<"$status_json")"
  node_ids+=("$node_id")
  vpn_ips+=("$vpn_ip")
done

"$kubectl_bin" -n "$namespace" apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${service_route_name}
  labels:
    ipars.io/live-smoke: "true"
spec:
  selector:
    app.kubernetes.io/component: ipars-bootstrap
  ports:
    - name: http
      port: ${service_route_port}
      targetPort: control-plane
EOF

service_route_ip="$($kubectl_bin -n "$namespace" get service "$service_route_name" -o jsonpath='{.spec.clusterIP}')"
if [[ ! "$service_route_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "route target Service did not receive an IPv4 ClusterIP, got ${service_route_ip:-<empty>}" >&2
  exit 1
fi
api_server_service_ip="$($kubectl_bin get service kubernetes -o jsonpath='{.spec.clusterIP}')"
if [[ ! "$api_server_service_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Kubernetes API Service did not expose an IPv4 ClusterIP, got ${api_server_service_ip:-<empty>}" >&2
  exit 1
fi

for attempt in $(seq 1 60); do
  route_target_endpoints="$($kubectl_bin -n "$namespace" get endpoints "$service_route_name" \
    -o jsonpath='{range .subsets[*].addresses[*]}{.ip}{"\n"}{end}' 2>/dev/null || true)"
  if [[ -n "$route_target_endpoints" ]]; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    echo "route target Service ${service_route_name} did not receive an endpoint" >&2
    exit 1
  fi
  sleep 2
done

route_provider_node_id="${node_ids[0]}"
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
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set agent.apiService.port=9780 \
  --set agent.apiService.targetPort=9780 \
  --set agent.peerMap.pollIntervalSeconds=2 \
  --set serviceExposure.routeIntervalSeconds=2 \
  --set agent.routeProvider=false \
  --set-string 'agent.tolerations[0].operator=Exists' \
  --set "agent.hostNetwork=${agent_host_network}" \
  --set-string "agent.dnsPolicy=${agent_dns_policy}" \
  --set-string "agent.state.hostPath=${agent_state_path}" \
  --set-string "cluster.controlPlaneUrl=${control_plane_url}" \
  --set-string "cluster.signalUrl=${signal_url}" \
  --set-string "cluster.stunEndpoint=${bootstrap_cluster_ip}:3478" \
  --set serviceExposure.enabled=true \
  --set serviceExposure.discoverServices=true \
  --set serviceExposure.discoverApiServer=true \
  --set-json 'serviceExposure.serviceCidrs=[]' \
  --set-string "serviceExposure.namespaces[0]=${namespace}" \
  --set-string 'serviceExposure.serviceLabelSelector=ipars.io/live-smoke=true' \
  --set-string "serviceExposure.routeProviderNodeId=${route_provider_node_id}"

"$kubectl_bin" -n "$namespace" rollout status "daemonset/${chart_fullname}" --timeout="${timeout_seconds}s"
mapfile -t updated_agent_pods < <("$kubectl_bin" -n "$namespace" get pods \
  -l "app.kubernetes.io/name=ipars,app.kubernetes.io/instance=${release}" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#updated_agent_pods[@]} -ne $desired_agents ]]; then
  echo "route-provider rollout did not preserve the expected number of agent pods" >&2
  exit 1
fi
declare -A pod_by_node vpn_ip_by_node
for pod in "${updated_agent_pods[@]}"; do
  "$kubectl_bin" -n "$namespace" wait --for=condition=Ready "pod/${pod}" --timeout="${timeout_seconds}s"
  status_json="$(wait_for_agent_runtime "$pod")"
  node_id="$(jq -er '.node_id | strings' <<<"$status_json")"
  vpn_ip="$(jq -er '.vpn_ip | strings' <<<"$status_json")"
  if [[ -n "${pod_by_node[$node_id]+x}" ]]; then
    echo "route-provider rollout returned duplicate agent identity ${node_id}" >&2
    exit 1
  fi
  pod_by_node["$node_id"]="$pod"
  vpn_ip_by_node["$node_id"]="$vpn_ip"
done
for index in "${!node_ids[@]}"; do
  node_id="${node_ids[$index]}"
  if [[ -z "${pod_by_node[$node_id]+x}" ]]; then
    echo "agent identity ${node_id} was not preserved during route-provider rollout" >&2
    exit 1
  fi
  agent_pods[$index]="${pod_by_node[$node_id]}"
  vpn_ips[$index]="${vpn_ip_by_node[$node_id]}"
done

for pod in "${agent_pods[@]}"; do
  ipv4_forwarding="$($kubectl_bin -n "$namespace" exec "pod/${pod}" -c agent -- \
    cat /proc/sys/net/ipv4/ip_forward)"
  if [[ "$ipv4_forwarding" != "1" ]]; then
    echo "agent pod ${pod} did not enable IPv4 forwarding, got ${ipv4_forwarding:-<empty>}" >&2
    exit 1
  fi
done

wait_for_control_plane_metrics "$desired_agents"
wait_for_agent_api_service "${agent_pods[0]}" "$agent_api_service_name"

for index in "${!node_ids[@]}"; do
  node_id="${node_ids[$index]}"
  pod="${agent_pods[$index]}"
  peer_map_json="$("$kubectl_bin" -n "$namespace" exec "pod/${pod}" -c agent -- \
    /usr/local/bin/ipars --agent-state-path /var/lib/ipars/agent.json peers \
      --control-plane-url "$control_plane_url" --node-id "$node_id")"
  jq -e --arg cluster_id "$cluster_id" '.cluster_id == $cluster_id and (.peers | type == "array")' \
    >/dev/null <<<"$peer_map_json"
done

if [[ "$agent_runtime_backend" == "linux-command" ]]; then
  for local_index in "${!node_ids[@]}"; do
    for remote_index in "${!node_ids[@]}"; do
      if [[ "$local_index" == "$remote_index" ]]; then
        continue
      fi
      activate_agent_peer "${agent_pods[$local_index]}" "${node_ids[$remote_index]}"
    done
  done

  for local_index in "${!node_ids[@]}"; do
    remote_index=$(( (local_index + 1) % ${#node_ids[@]} ))
    wait_for_wireguard_path \
      "${agent_pods[$local_index]}" \
      "${vpn_ips[$local_index]}" \
      "${vpn_ips[$remote_index]}"
    allowed_ips="$("$kubectl_bin" -n "$namespace" exec "${agent_pods[$local_index]}" -c agent -- \
      wg show ipars0 allowed-ips)"
    if grep -Fq -- "${bootstrap_cluster_ip}/32" <<<"$allowed_ips"; then
      echo "agent pod ${agent_pods[$local_index]} routed its locally advertised bootstrap Service through a peer" >&2
      exit 1
    fi
    route_to_bootstrap="$("$kubectl_bin" -n "$namespace" exec "${agent_pods[$local_index]}" -c agent -- \
      ip route get "$bootstrap_cluster_ip")"
    if grep -Fq -- "dev ipars0" <<<"$route_to_bootstrap"; then
      echo "agent pod ${agent_pods[$local_index]} installed its local bootstrap Service route on ipars0" >&2
      exit 1
    fi
  done

  if [[ ${#agent_pods[@]} -ge 2 ]]; then
    provider_pod="${agent_pods[0]}"
    consumer_pod="${agent_pods[1]}"
    service_cidr_route="${service_route_ip}/32"
    api_server_cidr_route="${api_server_service_ip}/32"
    for attempt in $(seq 1 90); do
      consumer_allowed_ips="$($kubectl_bin -n "$namespace" exec "$consumer_pod" -c agent -- \
        wg show ipars0 allowed-ips 2>/dev/null || true)"
      consumer_service_route="$($kubectl_bin -n "$namespace" exec "$consumer_pod" -c agent -- \
        ip route get "$service_route_ip" 2>/dev/null || true)"
      consumer_api_route="$($kubectl_bin -n "$namespace" exec "$consumer_pod" -c agent -- \
        ip route get "$api_server_service_ip" 2>/dev/null || true)"
      service_response_code="$($kubectl_bin -n "$namespace" exec "$consumer_pod" -c agent -- \
        curl --noproxy '*' --silent --show-error --max-time 5 \
          -o /dev/null -w "%{http_code}" \
          "http://${service_route_ip}:${service_route_port}/healthz" 2>/dev/null || true)"
      api_response_code="$($kubectl_bin -n "$namespace" exec "$consumer_pod" -c agent -- \
        sh -ec '
          token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
          curl --noproxy "*" --silent --show-error --max-time 5 \
            --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
            -H "Authorization: Bearer ${token}" \
            -o /dev/null -w "%{http_code}" "https://${1}/version"
        ' sh "$api_server_service_ip" 2>/dev/null || true)"
      if grep -Fq -- "$service_cidr_route" <<<"$consumer_allowed_ips" \
        && grep -Fq -- "$api_server_cidr_route" <<<"$consumer_allowed_ips" \
        && grep -Fq -- "dev ipars0" <<<"$consumer_service_route" \
        && grep -Fq -- "dev ipars0" <<<"$consumer_api_route" \
        && [[ "$service_response_code" == "200" ]] \
        && [[ "$api_response_code" == "200" ]]; then
        echo "Kubernetes Service ${service_route_ip} and API ${api_server_service_ip} reached through route provider ${route_provider_node_id}"
        break
      fi
      if [[ "$attempt" == 90 ]]; then
        echo "consumer pod did not reach Kubernetes Service/API through ipars0" >&2
        echo "allowed IPs:\n${consumer_allowed_ips}" >&2
        echo "Service route:\n${consumer_service_route}" >&2
        echo "API route:\n${consumer_api_route}" >&2
        echo "Service response code: ${service_response_code}" >&2
        echo "API response code: ${api_response_code}" >&2
        exit 1
      fi
      sleep 2
    done

    provider_service_route="$($kubectl_bin -n "$namespace" exec "$provider_pod" -c agent -- \
      ip route get "$service_route_ip")"
    if grep -Fq -- "dev ipars0" <<<"$provider_service_route"; then
      echo "route provider ${route_provider_node_id} routed its local Kubernetes Service through ipars0" >&2
      exit 1
    fi

    "$kubectl_bin" -n "$namespace" exec "$provider_pod" -c agent -- \
      sh -ec '
        ip -4 route replace "$1" dev ipars0 table 10064 protocol 242
      ' sh "$stale_kubernetes_route_cidr"
    for attempt in $(seq 1 90); do
      stale_routes="$($kubectl_bin -n "$namespace" exec "$provider_pod" -c agent -- \
        ip -4 route show table 10064 protocol 242 2>/dev/null || true)"
      if ! grep -Fq -- "$stale_kubernetes_route_cidr" <<<"$stale_routes"; then
        echo "route provider ${route_provider_node_id} removed stale Kubernetes managed route ${stale_kubernetes_route_cidr}"
        break
      fi
      if [[ "$attempt" == 90 ]]; then
        echo "route provider ${route_provider_node_id} retained stale Kubernetes managed route ${stale_kubernetes_route_cidr}" >&2
        echo "managed Kubernetes routes:\n${stale_routes}" >&2
        exit 1
      fi
      sleep 2
    done
  fi
fi

echo "Kubernetes live smoke checks completed for ${#agent_pods[@]} agent pod(s)"
