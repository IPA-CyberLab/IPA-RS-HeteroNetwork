#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker_bin="${DOCKER:-docker}"
dockerd_rootless_bin="${DOCKERD_ROOTLESS:-dockerd-rootless.sh}"
cargo_bin="${CARGO:-cargo}"
suffix="$$-$(date +%s%N)"
tmp_dir=""
runtime_dir=""
docker_socket=""
workload_network_a=""
workload_network_b=""
daemon_pid=""
daemon_pid_file=""
project_name="heteronetwork-rootless-${suffix}"
override_path=""
rootless_attach_overrides=()
e2e_started=0

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command '${command_name}' is not available in PATH" >&2
    exit 1
  fi
}

cleanup() {
  local status=$?
  trap - EXIT

  if [[ "$status" -ne 0 && -n "$daemon_pid" ]]; then
    echo "rootless Docker daemon log:" >&2
    sed -n '1,240p' "$tmp_dir/dockerd.log" >&2 2>/dev/null || true
  fi

  if [[ -n "$override_path" ]]; then
    local compose_files=(
      -f "$repo_root/docker/compose.yaml"
      -f "$repo_root/docker/compose.rootless.yaml"
      -f "$repo_root/docker/compose.rootless-dataplane.yaml"
    )
    if [[ "$e2e_started" -eq 1 ]]; then
      compose_files+=( -f "$repo_root/docker/compose.rootless-e2e.yaml" )
      compose_files+=( -f "$repo_root/docker/compose.rootless-route-provider-e2e.yaml" )
      compose_files+=( -f "$repo_root/docker/compose.rootless-discovery-e2e.yaml" )
      compose_files+=( -f "$repo_root/docker/compose.rootless-docker-discovery.yaml" )
      for attach_override in "${rootless_attach_overrides[@]}"; do
        compose_files+=( -f "$attach_override" )
      done
    else
      compose_files+=( -f "$override_path" )
    fi
    DOCKER_HOST="unix://${docker_socket}" \
      "$docker_bin" compose \
        -p "$project_name" \
        "${compose_files[@]}" \
        down --remove-orphans >/dev/null 2>&1 || true
  fi

  if [[ -n "$workload_network_a" ]]; then
    DOCKER_HOST="unix://${docker_socket}" "$docker_bin" network rm "$workload_network_a" >/dev/null 2>&1 || true
  fi
  if [[ -n "$workload_network_b" ]]; then
    DOCKER_HOST="unix://${docker_socket}" "$docker_bin" network rm "$workload_network_b" >/dev/null 2>&1 || true
  fi

  if [[ -n "$daemon_pid_file" && -f "$daemon_pid_file" ]]; then
    kill "$(cat "$daemon_pid_file")" >/dev/null 2>&1 || true
  fi
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$tmp_dir" ]]; then
    rm -rf "$tmp_dir" >/dev/null 2>&1 || true
  fi
  exit "$status"
}

require_command "$docker_bin"
require_command "$cargo_bin"
require_command jq
require_command curl
if command -v "$dockerd_rootless_bin" >/dev/null 2>&1; then
  rootless_launcher="dockerd-rootless"
else
  require_command dockerd
  rootless_launcher="rootlesskit"
fi
require_command rootlesskit
require_command fuse-overlayfs
require_command newuidmap
require_command newgidmap
if ! command -v slirp4netns >/dev/null 2>&1 && ! command -v vpnkit >/dev/null 2>&1; then
  echo "rootless Docker requires slirp4netns or vpnkit for user-mode networking" >&2
  exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "rootless Docker smoke requires /dev/net/tun; load the tun kernel module first" >&2
  exit 1
fi

user_name="$(id -un)"
if ! awk -F: -v user="$user_name" '$1 == user && $3 >= 65536 { found = 1 } END { exit !found }' /etc/subuid; then
  echo "${user_name} needs at least 65536 subordinate UIDs in /etc/subuid" >&2
  exit 1
fi
if ! awk -F: -v user="$user_name" '$1 == user && $3 >= 65536 { found = 1 } END { exit !found }' /etc/subgid; then
  echo "${user_name} needs at least 65536 subordinate GIDs in /etc/subgid" >&2
  exit 1
fi

trap cleanup EXIT
umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-rootless-smoke.XXXXXX")"
runtime_dir="$tmp_dir/runtime"
mkdir -m 700 "$runtime_dir"
docker_socket="$runtime_dir/docker.sock"
daemon_pid_file="$tmp_dir/dockerd.pid"

(
  export XDG_RUNTIME_DIR="$runtime_dir"
  export DOCKER_HOST="unix://${docker_socket}"
  if [[ "$rootless_launcher" == "dockerd-rootless" ]]; then
    exec "$dockerd_rootless_bin" \
      --host="$DOCKER_HOST" \
      --data-root="$tmp_dir/data" \
      --exec-root="$tmp_dir/exec" \
      --pidfile="$daemon_pid_file" \
      --storage-driver=fuse-overlayfs \
      --exec-opt=native.cgroupdriver=cgroupfs \
      --iptables=false \
      --dns=10.0.2.3 \
      --ip-forward=false
  fi
  exec rootlesskit \
    --net=slirp4netns \
    --mtu=65520 \
    --slirp4netns-sandbox=auto \
    --slirp4netns-seccomp=auto \
    --disable-host-loopback \
    --port-driver=builtin \
    --copy-up=/etc \
    --copy-up=/run \
    --propagation=rslave \
    --state-dir="$tmp_dir/rootlesskit" \
    sh -ec '
      rm -f /run/docker /run/containerd /run/xtables.lock
      exec dockerd "$@"
    ' sh \
      --host="$DOCKER_HOST" \
      --data-root="$tmp_dir/data" \
      --exec-root="$tmp_dir/exec" \
      --pidfile="$daemon_pid_file" \
      --storage-driver=fuse-overlayfs \
      --exec-opt=native.cgroupdriver=cgroupfs \
      --iptables=false \
      --dns=10.0.2.3 \
      --ip-forward=false
) >"$tmp_dir/dockerd.log" 2>&1 &
daemon_pid=$!

daemon_ready=0
for _ in $(seq 1 90); do
  if DOCKER_HOST="unix://${docker_socket}" "$docker_bin" info >/dev/null 2>&1; then
    daemon_ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if [[ "$daemon_ready" -ne 1 ]]; then
  echo "rootless Docker daemon did not become ready" >&2
  exit 1
fi

rendered_config="$tmp_dir/compose-config.yaml"
DOCKER_HOST="unix://${docker_socket}" "$docker_bin" compose \
  -p "$project_name" \
  -f "$repo_root/docker/compose.yaml" \
  -f "$repo_root/docker/compose.rootless.yaml" \
  -f "$repo_root/docker/compose.rootless-dataplane.yaml" \
  config --no-interpolate >"$rendered_config"
grep -F 'HETERONETWORK_AGENT_RUNTIME_BACKEND=linux-command' "$rendered_config" >/dev/null
grep -F 'HETERONETWORK_AGENT_WIREGUARD_BACKEND=userspace-boringtun' "$rendered_config" >/dev/null
grep -F '/dev/net/tun' "$rendered_config" >/dev/null
grep -F 'NET_ADMIN' "$rendered_config" >/dev/null

override_path="$tmp_dir/preflight.override.yaml"
cat >"$override_path" <<'EOF'
services:
  agent:
    command:
      - agent
      - --preflight-only
      - --apply-peer-map
      - --runtime-backend
      - linux-command
      - --wireguard-backend
      - userspace-boringtun
      - --route-backend
      - command
      - --stun-bind
      - 0.0.0.0:51821
      - --wireguard-listen-port
      - "51821"
      - --peer-probe-port
      - "51822"
    cap_add: !override
      - NET_ADMIN
    devices: !override
      - /dev/net/tun:/dev/net/tun
    environment: !override []
    secrets: !reset []
    volumes: !reset []
EOF

DOCKER_HOST="unix://${docker_socket}" "$docker_bin" compose \
  -p "$project_name" \
  -f "$repo_root/docker/compose.yaml" \
  -f "$repo_root/docker/compose.rootless.yaml" \
  -f "$repo_root/docker/compose.rootless-dataplane.yaml" \
  -f "$override_path" \
  run --rm --no-deps --build agent

echo "Rootless Docker BoringTun preflight passed"

generate_secret() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

run_ipars() {
  "$cargo_bin" run --locked --quiet -p ipars-cli -- "$@"
}

issuer_key_path="$tmp_dir/rootless-e2e-issuer.key"
init_output_path="$tmp_dir/rootless-e2e-init.json"
token_output_path="$tmp_dir/rootless-e2e-token.json"
join_token_path="$tmp_dir/rootless-e2e.join.token"
agent_api_token_path="$tmp_dir/rootless-e2e-agent-api.token"
control_plane_operator_token_path="$tmp_dir/rootless-e2e-control-plane-operator.token"
signal_operator_token_path="$tmp_dir/rootless-e2e-signal-operator.token"
stun_operator_token_path="$tmp_dir/rootless-e2e-stun-operator.token"
relay_operator_token_path="$tmp_dir/rootless-e2e-relay-operator.token"
relay_admission_token_path="$tmp_dir/rootless-e2e-relay-admission.token"

run_ipars init \
  --public-endpoint 172.30.250.3:8443 \
  --bootstrap-scheme http \
  --issuer-key-id rootless-e2e \
  --issuer-private-key-path "$issuer_key_path" \
  --emit-issuer-private-key \
  --token-ttl-seconds 3600 \
  --unlimited-uses \
  --allowed-route 100.64.0.0/10 \
  --allowed-route 172.30.251.0/24 \
  --allowed-route 172.30.252.0/24 \
  --allowed-route 172.30.253.0/24 \
  >"$init_output_path"

rootless_cluster_id="$(jq -er '.cluster_id' "$init_output_path")"
rootless_issuer_node_id="$(jq -er '.issuer_node_id' "$init_output_path")"
rootless_issuer_key_id="$(jq -er '.issuer_key_id' "$init_output_path")"
rootless_issuer_public_key="$(jq -er '.issuer_public_key' "$init_output_path")"

run_ipars token create \
  --cluster-id "$rootless_cluster_id" \
  --issuer-key-id "$rootless_issuer_key_id" \
  --issuer-private-key-path "$issuer_key_path" \
  --role edge \
  --ttl-seconds 3600 \
  --unlimited-uses \
  --allowed-route 100.64.0.0/10 \
  --allowed-route 172.30.251.0/24 \
  --allowed-route 172.30.252.0/24 \
  --allowed-route 172.30.253.0/24 \
  --control-plane-bootstrap http://172.30.250.3:8443 \
  --signal-bootstrap http://172.30.250.4:9443 \
  --stun-bootstrap udp://172.30.250.5:3478 \
  >"$token_output_path"
jq -ce '.' "$token_output_path" >"$join_token_path"

for secret_path in \
  "$agent_api_token_path" \
  "$control_plane_operator_token_path" \
  "$signal_operator_token_path" \
  "$stun_operator_token_path" \
  "$relay_operator_token_path" \
  "$relay_admission_token_path"; do
  generate_secret >"$secret_path"
done

export HETERONETWORK_ROOTLESS_CLUSTER_ID="$rootless_cluster_id"
export HETERONETWORK_ROOTLESS_ISSUER_NODE_ID="$rootless_issuer_node_id"
export HETERONETWORK_ROOTLESS_ISSUER_KEY_ID="$rootless_issuer_key_id"
export HETERONETWORK_ROOTLESS_ISSUER_PUBLIC_KEY="$rootless_issuer_public_key"
export HETERONETWORK_ROOTLESS_JOIN_TOKEN_FILE="$join_token_path"
export HETERONETWORK_ROOTLESS_AGENT_API_TOKEN_FILE="$agent_api_token_path"
export HETERONETWORK_ROOTLESS_CONTROL_PLANE_OPERATOR_TOKEN_FILE="$control_plane_operator_token_path"
export HETERONETWORK_ROOTLESS_SIGNAL_OPERATOR_TOKEN_FILE="$signal_operator_token_path"
export HETERONETWORK_ROOTLESS_STUN_OPERATOR_TOKEN_FILE="$stun_operator_token_path"
export HETERONETWORK_ROOTLESS_RELAY_OPERATOR_TOKEN_FILE="$relay_operator_token_path"
export HETERONETWORK_ROOTLESS_RELAY_ADMISSION_TOKEN_FILE="$relay_admission_token_path"
workload_network_a="${project_name}_workload-a"
workload_network_b="${project_name}_workload-b"
export HETERONETWORK_DOCKER_API_SOCKET_HOST="$docker_socket"
export HETERONETWORK_ROOTLESS_DOCKER_NETWORK_A="$workload_network_a"
export HETERONETWORK_ROOTLESS_DOCKER_NETWORK_B="$workload_network_b"
workload_a_http_port="${HETERONETWORK_ROOTLESS_WORKLOAD_A_HTTP_PORT:-18080}"
workload_b_http_port="${HETERONETWORK_ROOTLESS_WORKLOAD_B_HTTP_PORT:-18081}"
for workload_http_port in "$workload_a_http_port" "$workload_b_http_port"; do
  if [[ ! "$workload_http_port" =~ ^[0-9]+$ || "$workload_http_port" -lt 1 || "$workload_http_port" -gt 65535 ]]; then
    echo "rootless workload HTTP ports must be integers between 1 and 65535" >&2
    exit 1
  fi
done
if [[ "$workload_a_http_port" == "$workload_b_http_port" ]]; then
  echo "rootless workload HTTP ports must be distinct across Agent namespaces" >&2
  exit 1
fi
export HETERONETWORK_ROOTLESS_WORKLOAD_A_HTTP_PORT="$workload_a_http_port"
export HETERONETWORK_ROOTLESS_WORKLOAD_B_HTTP_PORT="$workload_b_http_port"

rootless_e2e_compose() {
  local compose_files=(
    -f "$repo_root/docker/compose.yaml"
    -f "$repo_root/docker/compose.rootless.yaml"
    -f "$repo_root/docker/compose.rootless-dataplane.yaml"
    -f "$repo_root/docker/compose.rootless-e2e.yaml"
    -f "$repo_root/docker/compose.rootless-route-provider-e2e.yaml"
    -f "$repo_root/docker/compose.rootless-discovery-e2e.yaml"
    -f "$repo_root/docker/compose.rootless-docker-discovery.yaml"
  )
  for attach_override in "${rootless_attach_overrides[@]}"; do
    compose_files+=( -f "$attach_override" )
  done
  DOCKER_HOST="unix://${docker_socket}" "$docker_bin" compose \
    -p "$project_name" "${compose_files[@]}" "$@"
}

rootless_host_workload_diagnostics() {
  local reason="$1"
  echo "rootless host-to-workload diagnostics (${reason}):" >&2
  rootless_e2e_compose ps >&2 || true
  rootless_e2e_compose logs --no-color --tail=160 agent agent-b workload-a workload-b >&2 || true
}

if ! rootless_e2e_compose config --format json >"$tmp_dir/rootless-e2e-config.json"; then
  echo "rootless e2e Compose config rendering failed" >&2
  "$docker_bin" compose version >&2 || true
  exit 1
fi
if ! jq -e --arg network_a "$workload_network_a" --arg network_b "$workload_network_b" '
  .services.agent.environment.HETERONETWORK_DOCKER_DISCOVER_NETWORKS == "true"
  and .services.agent.environment.HETERONETWORK_DOCKER_NETWORKS == $network_a
  and .services.agent.environment.HETERONETWORK_DOCKER_CONTAINER_CIDRS == null
  and .services["agent-b"].environment.HETERONETWORK_DOCKER_DISCOVER_NETWORKS == "true"
  and .services["agent-b"].environment.HETERONETWORK_DOCKER_NETWORKS == $network_b
  and .services["agent-b"].environment.HETERONETWORK_DOCKER_CONTAINER_CIDRS == null
  # Compose v2.38 omits false-valued bind fields from JSON; reject only true.
  and any(.services.agent.volumes[]; .target == "/run/heteronetwork/docker.sock" and .read_only == true and ((.bind.create_host_path // false) == false))
  and any(.services["agent-b"].volumes[]; .target == "/run/heteronetwork/docker.sock" and .read_only == true and ((.bind.create_host_path // false) == false))
' "$tmp_dir/rootless-e2e-config.json" >/dev/null; then
  echo "rootless e2e Compose discovery contract mismatch" >&2
  "$docker_bin" compose version >&2 || true
  jq '{agent: {environment: .services.agent.environment, volumes: .services.agent.volumes}, agent_b: {environment: .services["agent-b"].environment, volumes: .services["agent-b"].volumes}}' \
    "$tmp_dir/rootless-e2e-config.json" >&2 || true
  exit 1
fi

rootless_attach_overrides=(
  "$tmp_dir/rootless-workload-a-attach.yaml"
  "$tmp_dir/rootless-workload-b-attach.yaml"
)
if ! "$repo_root/scripts/rootless-compose-attach.sh" \
  --config-json "$tmp_dir/rootless-e2e-config.json" \
  --agent-service agent \
  --workload-service workload-a \
  --output "${rootless_attach_overrides[0]}"; then
  echo "rootless workload-a namespace attachment generation failed" >&2
  exit 1
fi
if ! "$repo_root/scripts/rootless-compose-attach.sh" \
  --config-json "$tmp_dir/rootless-e2e-config.json" \
  --agent-service agent-b \
  --workload-service workload-b \
  --output "${rootless_attach_overrides[1]}"; then
  echo "rootless workload-b namespace attachment generation failed" >&2
  exit 1
fi
if ! rootless_e2e_compose config --format json >"$tmp_dir/rootless-e2e-attached-config.json"; then
  echo "rootless attached Compose config rendering failed" >&2
  rootless_e2e_compose config >&2 || true
  exit 1
fi
if ! jq -e --arg port_a "$workload_a_http_port" --arg port_b "$workload_b_http_port" '
  .services["workload-a"].network_mode == "service:agent"
  and .services["workload-b"].network_mode == "service:agent-b"
  and .services["workload-a"].ports == null
  and .services["workload-b"].ports == null
  and any(.services.agent.ports[]; (.target == 8080 and (.published | tostring) == $port_a))
  and any(.services["agent-b"].ports[]; (.target == 8080 and (.published | tostring) == $port_b))
' "$tmp_dir/rootless-e2e-attached-config.json" >/dev/null; then
  echo "rootless workload namespace attachment contract mismatch" >&2
  jq '{agent: .services.agent, agent_b: .services["agent-b"], workload_a: .services["workload-a"], workload_b: .services["workload-b"]}' \
    "$tmp_dir/rootless-e2e-attached-config.json" >&2 || true
  exit 1
fi
e2e_started=1
if ! rootless_e2e_compose up -d --build --wait --wait-timeout 300; then
  rootless_e2e_compose ps >&2 || true
  rootless_e2e_compose logs --no-color --tail=160 control-plane signal stun agent agent-b workload-a workload-b >&2 || true
  exit 1
fi

for workload_http_port in "$workload_a_http_port" "$workload_b_http_port"; do
  host_workload_ready=0
  for _ in $(seq 1 60); do
    if curl --noproxy "*" --fail --silent --show-error --max-time 3 \
      "http://127.0.0.1:${workload_http_port}/healthz" >/dev/null 2>&1; then
      host_workload_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$host_workload_ready" -ne 1 ]]; then
    echo "rootless host-to-workload published port ${workload_http_port} did not become reachable" >&2
    rootless_host_workload_diagnostics "published port failed"
    exit 1
  fi
done
echo "rootless host-to-workload published ports ${workload_a_http_port},${workload_b_http_port} are reachable"

agent_get() {
  local service="$1"
  local path="$2"
  rootless_e2e_compose exec -T "$service" sh -ec '
    token="$(cat /run/secrets/heteronetwork-agent-api-bearer-token)"
    curl --noproxy "*" -fsS -H "Authorization: Bearer ${token}" "http://127.0.0.1:9780${1}"
  ' sh "$path"
}

agent_post_peer_activity() {
  local service="$1"
  local peer="$2"
  rootless_e2e_compose exec -T "$service" sh -ec '
    token="$(cat /run/secrets/heteronetwork-agent-api-bearer-token)"
    body="$(printf '\''{"peer":"%s","pin":true}'\'' "$1")"
    curl --noproxy "*" -fsS \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -X POST --data "${body}" \
      http://127.0.0.1:9780/v1/peer-activity
  ' sh "$peer"
}

wait_for_agent_status() {
  local service="$1"
  local value=""
  for _ in $(seq 1 120); do
    value="$(agent_get "$service" /v1/status 2>/dev/null || true)"
    if jq -e '
      (.node_id | type == "string" and length > 0)
      and (.identity_public_key | type == "string" and length > 0)
      and (.wireguard_public_key | type == "string" and length > 0)
      and (.vpn_ip | type == "string" and length > 0)
    ' <<<"$value" >/dev/null 2>&1; then
      printf '%s\n' "$value"
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${service} agent status" >&2
  rootless_e2e_compose logs --no-color --tail=160 "$service" >&2 || true
  return 1
}

wait_for_agent_peer_map() {
  local service="$1"
  local value=""
  for _ in $(seq 1 120); do
    value="$(agent_get "$service" /v1/metrics 2>/dev/null || true)"
    if jq -e '.peer_map_synced == true and (.peer_map_peer_count // 0) >= 1' <<<"$value" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${service} peer-map sync" >&2
  agent_get "$service" /v1/metrics >&2 || true
  return 1
}

wait_for_agent_path() {
  local service="$1"
  local local_node="$2"
  local remote_node="$3"
  local value=""
  for _ in $(seq 1 120); do
    value="$(agent_get "$service" /v1/paths 2>/dev/null || true)"
    if jq -e --arg local_node "$local_node" --arg remote_node "$remote_node" '
      any(.paths[]?;
        .key.local == $local_node
        and .key.remote == $remote_node
        and (.selected_state | type == "string" and length > 0)
      )
    ' <<<"$value" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${service} path record" >&2
  agent_get "$service" /v1/paths >&2 || true
  return 1
}

wait_for_direct_path() {
  local service="$1"
  local local_node="$2"
  local remote_node="$3"
  local value=""
  local metrics=""
  for _ in $(seq 1 120); do
    value="$(agent_get "$service" /v1/paths 2>/dev/null || true)"
    metrics="$(agent_get "$service" /v1/metrics 2>/dev/null || true)"
    if jq -e --arg local_node "$local_node" --arg remote_node "$remote_node" '
      any(.paths[]?;
        .key.local == $local_node
        and .key.remote == $remote_node
        and (.selected_state | type == "string" and startswith("DIRECT_"))
      )
    ' <<<"$value" >/dev/null 2>&1 \
      && jq -e '(.direct_path_probe_confirmed_count // 0) >= 1' <<<"$metrics" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${service} direct path" >&2
  agent_get "$service" /v1/paths >&2 || true
  agent_get "$service" /v1/metrics >&2 || true
  return 1
}

assert_vpn_route() {
  local service="$1"
  local remote_vpn_ip="$2"
  rootless_e2e_compose exec -T "$service" sh -ec '
    ip route get "$1" | grep -Eq " dev heteronetwork0( |$)"
  ' sh "$remote_vpn_ip"
}

assert_vpn_http() {
  local service="$1"
  local remote_vpn_ip="$2"
  rootless_e2e_compose exec -T "$service" sh -ec '
    curl --noproxy "*" --connect-timeout 5 --max-time 15 -fsS "http://${1}:9780/healthz" | grep -F '\''"status":"ok"'\'' >/dev/null
  ' sh "$remote_vpn_ip"
}

assert_workload_http() {
  local service="$1"
  local remote_workload_ip="$2"
  rootless_e2e_compose exec -T "$service" sh -ec '
    ip route get "$1" | grep -Eq " dev heteronetwork0( |$)"
    curl --noproxy "*" --connect-timeout 5 --max-time 15 -fsS "http://${1}:8080/healthz" | grep -F '\''"status":"ok"'\'' >/dev/null
  ' sh "$remote_workload_ip"
}

wait_for_workload_http() {
  local service="$1"
  local remote_workload_ip="$2"
  for _ in $(seq 1 120); do
    if assert_workload_http "$service" "$remote_workload_ip" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_workload_route_churn() {
  local service="$1"
  local remote_workload_ip="$2"
  local stale_workload_cidr="$3"
  local stale_workload_ip="${stale_workload_cidr%/*}"
  for _ in $(seq 1 120); do
    if assert_workload_http "$service" "$remote_workload_ip" >/dev/null 2>&1 \
      && ! rootless_e2e_compose exec -T "$service" sh -ec '
        wg show heteronetwork0 allowed-ips | grep -F -- "$1" >/dev/null
      ' sh "$stale_workload_cidr" \
      && ! rootless_e2e_compose exec -T "$service" sh -ec '
        ip route get "$1" | grep -Eq " dev heteronetwork0( |$)"
      ' sh "$stale_workload_ip"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rootless_dataplane_diagnostics() {
  local reason="$1"
  echo "rootless dataplane diagnostics (${reason}):" >&2
  for service in agent agent-b; do
    echo "--- ${service} paths ---" >&2
    agent_get "$service" /v1/paths >&2 || true
    echo "--- ${service} metrics ---" >&2
    agent_get "$service" /v1/metrics >&2 || true
    echo "--- ${service} network and WireGuard ---" >&2
    rootless_e2e_compose exec -T "$service" sh -ec '
      ip address show
      ip route show
      wg show heteronetwork0
    ' >&2 || true
  done
  echo "--- agent logs ---" >&2
  rootless_e2e_compose logs --no-color --tail=200 agent agent-b workload-a workload-b >&2 || true
}

agent_a_status="$(wait_for_agent_status agent)"
agent_b_status="$(wait_for_agent_status agent-b)"
agent_a_node="$(jq -er '.node_id' <<<"$agent_a_status")"
agent_b_node="$(jq -er '.node_id' <<<"$agent_b_status")"
agent_a_vpn_ip="$(jq -er '.vpn_ip' <<<"$agent_a_status")"
agent_b_vpn_ip="$(jq -er '.vpn_ip' <<<"$agent_b_status")"
if [[ "$agent_a_node" == "$agent_b_node" ]]; then
  echo "rootless E2E agents registered the same node_id ${agent_a_node}" >&2
  exit 1
fi

wait_for_agent_peer_map agent
wait_for_agent_peer_map agent-b
agent_post_peer_activity agent "$agent_b_node" >/dev/null
agent_post_peer_activity agent-b "$agent_a_node" >/dev/null
wait_for_agent_path agent "$agent_a_node" "$agent_b_node"
wait_for_agent_path agent-b "$agent_b_node" "$agent_a_node"
assert_vpn_route agent "$agent_b_vpn_ip"
assert_vpn_route agent-b "$agent_a_vpn_ip"
if ! assert_vpn_http agent "$agent_b_vpn_ip"; then
  rootless_dataplane_diagnostics "agent HTTP over VPN failed"
  exit 1
fi
if ! assert_vpn_http agent-b "$agent_a_vpn_ip"; then
  rootless_dataplane_diagnostics "agent-b HTTP over VPN failed"
  exit 1
fi
if ! wait_for_direct_path agent "$agent_a_node" "$agent_b_node"; then
  rootless_dataplane_diagnostics "agent direct path failed"
  exit 1
fi
if ! wait_for_direct_path agent-b "$agent_b_node" "$agent_a_node"; then
  rootless_dataplane_diagnostics "agent-b direct path failed"
  exit 1
fi

echo "Rootless Docker BoringTun two-agent VPN packet and direct-path smoke passed"

if ! assert_workload_http agent 172.30.252.2; then
  rootless_dataplane_diagnostics "agent could not reach remote rootless workload"
  exit 1
fi
if ! assert_workload_http agent-b 172.30.251.2; then
  rootless_dataplane_diagnostics "agent-b could not reach remote rootless workload"
  exit 1
fi

agent_a_container="$(rootless_e2e_compose ps -q agent)"
if [[ -z "$agent_a_container" ]]; then
  rootless_dataplane_diagnostics "could not identify Agent A container for Docker network churn"
  exit 1
fi
DOCKER_HOST="unix://${docker_socket}" "$docker_bin" network disconnect -f \
  "$workload_network_a" "$agent_a_container"
DOCKER_HOST="unix://${docker_socket}" "$docker_bin" network rm "$workload_network_a"
DOCKER_HOST="unix://${docker_socket}" "$docker_bin" network create \
  --driver bridge \
  --subnet 172.30.253.0/24 \
  --gateway 172.30.253.1 \
  "$workload_network_a" >/dev/null
DOCKER_HOST="unix://${docker_socket}" "$docker_bin" network connect \
  --ip 172.30.253.2 \
  "$workload_network_a" "$agent_a_container"

if ! wait_for_workload_route_churn agent-b 172.30.253.2 172.30.251.0/24; then
  rootless_dataplane_diagnostics "Docker API network discovery did not reconcile the live workload subnet change"
  exit 1
fi

if ! assert_vpn_http workload-a "$agent_b_vpn_ip"; then
  rootless_dataplane_diagnostics "workload-a could not reach the remote agent over the VPN"
  exit 1
fi
if ! assert_vpn_http workload-b "$agent_a_vpn_ip"; then
  rootless_dataplane_diagnostics "workload-b could not reach the remote agent over the VPN"
  exit 1
fi

echo "Rootless Docker route-provider workload namespace smoke passed"
