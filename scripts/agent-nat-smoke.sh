#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ipars_bin="${IPARS_AGENT_NAT_SMOKE_IPARS_BIN:-${repo_root}/target/debug/ipars}"
iparsd_bin="${IPARS_AGENT_NAT_SMOKE_IPARSD_BIN:-${repo_root}/target/debug/iparsd}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipars-agent-nat-smoke.XXXXXX")"
state_dir="${work_dir}/bootstrap"
init_output="${work_dir}/init.json"
init_error="${work_dir}/init.stderr"
join_token_path="${work_dir}/agent.join-token"
control_plane_operator_token_path="${state_dir}/control-plane-operator.token"
control_plane_operator_header_path="${work_dir}/control-plane-operator.header"
nat_profile="${IPARS_AGENT_NAT_SMOKE_PROFILE:-endpoint-independent}"

case "$nat_profile" in
  endpoint-independent|symmetric|one-sided)
    ;;
  *)
    echo "unsupported IPARS_AGENT_NAT_SMOKE_PROFILE: ${nat_profile}" >&2
    echo "expected endpoint-independent, symmetric, or one-sided" >&2
    exit 1
    ;;
esac

suffix="$$"
bridge="ipbn${suffix}"
nat_a="ipars-nat-a-${suffix}"
nat_b="ipars-nat-b-${suffix}"
agent_a="ipars-agent-a-${suffix}"
agent_b="ipars-agent-b-${suffix}"

root_public_ip="198.18.100.1"
nat_a_public_ip="198.18.100.2"
nat_b_public_ip="198.18.100.3"
nat_a_gateway="10.250.0.1"
nat_a_agent_ip="10.250.0.2"
nat_b_gateway="10.251.0.1"
nat_b_agent_ip="10.251.0.2"

nat_a_root_public_if="ipap${suffix}"
nat_a_public_if="ipnp${suffix}"
nat_a_agent_if="ipaa${suffix}"
nat_a_private_if="ipna${suffix}"
nat_b_root_public_if="ipbp${suffix}"
nat_b_public_if="ipnq${suffix}"
nat_b_agent_if="ipab${suffix}"
nat_b_private_if="ipnb${suffix}"

agent_a_pid=""
agent_b_pid=""
signal_pid=""
agent_pids=()
public_ports=()
port_base=""
direct_rule_a=()
direct_rule_b=()
direct_input_rule_a=()
direct_input_rule_b=()
cleanup_status=0

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command '${command_name}' is not available in PATH" >&2
    exit 1
  fi
}

port_in_use() {
  local port="$1"
  ss -H -ltnu 2>/dev/null | awk -v port="$port" '$5 ~ (":" port "$") { found = 1 } END { exit !found }'
}

pick_port_base() {
  local base
  local port
  local available
  for _ in $(seq 1 100); do
    base=$((40000 + (RANDOM % 12000)))
    available=1
    for port in $(seq "$base" "$((base + 7))"); do
      if port_in_use "$port"; then
        available=0
        break
      fi
    done
    if [[ "$available" == "1" ]]; then
      printf '%s\n' "$base"
      return 0
    fi
  done
  echo "could not find eight consecutive unused local ports" >&2
  return 1
}

kill_pid() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  kill "$pid" 2>/dev/null || true
}

kill_namespace_processes() {
  local namespace="$1"
  local pids
  pids="$(ip netns pids "$namespace" 2>/dev/null || true)"
  for pid in $pids; do
    kill_pid "$pid"
  done
  sleep 0.2
  pids="$(ip netns pids "$namespace" 2>/dev/null || true)"
  for pid in $pids; do
    kill -9 "$pid" 2>/dev/null || true
  done
}

dump_failure() {
  echo "agent NAT smoke failed" >&2
  if [[ -s "$init_error" ]]; then
    echo "--- init stderr ---" >&2
    cat "$init_error" >&2 || true
  fi
  if [[ -s "$init_output" ]]; then
    echo "--- init output ---" >&2
    jq . "$init_output" >&2 2>/dev/null || cat "$init_output" >&2
  fi
  for log in "${work_dir}"/agent-*.log "${state_dir}"/logs/*.log; do
    [[ -f "$log" ]] || continue
    echo "--- ${log} ---" >&2
    tail -n 120 "$log" >&2 || true
  done
  for namespace in "$agent_a" "$agent_b" "$nat_a" "$nat_b"; do
    if ip netns list | awk '{print $1}' | grep -Fx -- "$namespace" >/dev/null 2>&1; then
      echo "--- ${namespace} links/routes ---" >&2
      ip -n "$namespace" addr show >&2 || true
      ip -n "$namespace" route show >&2 || true
    fi
  done
}

cleanup() {
  cleanup_status=$?
  trap - EXIT
  set +e

  kill_pid "$agent_a_pid"
  kill_pid "$agent_b_pid"
  kill_pid "$signal_pid"
  if [[ -s "$init_output" ]]; then
    while IFS= read -r pid; do
      kill_pid "$pid"
    done < <(jq -r '.daemon_processes[]?.pid' "$init_output" 2>/dev/null || true)
  fi

  for namespace in "$agent_a" "$agent_b" "$nat_a" "$nat_b"; do
    kill_namespace_processes "$namespace"
  done
  sleep 0.3
  for namespace in "$agent_a" "$agent_b" "$nat_a" "$nat_b"; do
    ip netns del "$namespace" >/dev/null 2>&1 || true
  done
  ip link del "$bridge" >/dev/null 2>&1 || true

  if [[ "$cleanup_status" -ne 0 ]]; then
    dump_failure
  fi
  rm -rf "$work_dir"
  exit "$cleanup_status"
}

wait_root_health() {
  local host="$1"
  local port="$2"
  for _ in $(seq 1 45); do
    if curl --fail --silent --show-error --max-time 3 \
      "http://${host}:${port}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "public service on port ${port} did not become healthy" >&2
  return 1
}

ns_curl() {
  local namespace="$1"
  local url="$2"
  ip netns exec "$namespace" curl --fail --silent --show-error --max-time 3 "$url"
}

wait_agent_health() {
  local namespace="$1"
  for _ in $(seq 1 60); do
    if ns_curl "$namespace" "http://127.0.0.1:9780/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "agent HTTP service in ${namespace} did not become healthy" >&2
  return 1
}

create_agent_nat_pair() {
  local nat_namespace="$1"
  local agent_namespace="$2"
  local public_ip="$3"
  local agent_ip="$4"
  local gateway_ip="$5"
  local root_public_if="$6"
  local public_if="$7"
  local agent_if="$8"
  local private_if="$9"
  local profile="${10}"

  ip link add "$root_public_if" type veth peer name "$public_if"
  ip link set "$root_public_if" master "$bridge"
  ip link set "$root_public_if" up
  ip link set "$public_if" netns "$nat_namespace"

  ip link add "$agent_if" type veth peer name "$private_if"
  ip link set "$agent_if" netns "$agent_namespace"
  ip link set "$private_if" netns "$nat_namespace"

  ip -n "$nat_namespace" link set lo up
  ip -n "$nat_namespace" link set "$public_if" up
  ip -n "$nat_namespace" addr add "${public_ip}/24" dev "$public_if"
  ip -n "$nat_namespace" route replace default via "$root_public_ip" dev "$public_if"

  ip -n "$agent_namespace" link set lo up
  ip -n "$agent_namespace" link set "$agent_if" up
  ip -n "$agent_namespace" addr add "${agent_ip}/30" dev "$agent_if"
  ip -n "$agent_namespace" route replace default via "$gateway_ip" dev "$agent_if"

  ip -n "$nat_namespace" link set "$private_if" up
  ip -n "$nat_namespace" addr add "${gateway_ip}/30" dev "$private_if"
  ip netns exec "$nat_namespace" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$nat_namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$nat_namespace" sysctl -qw net.ipv4.conf.default.rp_filter=0
  ip netns exec "$agent_namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$agent_namespace" sysctl -qw net.ipv4.conf.default.rp_filter=0

  ip netns exec "$nat_namespace" iptables -P FORWARD ACCEPT
  if [[ "$profile" == "symmetric" ]]; then
    ip netns exec "$nat_namespace" iptables -t nat -A POSTROUTING \
      -s "${agent_ip}/32" -o "$public_if" -p tcp \
      -j SNAT --to-source "$public_ip"
    ip netns exec "$nat_namespace" iptables -t nat -A POSTROUTING \
      -s "${agent_ip}/32" -o "$public_if" -p udp \
      -j SNAT --to-source "$public_ip" --random-fully
  else
    ip netns exec "$nat_namespace" iptables -t nat -A POSTROUTING \
      -s "${agent_ip}/32" -o "$public_if" -j SNAT --to-source "$public_ip"
  fi
}

create_public_agent() {
  local agent_namespace="$1"
  local public_ip="$2"
  local root_public_if="$3"
  local public_if="$4"

  ip link add "$root_public_if" type veth peer name "$public_if"
  ip link set "$root_public_if" master "$bridge"
  ip link set "$root_public_if" up
  ip link set "$public_if" netns "$agent_namespace"

  ip -n "$agent_namespace" link set lo up
  ip -n "$agent_namespace" link set "$public_if" up
  ip -n "$agent_namespace" addr add "${public_ip}/24" dev "$public_if"
  ip -n "$agent_namespace" route replace default via "$root_public_ip" dev "$public_if"
  ip netns exec "$agent_namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$agent_namespace" sysctl -qw net.ipv4.conf.default.rp_filter=0
}

block_direct_peer() {
  local nat_namespace="$1"
  local public_if="$2"
  local peer_public_ip="$3"
  local agent_ip="$4"
  local -n forward_rule_ref="$5"
  local -n input_rule_ref="$6"
  forward_rule_ref=(
    -I FORWARD 1
    -i "$public_if"
    -s "$peer_public_ip"
    -d "$agent_ip"
    -p udp
    --dport 51820
    -j DROP
  )
  input_rule_ref=(
    -I INPUT 1
    -i "$public_if"
    -s "$peer_public_ip"
    -p udp
    --dport 51820
    -j DROP
  )
  ip netns exec "$nat_namespace" iptables "${forward_rule_ref[@]}"
  ip netns exec "$nat_namespace" iptables "${input_rule_ref[@]}"
}

unblock_direct_peer() {
  local nat_namespace="$1"
  local -n rule_ref="$2"
  [[ "${#rule_ref[@]}" -gt 0 ]] || return 0
  local delete_rule=(-D "${rule_ref[1]}" "${rule_ref[@]:3}")
  ip netns exec "$nat_namespace" iptables "${delete_rule[@]}"
}

stop_signal() {
  kill_pid "$signal_pid"
  if [[ "$signal_pid" =~ ^[0-9]+$ ]]; then
    for _ in $(seq 1 30); do
      if ! kill -0 "$signal_pid" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done
    kill -9 "$signal_pid" 2>/dev/null || true
  fi
  signal_pid=""
}

start_signal() {
  local mode="$1"
  local log_path="$2"
  local -a args=(
    signal
    --listen "${root_public_ip}:${signal_port}"
    --control-plane-url "http://${root_public_ip}:${control_plane_port}"
  )
  if [[ "$mode" == "disabled" ]]; then
    args+=(--disable-nat-traversal)
  fi
  "$iparsd_bin" "${args[@]}" >"$log_path" 2>&1 &
  signal_pid=$!
  wait_root_health "$root_public_ip" "$signal_port"
}

start_agent() {
  local namespace="$1"
  local agent_ip="$2"
  local state_path="$3"
  local log_path="$4"
  ip netns exec "$namespace" "$iparsd_bin" agent \
    --listen 127.0.0.1:9780 \
    --state-path "$state_path" \
    --join-token-path "$join_token_path" \
    --control-plane-url "http://${root_public_ip}:${control_plane_port}" \
    --signal-url "http://${root_public_ip}:${signal_port}" \
    --stun-server "${root_public_ip}:${stun_port},${root_public_ip}:${stun_alternate_port}" \
    --stun-bind "${agent_ip}:51820" \
    --wireguard-listen-port 51820 \
    --wireguard-backend command \
    --route-backend command \
    --runtime-backend linux-command \
    --apply-peer-map \
    --relay-admission-bearer-token-path "${state_dir}/relay-admission.token" \
    --relay-forwarder-bind "${agent_ip}:0" \
    --relay-forwarder-wireguard-endpoint "${agent_ip}:51820" \
    --peer-map-poll-interval-seconds 2 \
    --heartbeat-interval-seconds 2 \
    --signal-registration-interval-seconds 2 \
    --signal-path-interval-seconds 2 \
    --direct-path-probe-timeout-seconds 8 \
    --direct-handshake-max-age-seconds 30 \
    --relay-session-renew-before-seconds 5 \
    --hole-punch-attempts 8 \
    --hole-punch-interval-millis 100 \
    --http-connect-timeout-seconds 3 \
    --http-request-timeout-seconds 5 \
    --disable-peer-probe \
    >"$log_path" 2>&1 &
  local pid=$!
  agent_pids+=("$pid")
  if [[ "$namespace" == "$agent_a" ]]; then
    agent_a_pid="$pid"
  else
    agent_b_pid="$pid"
  fi
}

agent_status() {
  ns_curl "$1" "http://127.0.0.1:9780/v1/status"
}

agent_metrics() {
  ns_curl "$1" "http://127.0.0.1:9780/v1/metrics"
}

agent_paths() {
  ns_curl "$1" "http://127.0.0.1:9780/v1/paths"
}

agent_peers() {
  ns_curl "$1" "http://127.0.0.1:9780/v1/peers"
}

relay_status() {
  curl --fail --silent --show-error --max-time 3 \
    "http://${root_public_ip}:${relay_http_port}/v1/status"
}

ping_overlay() {
  local namespace="$1"
  local target="$2"
  for attempt in 1 2 3; do
    if ip netns exec "$namespace" ping -I ipars0 -c 3 -W 2 "$target"; then
      return 0
    fi
    sleep 1
  done
  echo "overlay ping from ${namespace} to ${target} failed after relay/direct warm-up retries" >&2
  return 1
}

pin_agent_peer() {
  local namespace="$1"
  local peer="$2"
  local request
  request="$(jq -cn --arg peer "$peer" '{peer: $peer, pin: true}')"
  ip netns exec "$namespace" curl --fail --silent --show-error --max-time 3 \
    -X POST -H 'content-type: application/json' \
    --data "$request" http://127.0.0.1:9780/v1/peer-activity >/dev/null
}

path_state() {
  local namespace="$1"
  local peer="$2"
  agent_paths "$namespace" | jq -r --arg peer "$peer" \
    '.paths[]? | select(.key.remote == $peer) | .selected_state // empty' | head -n 1
}

wait_agent_ready() {
  local namespace="$1"
  local log_path="$2"
  local public_agent=0
  if [[ "$nat_profile" == "one-sided" && "$namespace" == "$agent_b" ]]; then
    public_agent=1
  fi
  for _ in $(seq 1 90); do
    if ! kill -0 "$(if [[ "$namespace" == "$agent_a" ]]; then echo "$agent_a_pid"; else echo "$agent_b_pid"; fi)" 2>/dev/null; then
      echo "agent in ${namespace} exited before readiness" >&2
      return 1
    fi
    local status
    local metrics
    if status="$(agent_status "$namespace" 2>/dev/null)" \
      && metrics="$(agent_metrics "$namespace" 2>/dev/null)" \
      && jq -e --arg profile "$nat_profile" --arg public_agent "$public_agent" '
        .vpn_ip != null and
        .candidate_count >= 2 and
        .nat_classification != null and
        (if $profile == "symmetric" then
          .nat_classification.mapping_behavior == "address_and_port_dependent" and
          .nat_classification.strategy == "relay_preferred"
        elif $public_agent == "1" then
          .nat_classification.mapping_behavior == "no_nat"
        else
          .nat_classification.mapping_behavior == "endpoint_independent" and
          .nat_classification.filtering_behavior == "endpoint_independent"
        end)
      ' <<<"$status" >/dev/null \
      && jq -e '.peer_map_synced == true and .peer_map_peer_count >= 2' <<<"$metrics" >/dev/null; then
      printf '%s\n' "$status" >"${log_path}.status.json"
      printf '%s\n' "$metrics" >"${log_path}.metrics.json"
      agent_peers "$namespace" >"${log_path}.peers.json"
      return 0
    fi
    sleep 1
  done
  echo "agent in ${namespace} did not register, classify NAT, and sync peer map" >&2
  return 1
}

wait_control_plane_ready() {
  for _ in $(seq 1 90); do
    local metrics
    if metrics="$(curl --fail --silent --show-error --max-time 3 \
      --header "@${control_plane_operator_header_path}" \
      "http://${root_public_ip}:${control_plane_port}/v1/metrics" 2>/dev/null)" \
      && jq -e '.node_count >= 3 and .healthy_node_count >= 3 and .relay_candidate_count >= 1' \
        <<<"$metrics" >/dev/null; then
      printf '%s\n' "$metrics" >"${work_dir}/control-plane.metrics.json"
      return 0
    fi
    sleep 1
  done
  echo "control plane did not observe both agents and a healthy relay candidate" >&2
  return 1
}

wait_for_relay_path() {
  local peer_a="$1"
  local peer_b="$2"
  for _ in $(seq 1 90); do
    local state_a state_b metrics_a metrics_b
    state_a="$(path_state "$agent_a" "$peer_b" 2>/dev/null || true)"
    state_b="$(path_state "$agent_b" "$peer_a" 2>/dev/null || true)"
    if [[ "$state_a" == "RELAY" && "$state_b" == "RELAY" ]] \
      && metrics_a="$(agent_metrics "$agent_a" 2>/dev/null)" \
      && metrics_b="$(agent_metrics "$agent_b" 2>/dev/null)" \
      && jq -e '.relay_session_count >= 1 and .relay_forwarder_count >= 1 and .relay_admission_success_count >= 1' \
        <<<"$metrics_a" >/dev/null \
      && jq -e '.relay_session_count >= 1 and .relay_forwarder_count >= 1 and .relay_admission_success_count >= 1' \
        <<<"$metrics_b" >/dev/null; then
      printf '%s\n' "$metrics_a" >"${work_dir}/relay-a.metrics.json"
      printf '%s\n' "$metrics_b" >"${work_dir}/relay-b.metrics.json"
      return 0
    fi
    sleep 1
  done
  echo "both agents did not converge to an active relay path" >&2
  echo "--- agent A status ---" >&2
  agent_status "$agent_a" | jq . >&2 || true
  echo "--- agent B status ---" >&2
  agent_status "$agent_b" | jq . >&2 || true
  echo "--- agent A paths ---" >&2
  agent_paths "$agent_a" | jq . >&2 || true
  echo "--- agent B paths ---" >&2
  agent_paths "$agent_b" | jq . >&2 || true
  echo "--- agent A peers ---" >&2
  agent_peers "$agent_a" | jq . >&2 || true
  echo "--- agent B peers ---" >&2
  agent_peers "$agent_b" | jq . >&2 || true
  echo "--- relay status ---" >&2
  relay_status | jq . >&2 || true
  return 1
}

wait_for_direct_path() {
  local peer_a="$1"
  local peer_b="$2"
  local expected_state_a="${3:-DIRECT_NAT_TRAVERSAL}"
  local expected_state_b="${4:-DIRECT_NAT_TRAVERSAL}"
  for _ in $(seq 1 120); do
    local state_a state_b metrics_a metrics_b
    state_a="$(path_state "$agent_a" "$peer_b" 2>/dev/null || true)"
    state_b="$(path_state "$agent_b" "$peer_a" 2>/dev/null || true)"
    if [[ "$state_a" == "$expected_state_a" && "$state_b" == "$expected_state_b" ]] \
      && metrics_a="$(agent_metrics "$agent_a" 2>/dev/null)" \
      && metrics_b="$(agent_metrics "$agent_b" 2>/dev/null)" \
      && jq -e '.relay_session_count == 0 and .relay_forwarder_count == 0' <<<"$metrics_a" >/dev/null \
      && jq -e '.relay_session_count == 0 and .relay_forwarder_count == 0' <<<"$metrics_b" >/dev/null; then
      printf '%s\n' "$metrics_a" >"${work_dir}/direct-a.metrics.json"
      printf '%s\n' "$metrics_b" >"${work_dir}/direct-b.metrics.json"
      return 0
    fi
    sleep 1
  done
  echo "agents did not promote the expected direct paths (${expected_state_a}/${expected_state_b})" >&2
  echo "--- agent A status ---" >&2
  agent_status "$agent_a" | jq . >&2 || true
  echo "--- agent B status ---" >&2
  agent_status "$agent_b" | jq . >&2 || true
  echo "--- agent A paths ---" >&2
  agent_paths "$agent_a" | jq . >&2 || true
  echo "--- agent B paths ---" >&2
  agent_paths "$agent_b" | jq . >&2 || true
  echo "--- agent A metrics ---" >&2
  agent_metrics "$agent_a" | jq . >&2 || true
  echo "--- agent B metrics ---" >&2
  agent_metrics "$agent_b" | jq . >&2 || true
  return 1
}

require_command ip
require_command iptables
require_command sysctl
require_command curl
require_command jq
require_command ss
require_command ping
require_command wg
[[ "$(id -u)" == "0" ]] || {
  echo "agent NAT smoke must run as root because it creates namespaces, bridges, and WireGuard interfaces" >&2
  exit 1
}
[[ -x "$ipars_bin" ]] || { echo "ipars binary is not executable: $ipars_bin" >&2; exit 1; }
[[ -x "$iparsd_bin" ]] || { echo "iparsd binary is not executable: $iparsd_bin" >&2; exit 1; }

mkdir -p "$state_dir"
chmod 700 "$state_dir"
printf 'agent-nat-smoke-control-plane-operator-token-0123456789\n' >"$control_plane_operator_token_path"
chmod 600 "$control_plane_operator_token_path"
printf 'Authorization: Bearer %s\n' "$(<"$control_plane_operator_token_path")" >"$control_plane_operator_header_path"
chmod 600 "$control_plane_operator_header_path"
trap cleanup EXIT

port_base="$(pick_port_base)"
control_plane_port="$port_base"
signal_port="$((port_base + 1))"
stun_port="$((port_base + 2))"
stun_alternate_port="$((port_base + 3))"
stun_http_port="$((port_base + 4))"
relay_udp_port="$((port_base + 5))"
relay_http_port="$((port_base + 6))"
relay_agent_port="$((port_base + 7))"
public_ports=(
  "$control_plane_port"
  "$signal_port"
  "$stun_port"
  "$stun_alternate_port"
  "$stun_http_port"
  "$relay_udp_port"
  "$relay_http_port"
  "$relay_agent_port"
)

ip netns add "$nat_a"
if [[ "$nat_profile" != "one-sided" ]]; then
  ip netns add "$nat_b"
fi
ip netns add "$agent_a"
ip netns add "$agent_b"
ip link add "$bridge" type bridge
ip addr add "${root_public_ip}/24" dev "$bridge"
ip link set "$bridge" up

if [[ "$nat_profile" == "one-sided" ]]; then
  create_agent_nat_pair \
    "$nat_a" "$agent_a" "$nat_a_public_ip" "$nat_a_agent_ip" "$nat_a_gateway" \
    "$nat_a_root_public_if" "$nat_a_public_if" "$nat_a_agent_if" "$nat_a_private_if" \
    endpoint-independent
  create_public_agent "$agent_b" "$nat_b_public_ip" "$nat_b_root_public_if" "$nat_b_public_if"
else
  create_agent_nat_pair \
    "$nat_a" "$agent_a" "$nat_a_public_ip" "$nat_a_agent_ip" "$nat_a_gateway" \
    "$nat_a_root_public_if" "$nat_a_public_if" "$nat_a_agent_if" "$nat_a_private_if" \
    "$nat_profile"
  create_agent_nat_pair \
    "$nat_b" "$agent_b" "$nat_b_public_ip" "$nat_b_agent_ip" "$nat_b_gateway" \
    "$nat_b_root_public_if" "$nat_b_public_if" "$nat_b_agent_if" "$nat_b_private_if" \
    "$nat_profile"
fi

block_direct_peer \
  "$nat_a" "$nat_a_public_if" "$nat_b_public_ip" "$nat_a_agent_ip" \
  direct_rule_a direct_input_rule_a
if [[ "$nat_profile" != "one-sided" ]]; then
  block_direct_peer \
    "$nat_b" "$nat_b_public_if" "$nat_a_public_ip" "$nat_b_agent_ip" \
    direct_rule_b direct_input_rule_b
fi

echo "starting public bootstrap services on ${root_public_ip}"
if ! "$ipars_bin" init \
  --public-endpoint "${root_public_ip}:${relay_udp_port}" \
  --spawn-daemons \
  --daemon-ready-timeout-seconds 30 \
  --daemon-binary "$iparsd_bin" \
  --daemon-state-dir "$state_dir" \
  --control-plane-listen "${root_public_ip}:${control_plane_port}" \
  --signal-listen "${root_public_ip}:${signal_port}" \
  --stun-listen "${root_public_ip}:${stun_port}" \
  --stun-alternate-listen "${root_public_ip}:${stun_alternate_port}" \
  --stun-http-listen "${root_public_ip}:${stun_http_port}" \
  --relay-udp-listen "${root_public_ip}:${relay_udp_port}" \
  --relay-http-listen "${root_public_ip}:${relay_http_port}" \
  --relay-agent-listen "127.0.0.1:${relay_agent_port}" \
  --control-plane-operator-api-bearer-token-path "$control_plane_operator_token_path" \
  --allow-relay \
  --unlimited-uses \
  --allowed-route 100.64.0.0/10 \
  --token-ttl-seconds 3600 \
  >"$init_output" 2>"$init_error"; then
  exit 1
fi

jq -e '.services == ["control-plane", "signal", "stun", "relay", "relay-agent"] and (.daemon_processes | length == 5)' \
  "$init_output" >/dev/null
jq -c '.join_token' "$init_output" >"$join_token_path"
chmod 600 "$join_token_path"
for port in "$control_plane_port" "$signal_port" "$stun_http_port" "$relay_http_port" "$relay_agent_port"; do
  if [[ "$port" == "$relay_agent_port" ]]; then
    wait_root_health 127.0.0.1 "$port"
  else
    wait_root_health "$root_public_ip" "$port"
  fi
done

signal_pid="$(jq -r '.daemon_processes[] | select(.service == "signal") | .pid' "$init_output")"
if [[ "$nat_profile" != "symmetric" ]]; then
  stop_signal
  start_signal disabled "${state_dir}/logs/signal-disabled.log"
fi

agent_b_bind_ip="$nat_b_agent_ip"
if [[ "$nat_profile" == "one-sided" ]]; then
  agent_b_bind_ip="$nat_b_public_ip"
fi
start_agent "$agent_a" "$nat_a_agent_ip" "${work_dir}/agent-a.json" "${work_dir}/agent-a.log"
start_agent "$agent_b" "$agent_b_bind_ip" "${work_dir}/agent-b.json" "${work_dir}/agent-b.log"
wait_agent_health "$agent_a"
wait_agent_health "$agent_b"
wait_agent_ready "$agent_a" "${work_dir}/agent-a.log"
wait_agent_ready "$agent_b" "${work_dir}/agent-b.log"
wait_control_plane_ready

node_a="$(jq -r '.node_id' "${work_dir}/agent-a.log.status.json")"
node_b="$(jq -r '.node_id' "${work_dir}/agent-b.log.status.json")"
vpn_a="$(jq -r '.vpn_ip' "${work_dir}/agent-a.log.status.json")"
vpn_b="$(jq -r '.vpn_ip' "${work_dir}/agent-b.log.status.json")"
[[ "$node_a" != "null" && "$node_a" != "$node_b" ]] || { echo "agent node IDs were invalid or duplicated" >&2; exit 1; }
[[ "$vpn_a" != "null" && "$vpn_b" != "null" && "$vpn_a" != "$vpn_b" ]] || { echo "agent VPN IP allocation was invalid" >&2; exit 1; }

pin_agent_peer "$agent_a" "$node_b"
pin_agent_peer "$agent_b" "$node_a"
wait_for_relay_path "$node_a" "$node_b"
if [[ "${IPARS_AGENT_NAT_SMOKE_PAUSE_AFTER_RELAY_SECONDS:-0}" != "0" ]]; then
  sleep "${IPARS_AGENT_NAT_SMOKE_PAUSE_AFTER_RELAY_SECONDS}"
fi
ping_overlay "$agent_a" "$vpn_b"
ping_overlay "$agent_b" "$vpn_a"
agent_metrics "$agent_a" >"${work_dir}/relay-a.metrics.json"
agent_metrics "$agent_b" >"${work_dir}/relay-b.metrics.json"
for metrics_path in "${work_dir}/relay-a.metrics.json" "${work_dir}/relay-b.metrics.json"; do
  jq -e '([.relay_forwarders[]?.outbound_payload_bytes] | add // 0) > 0' "$metrics_path" >/dev/null
done

if [[ "$nat_profile" == "endpoint-independent" || "$nat_profile" == "one-sided" ]]; then
  stop_signal
  start_signal enabled "${state_dir}/logs/signal-enabled.log"
  unblock_direct_peer "$nat_a" direct_rule_a
  unblock_direct_peer "$nat_a" direct_input_rule_a
  if [[ "$nat_profile" != "one-sided" ]]; then
    unblock_direct_peer "$nat_b" direct_rule_b
    unblock_direct_peer "$nat_b" direct_input_rule_b
  fi
  if [[ "${IPARS_AGENT_NAT_SMOKE_PAUSE_BEFORE_DIRECT_SECONDS:-0}" != "0" ]]; then
    sleep "${IPARS_AGENT_NAT_SMOKE_PAUSE_BEFORE_DIRECT_SECONDS}"
  fi
  wait_for_direct_path "$node_a" "$node_b"
  if [[ "${IPARS_AGENT_NAT_SMOKE_PAUSE_AFTER_DIRECT_SECONDS:-0}" != "0" ]]; then
    sleep "${IPARS_AGENT_NAT_SMOKE_PAUSE_AFTER_DIRECT_SECONDS}"
  fi
  ping_overlay "$agent_a" "$vpn_b"
  ping_overlay "$agent_b" "$vpn_a"
  ip netns exec "$agent_a" wg show ipars0 endpoints | grep -F -- "${nat_b_public_ip}:51820" >/dev/null
  ip netns exec "$agent_b" wg show ipars0 endpoints | grep -F -- "${nat_a_public_ip}:51820" >/dev/null
  if [[ "$nat_profile" == "one-sided" ]]; then
    echo "agent NAT smoke passed: one-sided public-peer NAT Agents used encrypted relay fallback and promoted to direct NAT traversal"
  else
    echo "agent NAT smoke passed: endpoint-independent SNAT Agents used encrypted relay fallback and promoted to direct NAT traversal"
  fi
else
  sleep 5
  wait_for_relay_path "$node_a" "$node_b"
  ping_overlay "$agent_a" "$vpn_b"
  ping_overlay "$agent_b" "$vpn_a"
  echo "agent NAT smoke passed: symmetric SNAT Agents classified address-and-port-dependent NAT and stayed on encrypted relay fallback"
fi
