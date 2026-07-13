#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-cargo}"
ipars_bin="${IPARS_INIT_SMOKE_IPARS_BIN:-}"
iparsd_bin="${IPARS_INIT_SMOKE_IPARSD_BIN:-}"
ready_timeout="${IPARS_INIT_SMOKE_READY_TIMEOUT_SECONDS:-20}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipars-init-spawn-smoke.XXXXXX")"
state_dir="${work_dir}/state"
output_path="${work_dir}/init.json"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command '${command_name}' is not available in PATH" >&2
    exit 1
  fi
}

port_in_use() {
  local port="$1"
  ! ss -H -ltnu 2>/dev/null | awk -v port="$port" '$5 ~ (":" port "$") { found = 1 } END { exit found }'
}

pick_port_base() {
  local base
  local port
  local available
  for _ in $(seq 1 50); do
    base=$((20000 + (RANDOM % 20000)))
    available=1
    for port in $(seq "$base" "$((base + 6))"); do
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
  echo "could not find seven consecutive unused local ports" >&2
  return 1
}

stop_spawned_daemons() {
  [[ -s "$output_path" ]] || return 0
  local pid
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    kill "$pid" 2>/dev/null || true
  done < <(jq -r '.daemon_processes[]?.pid' "$output_path" 2>/dev/null || true)
  sleep 0.2
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    kill -9 "$pid" 2>/dev/null || true
  done < <(jq -r '.daemon_processes[]?.pid' "$output_path" 2>/dev/null || true)
}

dump_failure() {
  if [[ -s "$output_path" ]]; then
    echo "ipars init output:" >&2
    jq . "$output_path" >&2 || cat "$output_path" >&2
  fi
  if [[ -d "${state_dir}/logs" ]]; then
    local log
    for log in "${state_dir}/logs"/*.log; do
      [[ -f "$log" ]] || continue
      echo "--- ${log} ---" >&2
      tail -n 80 "$log" >&2 || true
    done
  fi
}

cleanup() {
  local status=$?
  trap - EXIT
  stop_spawned_daemons
  if [[ "$status" -ne 0 ]]; then
    dump_failure
  fi
  rm -rf "$work_dir"
  exit "$status"
}

require_command curl
require_command jq
require_command ss
require_command stat
trap cleanup EXIT

cd "$repo_root"
if [[ -z "$ipars_bin" || -z "$iparsd_bin" ]]; then
  "$cargo_bin" build --locked -p ipars-cli -p ipars-daemon
  ipars_bin="${ipars_bin:-${repo_root}/target/debug/ipars}"
  iparsd_bin="${iparsd_bin:-${repo_root}/target/debug/iparsd}"
fi
[[ -x "$ipars_bin" ]] || { echo "ipars binary is not executable: $ipars_bin" >&2; exit 1; }
[[ -x "$iparsd_bin" ]] || { echo "iparsd binary is not executable: $iparsd_bin" >&2; exit 1; }

base="$(pick_port_base)"
control_plane_port="$base"
signal_port="$((base + 1))"
stun_port="$((base + 2))"
stun_http_port="$((base + 3))"
relay_udp_port="$((base + 4))"
relay_http_port="$((base + 5))"
relay_agent_port="$((base + 6))"

"$ipars_bin" init \
  --public-endpoint "127.0.0.1:${relay_udp_port}" \
  --spawn-daemons \
  --daemon-ready-timeout-seconds "$ready_timeout" \
  --daemon-binary "$iparsd_bin" \
  --daemon-state-dir "$state_dir" \
  --control-plane-listen "127.0.0.1:${control_plane_port}" \
  --signal-listen "127.0.0.1:${signal_port}" \
  --stun-listen "127.0.0.1:${stun_port}" \
  --stun-http-listen "127.0.0.1:${stun_http_port}" \
  --relay-udp-listen "127.0.0.1:${relay_udp_port}" \
  --relay-http-listen "127.0.0.1:${relay_http_port}" \
  --relay-agent-listen "127.0.0.1:${relay_agent_port}" \
  --allow-relay \
  --unlimited-uses \
  --allowed-route 100.64.0.0/10 >"$output_path"

jq -e '
  .services == ["control-plane", "signal", "stun", "relay", "relay-agent"] and
  (.daemon_processes | length == 5) and
  ([.daemon_processes[].service] == ["control-plane", "signal", "stun", "relay", "relay-agent"])
' "$output_path" >/dev/null

for port in "$control_plane_port" "$signal_port" "$stun_http_port" "$relay_http_port" "$relay_agent_port"; do
  curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${port}/healthz" >/dev/null
done

while IFS= read -r pid; do
  [[ "$pid" =~ ^[0-9]+$ ]] || { echo "invalid daemon PID in init output" >&2; exit 1; }
  kill -0 "$pid" 2>/dev/null || { echo "daemon PID ${pid} is not alive after readiness" >&2; exit 1; }
done < <(jq -r '.daemon_processes[].pid' "$output_path")

[[ "$(stat -c '%a' "$state_dir")" == "700" ]] || { echo "daemon state directory is not owner-only" >&2; exit 1; }
[[ "$(stat -c '%a' "${state_dir}/logs")" == "700" ]] || { echo "daemon log directory is not owner-only" >&2; exit 1; }
for secret in relay-admission.token relay-agent.json relay-agent.join-token; do
  [[ "$(stat -c '%a' "${state_dir}/${secret}")" == "600" ]] || {
    echo "${secret} is not owner-only" >&2
    exit 1
  }
done

admission_token="$(tr -d '\r\n' < "${state_dir}/relay-admission.token")"
[[ -n "$admission_token" ]] || { echo "relay admission token was empty" >&2; exit 1; }
if grep -Fq "$admission_token" "$output_path"; then
  echo "relay admission token leaked into init JSON output" >&2
  exit 1
fi

echo "ipars init spawn smoke passed: five daemons became healthy and owner-only bootstrap state was created"
