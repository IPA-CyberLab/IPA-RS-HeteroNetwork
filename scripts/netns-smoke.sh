#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-/home/coder/.cargo/bin/cargo}"
suffix="$$-$(date +%s%N)"
probe_netns="ipars-smoke-probe-${suffix}"
preflight_stderr="/tmp/ipars-netns-smoke-preflight-${suffix}.stderr"

cleanup() {
  ip netns del "${probe_netns}" >/dev/null 2>&1 || true
  rm -f "${preflight_stderr}"
}

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command '${command_name}' is not available in PATH" >&2
    exit 1
  fi
}

preflight_netns() {
  require_command ip
  require_command iptables
  require_command sysctl
  trap cleanup EXIT
  if ! ip netns add "${probe_netns}" >"${preflight_stderr}" 2>&1; then
    echo "failed to create a temporary network namespace; run with CAP_SYS_ADMIN and CAP_NET_ADMIN" >&2
    cat "${preflight_stderr}" >&2
    exit 1
  fi
  ip -n "${probe_netns}" link set lo up
  cleanup
  trap - EXIT
}

run_cargo_test() {
  local name="$1"
  local env_name="$2"
  shift 2
  echo "running ${name}"
  env "${env_name}=1" "$cargo_bin" test "$@" -- --nocapture
}

preflight_netns

cd "$repo_root"

run_cargo_test route-netns IPARS_RUN_NETNS_TESTS \
  -p ipars-route-manager --test netns_route_backend

if [[ "${IPARS_NETNS_SMOKE_SKIP_WIREGUARD:-0}" == "1" ]]; then
  echo "skipping WireGuard netns smoke because IPARS_NETNS_SMOKE_SKIP_WIREGUARD=1"
elif command -v wg >/dev/null 2>&1; then
  run_cargo_test wireguard-netns IPARS_RUN_WG_NETNS_TESTS \
    -p ipars-agent --test netns_wireguard_backend
else
  echo "skipping WireGuard netns smoke because 'wg' is not available"
fi

run_cargo_test hole-punch-netns IPARS_RUN_HOLE_PUNCH_NETNS_TESTS \
  -p ipars-agent --test netns_hole_punch

run_cargo_test relay-fallback-netns IPARS_RUN_RELAY_NETNS_TESTS \
  -p ipars-agent --test netns_relay_fallback

echo "Network namespace smoke checks completed"
