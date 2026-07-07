#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-/home/coder/.cargo/bin/cargo}"
suffix="$$-$(date +%s%N)"
probe_netns="ipars-smoke-probe-${suffix}"
probe_netns_path="/var/run/netns/${probe_netns}"
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

probe_netns_is_listed() {
  ip netns list | awk '{print $1}' | grep -Fx -- "${probe_netns}" >/dev/null
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
  if ! probe_netns_is_listed; then
    echo "temporary network namespace ${probe_netns} was created but is missing from 'ip netns list'" >&2
    exit 1
  fi
  if [[ ! -e "${probe_netns_path}" ]]; then
    echo "temporary network namespace entry ${probe_netns_path} was not created" >&2
    exit 1
  fi
  if [[ -L "${probe_netns_path}" ]]; then
    echo "temporary network namespace entry ${probe_netns_path} must not be a symlink" >&2
    exit 1
  fi
  ip -n "${probe_netns}" link set lo up
  cleanup
  if probe_netns_is_listed; then
    echo "temporary network namespace ${probe_netns} remained listed after cleanup" >&2
    exit 1
  fi
  if [[ -e "${probe_netns_path}" ]]; then
    echo "temporary network namespace entry ${probe_netns_path} remained after cleanup" >&2
    exit 1
  fi
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
