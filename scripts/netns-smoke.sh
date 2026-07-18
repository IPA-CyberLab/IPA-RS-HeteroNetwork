#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-}"
if [[ -z "${cargo_bin}" ]]; then
  cargo_bin="$(command -v cargo 2>/dev/null || true)"
fi
if [[ -z "${cargo_bin}" || ! -x "${cargo_bin}" ]]; then
  echo "CARGO must point to an executable cargo binary" >&2
  exit 1
fi
suffix="$$-$(date +%s%N)"
probe_netns="heteronetwork-smoke-probe-${suffix}"
probe_netns_path="/var/run/netns/${probe_netns}"
preflight_stderr="/tmp/heteronetwork-netns-smoke-preflight-${suffix}.stderr"
agent_preflight_log="/tmp/heteronetwork-netns-smoke-agent-preflight-${suffix}.log"
agent_preflight_state="/tmp/heteronetwork-netns-smoke-agent-${suffix}.json"
agent_preflight_token="/tmp/heteronetwork-netns-smoke-agent-${suffix}.join-token.json"
iparsd_bin="${HETERONETWORK_NETNS_SMOKE_IPARSD_BIN:-}"
ebpf_object_path="${HETERONETWORK_NETNS_SMOKE_EBPF_OBJECT_PATH:-}"

cleanup() {
  ip netns del "${probe_netns}" >/dev/null 2>&1 || true
  rm -f \
    "${preflight_stderr}" \
    "${agent_preflight_log}" \
    "${agent_preflight_state}" \
    "${agent_preflight_token}"
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
  env "${env_name}=1" "$cargo_bin" test --locked "$@" -- --nocapture
}

run_cargo_test_serial() {
  local name="$1"
  local env_name="$2"
  shift 2
  echo "running ${name} serially"
  env "${env_name}=1" "$cargo_bin" test --locked "$@" -- --nocapture --test-threads=1
}

prepare_iparsd() {
  if [[ -z "${iparsd_bin}" ]]; then
    "$cargo_bin" build --locked -p ipars-daemon
    iparsd_bin="${repo_root}/target/debug/iparsd"
  fi
  if [[ ! -x "${iparsd_bin}" ]]; then
    echo "HETERONETWORK_NETNS_SMOKE_IPARSD_BIN must point to an executable iparsd binary: ${iparsd_bin}" >&2
    exit 1
  fi
}

run_agent_runtime_preflight() {
  local name="$1"
  local wireguard_backend="$2"
  local route_backend="$3"
  rm -f "${agent_preflight_log}" "${agent_preflight_state}" "${agent_preflight_token}"
  if ip -n "${probe_netns}" link show dev heteronetwork0 >/dev/null 2>&1; then
    echo "runtime preflight namespace unexpectedly contains heteronetwork0 before ${name}" >&2
    exit 1
  fi
  if ! "${iparsd_bin}" agent \
    --preflight-only \
    --apply-peer-map \
    --linux-netns "${probe_netns}" \
    --wireguard-backend "${wireguard_backend}" \
    --route-backend "${route_backend}" \
    --disable-peer-probe \
    --state-path "${agent_preflight_state}" \
    --join-token-path "${agent_preflight_token}" \
    >"${agent_preflight_log}" 2>&1; then
    echo "${name} agent runtime preflight failed" >&2
    cat "${agent_preflight_log}" >&2
    exit 1
  fi
  if ! grep -Fq "runtime backend preflight passed" "${agent_preflight_log}"; then
    echo "${name} agent runtime preflight did not report backend success" >&2
    cat "${agent_preflight_log}" >&2
    exit 1
  fi
  if ! grep -Fq "agent runtime preflight-only check completed" "${agent_preflight_log}"; then
    echo "${name} agent runtime preflight did not report clean completion" >&2
    cat "${agent_preflight_log}" >&2
    exit 1
  fi
  if [[ -e "${agent_preflight_state}" || -e "${agent_preflight_token}" ]]; then
    echo "${name} agent runtime preflight created state or token material" >&2
    exit 1
  fi
  if ip -n "${probe_netns}" link show dev heteronetwork0 >/dev/null 2>&1; then
    echo "${name} agent runtime preflight created WireGuard interface heteronetwork0" >&2
    exit 1
  fi
}

run_agent_runtime_preflights() {
  trap cleanup EXIT
  ip netns add "${probe_netns}"
  ip -n "${probe_netns}" link set lo up
  run_agent_runtime_preflight kernel-netlink kernel-netlink kernel-netlink
  if command -v wg >/dev/null 2>&1; then
    run_agent_runtime_preflight command command command
  else
    echo "skipping command backend agent preflight because 'wg' is not available"
  fi
  if [[ -c /dev/net/tun ]]; then
    run_agent_runtime_preflight boringtun userspace-boringtun command
  else
    echo "skipping BoringTun backend agent preflight because /dev/net/tun is not available"
  fi
  cleanup
  trap - EXIT
}

run_ebpf_attach_smoke() {
  if [[ -z "${ebpf_object_path}" ]]; then
    echo "skipping eBPF attach smoke because HETERONETWORK_NETNS_SMOKE_EBPF_OBJECT_PATH is unset"
    return
  fi
  echo "running eBPF attach and ring-buffer event smoke"
  env \
    HETERONETWORK_RUN_EBPF_ATTACH_TESTS=1 \
    HETERONETWORK_EBPF_OBJECT_PATH="${ebpf_object_path}" \
    "$cargo_bin" test --locked -p ipars-daemon \
      tests::ebpf_ringbuf_privileged_attach_reads_sendto_event -- \
      --exact --nocapture
  env \
    HETERONETWORK_RUN_EBPF_ATTACH_TESTS=1 \
    HETERONETWORK_EBPF_OBJECT_PATH="${ebpf_object_path}" \
    "$cargo_bin" test --locked -p ipars-daemon \
      tests::ebpf_ringbuf_privileged_cgroup_hooks_read_connect_and_sendmsg_events -- \
      --exact --nocapture
}

preflight_netns

cd "$repo_root"
prepare_iparsd
run_agent_runtime_preflights
run_ebpf_attach_smoke

run_cargo_test route-netns HETERONETWORK_RUN_NETNS_TESTS \
  -p ipars-route-manager --test netns_route_backend

run_cargo_test peer-probe-netns HETERONETWORK_RUN_PEER_PROBE_NETNS_TESTS \
  -p ipars-agent --test netns_peer_probe

if [[ "${HETERONETWORK_NETNS_SMOKE_SKIP_WIREGUARD:-0}" == "1" ]]; then
  echo "skipping WireGuard netns smoke because HETERONETWORK_NETNS_SMOKE_SKIP_WIREGUARD=1"
elif command -v wg >/dev/null 2>&1; then
  run_cargo_test wireguard-netns HETERONETWORK_RUN_WG_NETNS_TESTS \
    -p ipars-agent --test netns_wireguard_backend
else
  echo "skipping WireGuard netns smoke because 'wg' is not available"
fi

run_cargo_test boringtun-netns HETERONETWORK_RUN_BORINGTUN_NETNS_TESTS \
  -p ipars-agent --test netns_wireguard_backend

run_cargo_test_serial hole-punch-netns HETERONETWORK_RUN_HOLE_PUNCH_NETNS_TESTS \
  -p ipars-agent --test netns_hole_punch

run_cargo_test relay-fallback-netns HETERONETWORK_RUN_RELAY_NETNS_TESTS \
  -p ipars-agent --test netns_relay_fallback

echo "Network namespace smoke checks completed"
