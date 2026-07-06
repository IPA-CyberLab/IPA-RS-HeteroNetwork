#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-/home/coder/.cargo/bin/cargo}"
output_dir="${IPARS_LOAD_SMOKE_OUTPUT_DIR:-/tmp}"

run_load() {
  local name="$1"
  shift
  "$cargo_bin" run -p ipars-load --quiet -- "$@" >"${output_dir}/ipars-load-${name}.json"
}

run_load in-memory-three --scenario three
run_load in-memory-ten --scenario ten
run_load in-memory-thousand --scenario thousand
run_load http-three --transport http --scenario three
run_load relay-udp-three --transport relay-udp --scenario three \
  --relay-packets-per-session 2 \
  --relay-payload-bytes 128

if [[ -n "${IPARS_LOAD_SMOKE_DAEMON_BIN:-}" ]]; then
  run_load daemon-three \
    --transport daemon \
    --scenario three \
    --iparsd-bin "${IPARS_LOAD_SMOKE_DAEMON_BIN}" \
    --daemon-agent-processes "${IPARS_LOAD_SMOKE_DAEMON_AGENTS:-3}" \
    --daemon-control-plane-processes "${IPARS_LOAD_SMOKE_DAEMON_CONTROL_PLANES:-2}" \
    --daemon-agent-readiness-timeout-seconds "${IPARS_LOAD_SMOKE_DAEMON_AGENT_TIMEOUT_SECONDS:-30}"
fi

echo "ipars-load smoke reports written to ${output_dir}/ipars-load-*.json"
