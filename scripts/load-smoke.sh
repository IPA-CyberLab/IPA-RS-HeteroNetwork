#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-/home/coder/.cargo/bin/cargo}"
output_dir="${HETERONETWORK_LOAD_SMOKE_OUTPUT_DIR:-/tmp}"
daemon_bin="${HETERONETWORK_LOAD_SMOKE_DAEMON_BIN:-}"

cd "$repo_root"
mkdir -p "$output_dir"

run_load() {
  local name="$1"
  local expected_transport="$2"
  local expected_scenario="$3"
  local report_path="${output_dir}/heteronetwork-load-${name}.json"
  shift 3
  "$cargo_bin" run --locked -p ipars-load --quiet -- "$@" >"$report_path"
  if ! grep -Fq "\"transport\": \"${expected_transport}\"" "$report_path"; then
    echo "load smoke report ${report_path} did not record transport ${expected_transport}" >&2
    cat "$report_path" >&2
    exit 1
  fi
  if ! grep -Fq "\"scenario\": \"${expected_scenario}\"" "$report_path"; then
    echo "load smoke report ${report_path} did not record scenario ${expected_scenario}" >&2
    cat "$report_path" >&2
    exit 1
  fi
}

run_load in-memory-three in_memory three --scenario three
run_load in-memory-ten in_memory ten --scenario ten
run_load in-memory-thousand in_memory thousand --scenario thousand
run_load http-three http three --transport http --scenario three
run_load relay-udp-three relay_udp three --transport relay-udp --scenario three \
  --relay-packets-per-session 2 \
  --relay-payload-bytes 128

if [[ "${HETERONETWORK_LOAD_SMOKE_BUILD_DAEMON:-0}" == "1" ]]; then
  "$cargo_bin" build --locked -p ipars-daemon
  daemon_bin="${repo_root}/target/debug/iparsd"
fi

if [[ -n "$daemon_bin" ]]; then
  if [[ ! -x "$daemon_bin" ]]; then
    echo "HETERONETWORK_LOAD_SMOKE_DAEMON_BIN must point to an executable iparsd binary: ${daemon_bin}" >&2
    exit 1
  fi
  run_load daemon-three daemon three \
    --transport daemon \
    --scenario three \
    --iparsd-bin "$daemon_bin" \
    --daemon-agent-processes "${HETERONETWORK_LOAD_SMOKE_DAEMON_AGENTS:-3}" \
    --daemon-control-plane-processes "${HETERONETWORK_LOAD_SMOKE_DAEMON_CONTROL_PLANES:-2}" \
    --daemon-agent-readiness-timeout-seconds "${HETERONETWORK_LOAD_SMOKE_DAEMON_AGENT_TIMEOUT_SECONDS:-30}"

  postgres_database_url="${HETERONETWORK_LOAD_SMOKE_POSTGRES_DATABASE_URL:-}"
  if [[ -n "$postgres_database_url" ]]; then
    postgres_report="${output_dir}/heteronetwork-load-daemon-postgres-three.json"
    HETERONETWORK_LOAD_DAEMON_DATABASE_URL="$postgres_database_url" run_load daemon-postgres-three daemon three \
      --transport daemon \
      --scenario three \
      --iparsd-bin "$daemon_bin" \
      --daemon-agent-processes "${HETERONETWORK_LOAD_SMOKE_DAEMON_AGENTS:-3}" \
      --daemon-control-plane-processes "${HETERONETWORK_LOAD_SMOKE_DAEMON_CONTROL_PLANES:-2}" \
      --daemon-agent-readiness-timeout-seconds "${HETERONETWORK_LOAD_SMOKE_DAEMON_AGENT_TIMEOUT_SECONDS:-30}"
    if ! grep -Fq '"daemon_database_backend": "postgres"' "$postgres_report"; then
      echo "load smoke report ${postgres_report} did not record PostgreSQL daemon backend" >&2
      cat "$postgres_report" >&2
      exit 1
    fi
  fi
fi

echo "HeteroNetwork load smoke reports written to ${output_dir}/heteronetwork-load-*.json"
