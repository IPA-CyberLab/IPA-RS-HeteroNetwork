#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-cargo}"
docker_bin="${DOCKER:-docker}"
dockerd_bin="${DOCKERD:-dockerd}"
containerd_bin="${CONTAINERD:-containerd}"
suffix="$$-$(date +%s%N)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-docker-multi-engine.XXXXXX")"
engine_a_port="$((25000 + ($$ % 1000)))"
engine_b_port="$((engine_a_port + 1))"
engine_a_data="$tmp_dir/data-a"
engine_b_data="$tmp_dir/data-b"
engine_a_exec="$tmp_dir/exec-a"
engine_b_exec="$tmp_dir/exec-b"
engine_a_containerd_root="$tmp_dir/containerd-root-a"
engine_b_containerd_root="$tmp_dir/containerd-root-b"
engine_a_containerd_state="$tmp_dir/containerd-state-a"
engine_b_containerd_state="$tmp_dir/containerd-state-b"
engine_a_pidfile="$tmp_dir/dockerd-a.pid"
engine_b_pidfile="$tmp_dir/dockerd-b.pid"
engine_a_containerd="$tmp_dir/containerd-a.sock"
engine_b_containerd="$tmp_dir/containerd-b.sock"
engine_a_containerd_pidfile="$tmp_dir/containerd-a.pid"
engine_b_containerd_pidfile="$tmp_dir/containerd-b.pid"
engine_a_containerd_pid=""
engine_b_containerd_pid=""
engine_a_containerd_launcher_pid=""
engine_b_containerd_launcher_pid=""
engine_a_containerd_log="$tmp_dir/containerd-a.log"
engine_b_containerd_log="$tmp_dir/containerd-b.log"
engine_a_log="$tmp_dir/dockerd-a.log"
engine_b_log="$tmp_dir/dockerd-b.log"
test_log="$tmp_dir/test.log"
test_exit="$tmp_dir/test.exit"
ready_file="$tmp_dir/ready"
release_file="$tmp_dir/release"
engine_a_network="heteronetwork-engine-a-${suffix}"
engine_b_network="heteronetwork-engine-b-${suffix}"

if (( EUID == 0 )); then
  root_prefix=()
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  root_prefix=(sudo -n)
else
  echo "running two Docker daemons requires root or passwordless sudo" >&2
  exit 1
fi

run_root() {
  "${root_prefix[@]}" "$@"
}

cleanup() {
  set +e
  if [[ -f "$engine_a_pidfile" ]]; then
    run_root kill "$(run_root cat "$engine_a_pidfile")" >/dev/null 2>&1 || true
  fi
  if [[ -f "$engine_b_pidfile" ]]; then
    run_root kill "$(run_root cat "$engine_b_pidfile")" >/dev/null 2>&1 || true
  fi
  if [[ -n "$engine_a_containerd_pid" ]]; then
    run_root kill "$engine_a_containerd_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$engine_b_containerd_pid" ]]; then
    run_root kill "$engine_b_containerd_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$engine_a_containerd_launcher_pid" ]]; then
    kill "$engine_a_containerd_launcher_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$engine_b_containerd_launcher_pid" ]]; then
    kill "$engine_b_containerd_launcher_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${test_pid:-}" ]]; then
    kill "$test_pid" >/dev/null 2>&1 || true
  fi
  run_root rm -rf "$tmp_dir"
}
trap cleanup EXIT

require_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "required command '$name' is not available in PATH" >&2
    exit 1
  fi
}

require_command "$docker_bin"
require_command "$dockerd_bin"
require_command "$containerd_bin"
require_command curl

cd "$repo_root"
"$cargo_bin" test --locked -p ipars-daemon --all-features \
  docker_api_discovery_supports_multiple_real_docker_engines_and_churn --no-run

wait_for_containerd() {
  local socket_path="$1"
  local pid="$2"
  local log_path="$3"
  for _ in $(seq 1 60); do
    if [[ -S "$socket_path" ]]; then
      return 0
    fi
    if ! run_root kill -0 "$pid" >/dev/null 2>&1; then
      echo "containerd for ${socket_path} exited before becoming ready" >&2
      cat "$log_path" >&2 || true
      exit 1
    fi
    sleep 1
  done
  echo "containerd socket ${socket_path} did not become ready" >&2
  cat "$log_path" >&2 || true
  exit 1
}

start_engine() {
  local name="$1"
  local port="$2"
  local data_root="$3"
  local exec_root="$4"
  local pidfile="$5"
  local containerd_socket="$6"
  local containerd_pidfile="$7"
  local containerd_root="$8"
  local containerd_state="$9"
  local containerd_log_path="${10}"
  local log_path="${11}"
  run_root mkdir -p "$data_root" "$exec_root" "$containerd_root" "$containerd_state"
  run_root sh -c 'printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
    heteronetwork-containerd "$containerd_pidfile" "$containerd_bin" \
    --config=/dev/null \
    --address="$containerd_socket" \
    --root="$containerd_root" \
    --state="$containerd_state" \
    --log-level=error \
    >"$containerd_log_path" 2>&1 &
  local containerd_launcher_pid=$!
  if [[ "$name" == "a" ]]; then
    engine_a_containerd_launcher_pid="$containerd_launcher_pid"
  else
    engine_b_containerd_launcher_pid="$containerd_launcher_pid"
  fi
  local containerd_pid=""
  for _ in $(seq 1 30); do
    if [[ -f "$containerd_pidfile" ]]; then
      containerd_pid="$(run_root cat "$containerd_pidfile")"
      break
    fi
    sleep 1
  done
  if [[ -z "$containerd_pid" ]]; then
    echo "containerd for ${containerd_socket} did not publish its pid" >&2
    cat "$containerd_log_path" >&2 || true
    exit 1
  fi
  if [[ "$name" == "a" ]]; then
    engine_a_containerd_pid="$containerd_pid"
  else
    engine_b_containerd_pid="$containerd_pid"
  fi
  wait_for_containerd "$containerd_socket" "$containerd_pid" "$containerd_log_path"
  run_root "$dockerd_bin" \
    --host="tcp://127.0.0.1:${port}" \
    --tls=false \
    --data-root="$data_root" \
    --exec-root="$exec_root" \
    --pidfile="$pidfile" \
    --containerd="$containerd_socket" \
    --containerd-namespace="ipars-${name}-${suffix}" \
    --containerd-plugins-namespace="ipars-${name}-plugins-${suffix}" \
    --storage-driver=vfs \
    --bridge=none \
    --iptables=false \
    --ip6tables=false \
    --ip-forward=false \
    --ip-masq=false \
    --userland-proxy=false \
    --log-level=error \
    >"$log_path" 2>&1 &
}

wait_for_engine() {
  local port="$1"
  local log_path="$2"
  for _ in $(seq 1 90); do
    if curl --fail --silent --show-error --max-time 1 "http://127.0.0.1:${port}/_ping" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Docker Engine on port ${port} did not become ready" >&2
  cat "$log_path" >&2 || true
  exit 1
}

docker_engine() {
  local port="$1"
  shift
  env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    "$docker_bin" --host "tcp://127.0.0.1:${port}" "$@"
}

start_engine a "$engine_a_port" "$engine_a_data" "$engine_a_exec" "$engine_a_pidfile" "$engine_a_containerd" "$engine_a_containerd_pidfile" "$engine_a_containerd_root" "$engine_a_containerd_state" "$engine_a_containerd_log" "$engine_a_log"
start_engine b "$engine_b_port" "$engine_b_data" "$engine_b_exec" "$engine_b_pidfile" "$engine_b_containerd" "$engine_b_containerd_pidfile" "$engine_b_containerd_root" "$engine_b_containerd_state" "$engine_b_containerd_log" "$engine_b_log"
wait_for_engine "$engine_a_port" "$engine_a_log"
wait_for_engine "$engine_b_port" "$engine_b_log"

docker_engine "$engine_a_port" network create --driver bridge --subnet 172.31.10.0/24 "$engine_a_network" >/dev/null
docker_engine "$engine_b_port" network create --driver bridge --subnet 172.31.20.0/24 "$engine_b_network" >/dev/null

(
  set +e
  env \
    HETERONETWORK_RUN_REAL_DOCKER_MULTI_ENGINE_SMOKE=1 \
    HETERONETWORK_DOCKER_MULTI_ENGINE_URL_A="http://127.0.0.1:${engine_a_port}" \
    HETERONETWORK_DOCKER_MULTI_ENGINE_URL_B="http://127.0.0.1:${engine_b_port}" \
    HETERONETWORK_DOCKER_MULTI_ENGINE_NETWORK_A="$engine_a_network" \
    HETERONETWORK_DOCKER_MULTI_ENGINE_NETWORK_B="$engine_b_network" \
    HETERONETWORK_DOCKER_MULTI_ENGINE_FIRST_CIDR_A=172.31.10.0/24 \
    HETERONETWORK_DOCKER_MULTI_ENGINE_FIRST_CIDR_B=172.31.20.0/24 \
    HETERONETWORK_DOCKER_MULTI_ENGINE_SECOND_CIDR_A=172.31.12.0/24 \
    HETERONETWORK_DOCKER_MULTI_ENGINE_SECOND_CIDR_B=172.31.22.0/24 \
    HETERONETWORK_DOCKER_MULTI_ENGINE_READY_FILE="$ready_file" \
    HETERONETWORK_DOCKER_MULTI_ENGINE_RELEASE_FILE="$release_file" \
    "$cargo_bin" test --locked -p ipars-daemon --all-features \
      docker_api_discovery_supports_multiple_real_docker_engines_and_churn -- --nocapture \
      >"$test_log" 2>&1
  status=$?
  printf '%s\n' "$status" >"$test_exit"
  exit "$status"
) &
test_pid=$!

for _ in $(seq 1 90); do
  if [[ -f "$ready_file" ]]; then
    break
  fi
  if [[ -f "$test_exit" ]]; then
    cat "$test_log" >&2
    exit "$(cat "$test_exit")"
  fi
  sleep 1
done
if [[ ! -f "$ready_file" ]]; then
  echo "real Docker Engine discovery test did not reach its churn barrier" >&2
  cat "$test_log" >&2 || true
  exit 1
fi

docker_engine "$engine_a_port" network rm "$engine_a_network" >/dev/null
docker_engine "$engine_b_port" network rm "$engine_b_network" >/dev/null
docker_engine "$engine_a_port" network create --driver bridge --subnet 172.31.12.0/24 "$engine_a_network" >/dev/null
docker_engine "$engine_b_port" network create --driver bridge --subnet 172.31.22.0/24 "$engine_b_network" >/dev/null
touch "$release_file"

if ! wait "$test_pid"; then
  cat "$test_log" >&2
  exit 1
fi
cat "$test_log"
echo "real multi-Docker-Engine discovery and churn smoke passed"
