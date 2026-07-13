#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker_bin="${DOCKER:-docker}"
dockerd_rootless_bin="${DOCKERD_ROOTLESS:-dockerd-rootless.sh}"
suffix="$$-$(date +%s%N)"
tmp_dir=""
runtime_dir=""
docker_socket=""
daemon_pid=""
daemon_pid_file=""
project_name="ipars-rootless-${suffix}"
override_path=""

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
    DOCKER_HOST="unix://${docker_socket}" \
      "$docker_bin" compose \
        -p "$project_name" \
        -f "$repo_root/docker/compose.yaml" \
        -f "$repo_root/docker/compose.rootless.yaml" \
        -f "$repo_root/docker/compose.rootless-dataplane.yaml" \
        -f "$override_path" \
        down --remove-orphans >/dev/null 2>&1 || true
  fi

  if [[ -n "$daemon_pid_file" && -f "$daemon_pid_file" ]]; then
    kill "$(cat "$daemon_pid_file")" >/dev/null 2>&1 || true
  fi
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$tmp_dir" ]]; then
    rm -rf "$tmp_dir"
  fi
  exit "$status"
}

require_command "$docker_bin"
require_command "$dockerd_rootless_bin"
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
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipars-rootless-smoke.XXXXXX")"
runtime_dir="$tmp_dir/runtime"
mkdir -m 700 "$runtime_dir"
docker_socket="$runtime_dir/docker.sock"
daemon_pid_file="$tmp_dir/dockerd.pid"

(
  export XDG_RUNTIME_DIR="$runtime_dir"
  export DOCKER_HOST="unix://${docker_socket}"
  exec "$dockerd_rootless_bin" \
    --host="$DOCKER_HOST" \
    --data-root="$tmp_dir/data" \
    --exec-root="$tmp_dir/exec" \
    --pidfile="$daemon_pid_file" \
    --storage-driver=fuse-overlayfs \
    --iptables=false \
    --bridge=none \
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
grep -F 'IPARS_AGENT_RUNTIME_BACKEND=linux-command' "$rendered_config" >/dev/null
grep -F 'IPARS_AGENT_WIREGUARD_BACKEND=userspace-boringtun' "$rendered_config" >/dev/null
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
