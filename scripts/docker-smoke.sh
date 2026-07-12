#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-/home/coder/.cargo/bin/cargo}"
suffix="$$-$(date +%s%N)"
docker_stderr="/tmp/ipars-docker-smoke-docker-${suffix}.stderr"
compose_stderr="/tmp/ipars-docker-smoke-compose-${suffix}.stderr"

cleanup() {
  rm -f "${docker_stderr}" "${compose_stderr}"
}

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "required command '${command_name}' is not available in PATH" >&2
    exit 1
  fi
}

preflight_docker() {
  require_command docker
  trap cleanup EXIT

  if ! docker version >"${docker_stderr}" 2>&1; then
    echo "Docker daemon is not reachable; start Docker or configure DOCKER_HOST" >&2
    cat "${docker_stderr}" >&2
    exit 1
  fi

  if ! docker compose version >"${compose_stderr}" 2>&1; then
    echo "Docker Compose is not available via 'docker compose'" >&2
    cat "${compose_stderr}" >&2
    exit 1
  fi
}

preflight_docker

cd "$repo_root"

env \
  DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}" \
  COMPOSE_DOCKER_CLI_BUILD="${COMPOSE_DOCKER_CLI_BUILD:-1}" \
  IPARS_RUN_DOCKER_COMPOSE_SMOKE=1 \
  "$cargo_bin" test --locked -p ipars-cli --test docker_compose_smoke -- --nocapture

echo "Docker Compose smoke checks completed"
