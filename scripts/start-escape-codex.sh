#!/usr/bin/env bash
set -euo pipefail

readonly PERSISTENT_HOME="${PERSISTENT_HOME:-/root}"
readonly CODEX_STATE_HOME="${CODEX_STATE_HOME:-${PERSISTENT_HOME}/.codex}"
readonly SYOUYU_MOUNT="${SYOUYU_MOUNT:-${PERSISTENT_HOME}/syouyu}"
readonly CODEX_S3_STATE_DIR="${CODEX_S3_STATE_DIR:-${SYOUYU_MOUNT}/codex-state}"
readonly CODEX_WORKSPACE="${CODEX_WORKSPACE:-${SYOUYU_MOUNT}/workspace}"
readonly CODEX_SESSION_NAME="${CODEX_SESSION_NAME:-codex}"
readonly SYNC_SESSION_NAME="${SYNC_SESSION_NAME:-codex-s3-sync}"
readonly LOCAL_BIN_DIRECTORY="${PERSISTENT_HOME}/.local/bin"
readonly LOCAL_LIBEXEC_DIRECTORY="${PERSISTENT_HOME}/.local/libexec"
readonly S3_BIN_DIRECTORY="${SYOUYU_MOUNT}/bin"
readonly STATE_HELPER="${LOCAL_BIN_DIRECTORY}/codex-s3-state"
readonly CODEX_BINARY="${LOCAL_LIBEXEC_DIRECTORY}/codex-bin"
readonly CODE_MODE_HOST="${LOCAL_LIBEXEC_DIRECTORY}/codex-code-mode-host"

fail() {
  printf 'start-escape-codex: %s\n' "$*" >&2
  exit 1
}

install_runtime_packages() {
  local missing=false command

  for command in git sqlite3 tmux; do
    if ! command -v "${command}" >/dev/null 2>&1; then
      missing=true
    fi
  done
  [[ ${missing} == true ]] || return 0
  ((EUID == 0)) || fail "root is required to install runtime packages"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates git sqlite3 tmux
}

install_persistent_tools() {
  install -d -m 0700 \
    "${LOCAL_BIN_DIRECTORY}" \
    "${LOCAL_LIBEXEC_DIRECTORY}" \
    "${CODEX_STATE_HOME}" \
    "${CODEX_WORKSPACE}"

  if [[ ! -x ${STATE_HELPER} ]]; then
    [[ -s ${S3_BIN_DIRECTORY}/codex-s3-state ]] \
      || fail "S3 recovery helper is missing: ${S3_BIN_DIRECTORY}/codex-s3-state"
    install -m 0700 "${S3_BIN_DIRECTORY}/codex-s3-state" "${STATE_HELPER}"
  fi
  if [[ ! -x ${CODEX_BINARY} ]]; then
    [[ -s ${S3_BIN_DIRECTORY}/codex-bin ]] \
      || fail "S3 Codex binary is missing: ${S3_BIN_DIRECTORY}/codex-bin"
    install -m 0700 "${S3_BIN_DIRECTORY}/codex-bin" "${CODEX_BINARY}"
  fi
  if [[ ! -x ${CODE_MODE_HOST} ]]; then
    [[ -s ${S3_BIN_DIRECTORY}/codex-code-mode-host ]] \
      || fail "S3 code-mode host is missing: ${S3_BIN_DIRECTORY}/codex-code-mode-host"
    install -m 0700 "${S3_BIN_DIRECTORY}/codex-code-mode-host" "${CODE_MODE_HOST}"
  fi
}

install_codex_wrapper() {
  cat >"${LOCAL_BIN_DIRECTORY}/codex" <<'WRAPPER'
#!/bin/sh
export HOME=/root
export CODEX_HOME=/root/.codex
export TMPDIR=/root/.cache/codex-tmp
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
mkdir -p "$CODEX_HOME/tmp" "$TMPDIR" /tmp/codex-arg0
if [ ! -L "$CODEX_HOME/tmp/arg0" ]; then
  if [ -e "$CODEX_HOME/tmp/arg0" ]; then
    mv "$CODEX_HOME/tmp/arg0" "$CODEX_HOME/tmp/arg0.stale-$(date +%s)"
  fi
  ln -s /tmp/codex-arg0 "$CODEX_HOME/tmp/arg0"
fi
exec /root/.local/libexec/codex-bin "$@"
WRAPPER
  chmod 0700 "${LOCAL_BIN_DIRECTORY}/codex"
}

restore_state_if_needed() {
  local integrity='missing' latest_snapshot

  if [[ -f ${CODEX_STATE_HOME}/state_5.sqlite ]]; then
    integrity="$(sqlite3 "${CODEX_STATE_HOME}/state_5.sqlite" 'PRAGMA integrity_check;' 2>/dev/null || true)"
  fi
  [[ ${integrity} == ok ]] && return 0
  latest_snapshot="$({
    find "${CODEX_S3_STATE_DIR}" -maxdepth 1 -type f -name 'snapshot-*.tar.gz' \
      -printf '%f\n' 2>/dev/null || true
  } | sort -r | head -n 1)"
  [[ -n ${latest_snapshot} ]] \
    || fail "local Codex state is unavailable and no S3 snapshot exists"
  CODEX_STATE_HOME="${CODEX_STATE_HOME}" \
  CODEX_S3_STATE_DIR="${CODEX_S3_STATE_DIR}" \
    "${STATE_HELPER}" restore latest
}

start_sync_daemon() {
  local sync_command

  if tmux has-session -t "${SYNC_SESSION_NAME}" 2>/dev/null; then
    if [[ $(tmux display-message -p -t "${SYNC_SESSION_NAME}" '#{pane_dead}') == 0 ]]; then
      return 0
    fi
    tmux kill-session -t "${SYNC_SESSION_NAME}" 2>/dev/null || true
  fi
  printf -v sync_command '%q ' \
    env \
    "HOME=${PERSISTENT_HOME}" \
    "CODEX_STATE_HOME=${CODEX_STATE_HOME}" \
    "CODEX_S3_STATE_DIR=${CODEX_S3_STATE_DIR}" \
    "${STATE_HELPER}" daemon
  tmux new-session -d -s "${SYNC_SESSION_NAME}" "${sync_command}"
  tmux set-option -t "${SYNC_SESSION_NAME}" remain-on-exit on
}

start_codex_session() {
  local thread_count=0 codex_command
  local -a command=(
    "${LOCAL_BIN_DIRECTORY}/codex"
    --dangerously-bypass-approvals-and-sandbox
    --no-alt-screen
  )

  if tmux has-session -t "${CODEX_SESSION_NAME}" 2>/dev/null; then
    if [[ $(tmux display-message -p -t "${CODEX_SESSION_NAME}" '#{pane_dead}') == 0 ]]; then
      printf 'Codex is already running. Attach with: tmux attach -t %s\n' "${CODEX_SESSION_NAME}"
      return 0
    fi
    tmux kill-session -t "${CODEX_SESSION_NAME}" 2>/dev/null || true
  fi

  if [[ -f ${CODEX_STATE_HOME}/state_5.sqlite ]]; then
    thread_count="$(sqlite3 "${CODEX_STATE_HOME}/state_5.sqlite" \
      'SELECT count(*) FROM threads WHERE archived = 0;' 2>/dev/null || printf '0')"
  fi
  if [[ ${thread_count} =~ ^[0-9]+$ ]] && ((thread_count > 0)); then
    command+=(resume --last --all)
  fi
  printf -v codex_command '%q ' "${command[@]}"
  tmux new-session -d \
    -s "${CODEX_SESSION_NAME}" \
    -c "${CODEX_WORKSPACE}" \
    "${codex_command}"
  tmux set-option -t "${CODEX_SESSION_NAME}" remain-on-exit on
  printf 'Codex started. Attach with: tmux attach -t %s\n' "${CODEX_SESSION_NAME}"
}

export HOME="${PERSISTENT_HOME}"
export CODEX_HOME="${CODEX_STATE_HOME}"
export TMPDIR="${PERSISTENT_HOME}/.cache/codex-tmp"
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export TERM=xterm-256color
install -d -m 0700 "${TMPDIR}"

install_runtime_packages
install_persistent_tools
install_codex_wrapper
restore_state_if_needed
start_sync_daemon
start_codex_session
