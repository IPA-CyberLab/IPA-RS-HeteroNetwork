#!/usr/bin/env bash
set -euo pipefail

readonly CODEX_STATE_HOME="${CODEX_STATE_HOME:-${CODEX_HOME:-${HOME}/.codex}}"
readonly CODEX_S3_STATE_DIR="${CODEX_S3_STATE_DIR:-${HOME}/syouyu/codex-state}"
readonly CODEX_S3_SYNC_INTERVAL="${CODEX_S3_SYNC_INTERVAL:-15}"
readonly CODEX_S3_SNAPSHOT_RETENTION="${CODEX_S3_SNAPSHOT_RETENTION:-5}"
readonly LOCK_DIRECTORY="${TMPDIR:-/tmp}/codex-s3-state.lock"

fail() {
  printf 'codex-s3-state: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

validate_configuration() {
  [[ ${CODEX_S3_SYNC_INTERVAL} =~ ^[0-9]+$ ]] && ((CODEX_S3_SYNC_INTERVAL >= 5)) \
    || fail "CODEX_S3_SYNC_INTERVAL must be at least 5 seconds"
  [[ ${CODEX_S3_SNAPSHOT_RETENTION} =~ ^[0-9]+$ ]] && ((CODEX_S3_SNAPSHOT_RETENTION >= 2)) \
    || fail "CODEX_S3_SNAPSHOT_RETENTION must be at least 2"
  [[ ${CODEX_STATE_HOME} == /* && ${CODEX_S3_STATE_DIR} == /* ]] \
    || fail "state paths must be absolute"
  [[ ${CODEX_STATE_HOME} != "${CODEX_S3_STATE_DIR}" ]] \
    || fail "CODEX_STATE_HOME and CODEX_S3_STATE_DIR must differ"
}

acquire_lock() {
  mkdir "${LOCK_DIRECTORY}" 2>/dev/null \
    || fail "another backup or restore operation is running"
}

release_lock() {
  rmdir "${LOCK_DIRECTORY}" 2>/dev/null || true
}

copy_complete_jsonl_files() {
  local source_directory=$1 destination_directory=$2 source relative destination last_byte

  [[ -d ${source_directory} ]] || return 0
  mkdir -p "${destination_directory}"
  cp -a "${source_directory}/." "${destination_directory}/"

  while IFS= read -r -d '' source; do
    relative="${source#${destination_directory}/}"
    destination="${destination_directory}/${relative}"
    [[ -s ${destination} ]] || continue
    last_byte="$(tail -c 1 "${destination}" | od -An -t x1 | tr -d '[:space:]')"
    if [[ ${last_byte} != 0a ]]; then
      sed -i '$d' "${destination}"
    fi
  done < <(find "${destination_directory}" -type f -name '*.jsonl' -print0)
}

backup_sqlite_database() {
  local source=$1 destination=$2 escaped_destination

  [[ -f ${source} ]] || return 0
  escaped_destination="${destination//\'/\'\'}"
  sqlite3 "${source}" ".timeout 10000" ".backup '${escaped_destination}'"
  [[ $(sqlite3 "${destination}" 'PRAGMA integrity_check;') == ok ]] \
    || fail "SQLite snapshot failed integrity validation: $(basename "${source}")"
}

snapshot_fingerprint() {
  {
    stat -c '%n:%Y:%s' \
      "${CODEX_STATE_HOME}/state_5.sqlite" \
      "${CODEX_STATE_HOME}/state_5.sqlite-wal" \
      "${CODEX_STATE_HOME}/goals_1.sqlite" \
      "${CODEX_STATE_HOME}/goals_1.sqlite-wal" \
      "${CODEX_STATE_HOME}/memories_1.sqlite" \
      "${CODEX_STATE_HOME}/memories_1.sqlite-wal" 2>/dev/null || true
    if [[ -d ${CODEX_STATE_HOME}/sessions ]]; then
      find "${CODEX_STATE_HOME}/sessions" -type f -printf '%p:%T@:%s\n' 2>/dev/null | sort
    fi
  } | sha256sum | cut -d ' ' -f 1
}

write_snapshot() (
  local work_directory archive_path epoch snapshot_name
  local source_name
  local -a snapshots=()

  require_command cp
  require_command find
  require_command od
  require_command sed
  require_command sha256sum
  require_command sqlite3
  require_command tar

  [[ -d ${CODEX_STATE_HOME} ]] || fail "Codex state directory is missing: ${CODEX_STATE_HOME}"
  mkdir -p "${CODEX_S3_STATE_DIR}"
  [[ -w ${CODEX_S3_STATE_DIR} ]] || fail "S3 state directory is not writable: ${CODEX_S3_STATE_DIR}"

  acquire_lock
  work_directory="$(mktemp -d "${TMPDIR:-/tmp}/codex-s3-snapshot.XXXXXX")"
  archive_path="${work_directory}/snapshot.tar.gz"
  trap 'rm -rf -- "${work_directory:-}"; release_lock' EXIT HUP INT TERM
  mkdir -p "${work_directory}/codex"

  for source_name in state_5.sqlite goals_1.sqlite memories_1.sqlite; do
    backup_sqlite_database \
      "${CODEX_STATE_HOME}/${source_name}" \
      "${work_directory}/codex/${source_name}"
  done

  for source_name in auth.json config.toml installation_id version.json; do
    if [[ -f ${CODEX_STATE_HOME}/${source_name} ]]; then
      cp -a "${CODEX_STATE_HOME}/${source_name}" "${work_directory}/codex/${source_name}"
    fi
  done

  copy_complete_jsonl_files \
    "${CODEX_STATE_HOME}/sessions" \
    "${work_directory}/codex/sessions"
  if [[ -d ${CODEX_STATE_HOME}/shell_snapshots ]]; then
    cp -a "${CODEX_STATE_HOME}/shell_snapshots" "${work_directory}/codex/shell_snapshots"
  fi

  epoch="$(date -u +%s)"
  {
    printf 'schema_version=1\n'
    printf 'created_at_epoch=%s\n' "${epoch}"
    printf 'source_host=%s\n' "$(hostname)"
    printf 'state_fingerprint=%s\n' "$(snapshot_fingerprint)"
  } >"${work_directory}/manifest"

  tar -C "${work_directory}" -czf "${archive_path}" codex manifest
  tar -tzf "${archive_path}" >/dev/null
  snapshot_name="snapshot-${epoch}-$$.tar.gz"
  cp "${archive_path}" "${CODEX_S3_STATE_DIR}/${snapshot_name}.partial"
  mv "${CODEX_S3_STATE_DIR}/${snapshot_name}.partial" \
    "${CODEX_S3_STATE_DIR}/${snapshot_name}"
  tar -tzf "${CODEX_S3_STATE_DIR}/${snapshot_name}" >/dev/null

  mapfile -t snapshots < <(
    find "${CODEX_S3_STATE_DIR}" -maxdepth 1 -type f -name 'snapshot-*.tar.gz' \
      -printf '%f\n' | sort -r
  )
  if ((${#snapshots[@]} > CODEX_S3_SNAPSHOT_RETENTION)); then
    for source_name in "${snapshots[@]:CODEX_S3_SNAPSHOT_RETENTION}"; do
      rm -f -- "${CODEX_S3_STATE_DIR}/${source_name}"
    done
  fi

  printf '%s\n' "${snapshot_name}"
  rm -rf -- "${work_directory}"
  release_lock
  trap - EXIT HUP INT TERM
)

resolve_snapshot_name() {
  local requested=${1:-latest} candidate

  if [[ ${requested} == latest ]]; then
    candidate="$({
      find "${CODEX_S3_STATE_DIR}" -maxdepth 1 -type f -name 'snapshot-*.tar.gz' \
        -printf '%f\n' 2>/dev/null || true
    } | sort -r | head -n 1)"
    [[ -n ${candidate} ]] || fail "S3 snapshot is missing"
  else
    candidate=${requested}
  fi
  [[ ${candidate} =~ ^snapshot-[0-9]+-[0-9]+\.tar\.gz$ ]] \
    || fail "invalid snapshot name"
  [[ -s ${CODEX_S3_STATE_DIR}/${candidate} ]] \
    || fail "snapshot does not exist: ${candidate}"
  printf '%s\n' "${candidate}"
}

restore_snapshot() (
  local snapshot_name work_directory archive_path previous_state

  require_command cp
  require_command sqlite3
  require_command tar

  snapshot_name="$(resolve_snapshot_name "${1:-latest}")"
  if pgrep -x codex >/dev/null 2>&1; then
    fail "Codex is running; stop it before restoring state"
  fi

  acquire_lock
  work_directory="$(mktemp -d "${TMPDIR:-/tmp}/codex-s3-restore.XXXXXX")"
  archive_path="${work_directory}/snapshot.tar.gz"
  trap 'rm -rf -- "${work_directory:-}"; release_lock' EXIT HUP INT TERM
  cp "${CODEX_S3_STATE_DIR}/${snapshot_name}" "${archive_path}"
  tar -tzf "${archive_path}" >/dev/null
  tar -C "${work_directory}" -xzf "${archive_path}"
  [[ -d ${work_directory}/codex && -f ${work_directory}/manifest ]] \
    || fail "snapshot layout is invalid"
  [[ -f ${work_directory}/codex/state_5.sqlite ]] \
    || fail "snapshot does not contain the Codex session index"
  [[ $(sqlite3 "${work_directory}/codex/state_5.sqlite" 'PRAGMA integrity_check;') == ok ]] \
    || fail "snapshot session index is corrupt"

  previous_state="${CODEX_STATE_HOME}.before-s3-restore-$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ -e ${CODEX_STATE_HOME} ]]; then
    mv "${CODEX_STATE_HOME}" "${previous_state}"
  fi
  install -d -m 0700 "${CODEX_STATE_HOME}"
  cp -a "${work_directory}/codex/." "${CODEX_STATE_HOME}/"
  install -d -m 0700 "${CODEX_STATE_HOME}/tmp" "${CODEX_STATE_HOME}/.tmp"
  rm -rf "${CODEX_STATE_HOME}/tmp/arg0"
  install -d -m 0700 /tmp/codex-arg0
  ln -s /tmp/codex-arg0 "${CODEX_STATE_HOME}/tmp/arg0"
  [[ ! -f ${CODEX_STATE_HOME}/auth.json ]] || chmod 0600 "${CODEX_STATE_HOME}/auth.json"

  printf 'restored=%s\n' "${snapshot_name}"
  printf 'previous_state=%s\n' "${previous_state}"
  rm -rf -- "${work_directory}"
  release_lock
  trap - EXIT HUP INT TERM
)

run_daemon() {
  local previous_fingerprint='' current_fingerprint

  while true; do
    current_fingerprint="$(snapshot_fingerprint)"
    if [[ ${current_fingerprint} != "${previous_fingerprint}" ]]; then
      if write_snapshot >/dev/null; then
        previous_fingerprint=${current_fingerprint}
      else
        printf 'codex-s3-state: snapshot failed; retrying\n' >&2
      fi
    fi
    sleep "${CODEX_S3_SYNC_INTERVAL}"
  done
}

usage() {
  cat <<'USAGE'
Usage: codex-s3-state.sh snapshot
       codex-s3-state.sh restore [latest|SNAPSHOT_NAME]
       codex-s3-state.sh daemon
USAGE
}

validate_configuration
case ${1:-} in
  snapshot)
    write_snapshot
    ;;
  restore)
    restore_snapshot "${2:-latest}"
    ;;
  daemon)
    run_daemon
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
