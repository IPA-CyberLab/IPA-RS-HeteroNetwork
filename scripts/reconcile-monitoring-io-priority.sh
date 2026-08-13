#!/usr/bin/env bash
set -euo pipefail

if ((EUID != 0)); then
  printf 'reconcile-monitoring-io-priority must run as root\n' >&2
  exit 1
fi

for required_command in ionice pgrep renice; do
  command -v "$required_command" >/dev/null 2>&1 || {
    printf 'required command is missing: %s\n' "$required_command" >&2
    exit 1
  }
done

for process_name in prometheus grafana; do
  while IFS= read -r process_id; do
    [[ "$process_id" =~ ^[0-9]+$ ]] || continue
    [[ -r "/proc/${process_id}/comm" ]] || continue
    [[ "$(<"/proc/${process_id}/comm")" == "$process_name" ]] || continue
    ionice -c 3 -p "$process_id"
    renice 10 -p "$process_id" >/dev/null
  done < <(pgrep -x "$process_name" || true)
done
