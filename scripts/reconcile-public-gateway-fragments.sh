#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_EXTRA_CADDYFILE="/etc/heteronetwork/public-gateway-extra.Caddyfile"
readonly DEFAULT_TARGET_DIRECTORY="/etc/heteronetwork/public-gateway.d"
readonly MANAGED_MARKER="# heteronetwork-managed-public-gateway-fragments:"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo --preserve-env=PUBLIC_GATEWAY_EXTRA_CADDYFILE,PUBLIC_GATEWAY_FRAGMENT_SOURCE,PUBLIC_GATEWAY_FRAGMENT_TARGET \
    "$0" "$@"
fi

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -- "${script_directory}/.." && pwd -P)"
source_directory="${PUBLIC_GATEWAY_FRAGMENT_SOURCE:-${repository_root}/deploy/environments/heteronet/public-gateway.d}"
target_directory="${PUBLIC_GATEWAY_FRAGMENT_TARGET:-${DEFAULT_TARGET_DIRECTORY}}"
extra_caddyfile="${PUBLIC_GATEWAY_EXTRA_CADDYFILE:-${DEFAULT_EXTRA_CADDYFILE}}"

[[ -d "${source_directory}" && ! -L "${source_directory}" ]] \
  || { printf 'public gateway fragment source is not a directory: %s\n' "${source_directory}" >&2; exit 1; }
[[ -f "${extra_caddyfile}" && ! -L "${extra_caddyfile}" ]] \
  || { printf 'public gateway extra Caddyfile is not a regular file: %s\n' "${extra_caddyfile}" >&2; exit 1; }

mapfile -d '' fragments < <(find "${source_directory}" -maxdepth 1 -type f -name '*.Caddyfile' -print0 | sort -z)
((${#fragments[@]} > 0)) \
  || { printf 'no public gateway fragments found in %s\n' "${source_directory}" >&2; exit 1; }

install -d -o root -g root -m 0755 "${target_directory}"
for fragment in "${fragments[@]}"; do
  [[ ! -L "${fragment}" ]] \
    || { printf 'public gateway fragment must not be a symlink: %s\n' "${fragment}" >&2; exit 1; }
  install -o root -g root -m 0644 "${fragment}" "${target_directory}/$(basename "${fragment}")"
done

fragment_digest="$({
  for fragment in "${fragments[@]}"; do
    printf '%s\0' "$(basename "${fragment}")"
    sha256sum "${fragment}"
  done
} | sha256sum | awk '{print $1}')"
temporary="$(mktemp "${extra_caddyfile}.XXXXXX")"
trap 'rm -f "${temporary}"' EXIT

awk -v marker="${MANAGED_MARKER}" -v import="import ${target_directory}/*.Caddyfile" '
  index($0, marker) == 1 { next }
  $0 == import { next }
  { print }
' "${extra_caddyfile}" >"${temporary}"
printf '\n%s %s\nimport %s/*.Caddyfile\n' \
  "${MANAGED_MARKER}" "${fragment_digest}" "${target_directory}" >>"${temporary}"

mode="$(stat -c '%a' "${extra_caddyfile}")"
owner="$(stat -c '%u' "${extra_caddyfile}")"
group="$(stat -c '%g' "${extra_caddyfile}")"
install -o "${owner}" -g "${group}" -m "${mode}" "${temporary}" "${extra_caddyfile}"
rm -f "${temporary}"
trap - EXIT

printf 'Public gateway fragments reconciled; the Agent will reload digest %s.\n' "${fragment_digest}"
