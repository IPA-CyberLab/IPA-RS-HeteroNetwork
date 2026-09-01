#!/usr/bin/env bash
set -euo pipefail

readonly bootstrap_env="${HETERONETWORK_PUBLIC_SERVICES_BOOTSTRAP_ENV:-/etc/heteronetwork/public-services/bootstrap.env}"
readonly autopilot="${HETERONETWORK_PUBLIC_SERVICES_AUTOPILOT:-/opt/heteronetwork/libexec/public-services-autopilot.sh}"
readonly owner_email="${HETERONETWORK_OWNER_EMAIL:-}"
readonly verification_origin="${HETERONETWORK_OWNER_OIDC_VERIFICATION_ORIGIN:-https://heterocloud.mizuame.app}"
readonly issuer="http://console.heteronetwork.internal:18079/realms/heterocloud"
readonly client_id="ipars-web"

fail() {
  printf 'reconcile-owner-console-auth: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" == 0 ]] || fail "must run as root"
[[ "$owner_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] \
  || fail "HETERONETWORK_OWNER_EMAIL must be set to the existing HeteroCloud owner email"
[[ "$verification_origin" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
  || fail "HETERONETWORK_OWNER_OIDC_VERIFICATION_ORIGIN must be an HTTPS origin"
[[ -f "$bootstrap_env" && ! -L "$bootstrap_env" ]] \
  || fail "public-services bootstrap configuration is unavailable"
[[ -x "$autopilot" && ! -L "$autopilot" ]] \
  || fail "public-services autopilot is unavailable"
command -v base64 >/dev/null || fail "base64 is required"
command -v awk >/dev/null || fail "awk is required"

bootstrap_uid="$(stat -c '%u' "$bootstrap_env")"
bootstrap_mode="$(stat -c '%a' "$bootstrap_env")"
[[ "$bootstrap_uid" == 0 && "$bootstrap_mode" == 600 ]] \
  || fail "public-services bootstrap configuration has unsafe ownership or mode"

encode() {
  printf '%s' "$1" | base64 | tr -d '\r\n'
}

decode_entry() {
  local key="$1" encoded
  encoded="$(awk -F= -v key="$key" '$1 == key {value = substr($0, index($0, "=") + 1)} END {print value}' "$bootstrap_env")"
  [[ -n "$encoded" ]] || return 0
  printf '%s' "$encoded" | base64 --decode
}

replace_entry() {
  local key="$1" value="$2" temporary
  temporary="$(mktemp "$(dirname "$bootstrap_env")/.bootstrap.env.XXXXXX")"
  awk -v key="$key" -v value="$value" '
    BEGIN { replaced = 0 }
    index($0, key "=") == 1 {
      if (!replaced) print key "=" value
      replaced = 1
      next
    }
    { print }
    END { if (!replaced) print key "=" value }
  ' "$bootstrap_env" >"$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$bootstrap_env"
}

fallbacks="$(decode_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64 || true)"
fallbacks="${fallbacks//\/realms\/heteronetwork/\/realms\/heterocloud}"

replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64 "$(encode "$issuer")"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_CLIENT_ID_B64 "$(encode "$client_id")"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_AUTH_BASE_URL_B64 "$(encode "$issuer")"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_BASE_URL_B64 \
  "$(encode 'http://127.0.0.1:18079/realms/heterocloud')"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64 \
  "$(encode "$fallbacks")"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_SCOPES_B64 \
  "$(encode 'openid profile email')"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_DEVICE_VERIFICATION_ORIGIN_B64 \
  "$(encode "$verification_origin")"
replace_entry HETERONETWORK_PUBLIC_SERVICES_OIDC_REQUIRED_EMAIL_B64 \
  "$(encode "${owner_email,,}")"

"$autopilot"
printf 'reconcile-owner-console-auth: configured %s for %s via %s\n' \
  "$client_id" "${owner_email,,}" "$verification_origin"
