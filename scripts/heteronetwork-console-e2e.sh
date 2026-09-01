#!/usr/bin/env bash
set -euo pipefail

readonly console_url="${HETERONETWORK_CONSOLE_E2E_URL:-http://console.heteronetwork.internal}"
readonly owner_url="${HETERONETWORK_CONSOLE_E2E_OWNER_URL:-http://owner.heteronetwork.internal:21443}"
readonly expected_issuer="${HETERONETWORK_CONSOLE_E2E_ISSUER:-http://console.heteronetwork.internal:18079/realms/heterocloud}"
readonly expected_client_id="${HETERONETWORK_CONSOLE_E2E_CLIENT_ID:-ipars-web}"
readonly expected_verification_origin="${HETERONETWORK_CONSOLE_E2E_VERIFICATION_ORIGIN:-https://heterocloud.mizuame.app}"
readonly expected_verification_issuer="${HETERONETWORK_CONSOLE_E2E_VERIFICATION_ISSUER:-${expected_verification_origin}/id/realms/heterocloud}"
readonly node_ips_csv="${HETERONETWORK_CONSOLE_E2E_NODE_IPS:-}"

fail() {
  printf 'heteronetwork-console-e2e: %s\n' "$*" >&2
  exit 1
}

command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required"
[[ "$console_url" == "http://console.heteronetwork.internal" ]] \
  || fail "console URL must be the canonical portless VPN URL"
[[ "$owner_url" == "http://owner.heteronetwork.internal:21443" ]] \
  || fail "owner URL must use the dedicated owner-console port"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

curl_common=(
  --silent
  --show-error
  --connect-timeout 3
  --max-time 15
)

probe_console_origin() {
  local resolve_arg="${1:-}" label="${2:-DNS}"
  local -a resolve=()
  if [[ -n "$resolve_arg" ]]; then
    resolve=(--resolve "console.heteronetwork.internal:80:${resolve_arg}")
  fi
  local headers="$work_dir/root-${label}.headers"
  local body="$work_dir/root-${label}.body"
  local code
  code="$(curl "${curl_common[@]}" "${resolve[@]}" \
    --dump-header "$headers" --output "$body" --write-out '%{http_code}' \
    "$console_url/")" || fail "$label console root request failed"
  [[ "$code" == 307 ]] || fail "$label console root returned HTTP $code"
  tr -d '\r' <"$headers" | grep -Fqix 'location: /ui/' \
    || fail "$label console root did not redirect to /ui/"

  code="$(curl "${curl_common[@]}" "${resolve[@]}" \
    --output "$body" --write-out '%{http_code}' "$console_url/ui/")" \
    || fail "$label console UI request failed"
  [[ "$code" == 200 ]] || fail "$label console UI returned HTTP $code"
  grep -Fq '/ui/app.js' "$body" || fail "$label console UI omitted its application bundle"
}

probe_console_origin "" DNS
if [[ -n "$node_ips_csv" ]]; then
  IFS=, read -r -a node_ips <<<"$node_ips_csv"
  for node_ip in "${node_ips[@]}"; do
    [[ "$node_ip" =~ ^10\.250\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
      || fail "invalid node VPN address: $node_ip"
    probe_console_origin "$node_ip" "$node_ip"
  done
fi

config="$work_dir/config.json"
curl "${curl_common[@]}" --fail --output "$config" "$console_url/ui/config" \
  || fail "console auth configuration is unavailable"
jq -e \
  --arg issuer "$expected_issuer" \
  --arg client_id "$expected_client_id" \
  --arg verification_origin "$expected_verification_origin" '
    .auth_enabled == true
    and .provider == "keycloak"
    and .issuer_url == $issuer
    and .client_id == $client_id
    and .device_verification_origin == $verification_origin
    and .device_login_endpoint == "/v1/web-ui/auth/device"
    and .device_login_poll_endpoint == "/v1/web-ui/auth/device/poll"
    and (.device_authorization_endpoint | startswith($issuer + "/protocol/openid-connect/auth/device"))
  ' "$config" >/dev/null \
  || fail "console does not use the HeteroCloud owner identity client"

device="$work_dir/device.json"
for attempt in 1 2 3; do
  code="$(curl "${curl_common[@]}" \
    --header 'Content-Type: application/json' --data '{}' \
    --output "$device" --write-out '%{http_code}' \
    "$console_url/v1/web-ui/auth/device")" \
    || fail "device authorization request failed"
  [[ "$code" == 429 ]] || break
  sleep 2
done
[[ "$code" == 200 ]] || fail "device authorization returned HTTP $code"
jq -e --arg issuer "$expected_verification_issuer" '
  (.handle | type == "string" and length >= 32)
  and (.user_code | type == "string" and length > 0)
  and .verification_uri == ($issuer + "/device")
  and (.verification_uri_complete | startswith($issuer + "/device?user_code="))
' "$device" >/dev/null || fail "device authorization response targets the wrong identity realm"

verification_url="$(jq -er '.verification_uri_complete' "$device")"
code="$(curl "${curl_common[@]}" --output "$work_dir/keycloak.html" \
  --write-out '%{http_code}' "$verification_url")" \
  || fail "owner Keycloak verification page is unavailable"
[[ "$code" == 200 ]] || fail "owner Keycloak verification page returned HTTP $code"
grep -Fq 'HeteroCloud' "$work_dir/keycloak.html" \
  || fail "device verification page is not the HeteroCloud realm"

code="$(curl "${curl_common[@]}" --output "$work_dir/owner.html" \
  --write-out '%{http_code}' "$owner_url/")" \
  || fail "owner console request failed"
case "$code" in
  200|302|303|307|308) ;;
  *) fail "owner console returned HTTP $code" ;;
esac

curl "${curl_common[@]}" --fail --output "$work_dir/app.js" "$console_url/ui/app.js" \
  || fail "console application bundle is unavailable"
grep -Fq 'owner.heteronetwork.internal:21443' "$work_dir/app.js" \
  || fail "console bundle contains a stale owner-console link"
if grep -Fq 'owner.heteronetwork.internal:19443' "$work_dir/app.js"; then
  fail "console bundle points the owner console at the signaling port"
fi

printf 'heteronetwork-console-e2e: ok\n'
