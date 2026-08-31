#!/usr/bin/env bash
set -euo pipefail

umask 077

public_base_url="${HETERONETWORK_KEYCLOAK_E2E_PUBLIC_BASE_URL:-https://heterocloud.mizuame.app}"
private_edge_url="${HETERONETWORK_KEYCLOAK_E2E_PRIVATE_EDGE_URL:-http://console.heteronetwork.internal:18079}"
agent_gateway_url="${HETERONETWORK_KEYCLOAK_E2E_AGENT_GATEWAY_URL:-http://console.heteronetwork.internal:9781}"
backend_urls_csv="${HETERONETWORK_KEYCLOAK_E2E_BACKEND_URLS:-}"
attempts="${HETERONETWORK_KEYCLOAK_E2E_ATTEMPTS:-10}"
required_backends="${HETERONETWORK_KEYCLOAK_E2E_REQUIRED_BACKENDS:-0}"
connect_timeout_seconds="${HETERONETWORK_KEYCLOAK_E2E_CONNECT_TIMEOUT_SECONDS:-5}"
request_timeout_seconds="${HETERONETWORK_KEYCLOAK_E2E_REQUEST_TIMEOUT_SECONDS:-20}"
public_realm="${HETERONETWORK_KEYCLOAK_E2E_PUBLIC_REALM:-heterocloud}"
private_realm="${HETERONETWORK_KEYCLOAK_E2E_PRIVATE_REALM:-heteronetwork}"
public_client_id="${HETERONETWORK_KEYCLOAK_E2E_PUBLIC_CLIENT_ID:-heterocloud-web}"
public_keycloak_prefix="${HETERONETWORK_KEYCLOAK_E2E_PUBLIC_KEYCLOAK_PREFIX:-/id}"
check_public=true
check_private=true
check_backends=true
check_assets=true
check_registration=true
check_device_authorization=true

usage() {
  cat <<'EOF'
Usage: keycloak-ha-e2e.sh [OPTIONS]

Runs a non-destructive end-to-end check of the public HeteroCloud OIDC login,
the private HeteroNetwork device login, and each configured Keycloak replica.

Options:
  --public-base-url URL       Public HeteroCloud origin.
  --private-edge-url URL      VPN-only Keycloak edge origin.
  --agent-gateway-url URL     VPN-only Agent Web UI gateway origin.
  --backend-url URL           Direct Keycloak replica origin; repeatable.
  --attempts N                Repeated public login attempts. Default: 10.
  --require-backends N        Require exactly N direct replica URLs.
  --public-only               Skip VPN-only edge, device, and replica checks.
  --skip-assets               Do not fetch Keycloak login CSS/JavaScript.
  --skip-registration         Do not open the self-registration form.
  --skip-device-authorization Do not create a short-lived device login request.
  -h, --help                  Show this help.

The same values can be supplied through HETERONETWORK_KEYCLOAK_E2E_* variables.
HETERONETWORK_KEYCLOAK_E2E_BACKEND_URLS is a comma-separated URL list.
EOF
}

fail() {
  printf 'keycloak HA E2E: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'keycloak HA E2E: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

valid_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

valid_base_url() {
  [[ "$1" =~ ^https?://[][A-Za-z0-9._~:%+-]+$ ]]
}

trim_trailing_slash() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  printf '%s\n' "$value"
}

urlencode() {
  local LC_ALL=C value="$1" output="" character index
  for ((index = 0; index < ${#value}; index++)); do
    character="${value:index:1}"
    case "$character" in
      [A-Za-z0-9.~_-]) output+="$character" ;;
      *) printf -v character '%%%02X' "'$character"; output+="$character" ;;
    esac
  done
  printf '%s\n' "$output"
}

header_value() {
  local name="$1" path="$2"
  awk -v target="$name" '
    BEGIN { IGNORECASE = 1 }
    {
      line = $0
      sub(/\r$/, "", line)
      separator = index(line, ":")
      if (separator > 0 && tolower(substr(line, 1, separator - 1)) == tolower(target)) {
        value = substr(line, separator + 1)
        sub(/^[[:space:]]+/, "", value)
      }
    }
    END {
      if (value == "") exit 1
      print value
    }
  ' "$path"
}

http_code() {
  local output_path="$1"
  shift
  curl --silent --show-error \
    --connect-timeout "$connect_timeout_seconds" \
    --max-time "$request_timeout_seconds" \
    --output "$output_path" \
    --write-out '%{http_code}' \
    "$@"
}

assert_json_discovery() {
  local path="$1" expected_issuer="$2"
  jq -e --arg issuer "$expected_issuer" '
    type == "object"
    and .issuer == $issuer
    and (.authorization_endpoint | type == "string" and startswith($issuer + "/"))
    and (.token_endpoint | type == "string" and startswith($issuer + "/"))
    and (.jwks_uri | type == "string" and startswith($issuer + "/"))
  ' "$path" >/dev/null || fail "OIDC discovery contract is invalid for $expected_issuer"
}

declare -a backend_urls=()
while (($# > 0)); do
  case "$1" in
    --public-base-url)
      (($# >= 2)) || fail "--public-base-url requires a value"
      public_base_url="$2"
      shift 2
      ;;
    --private-edge-url)
      (($# >= 2)) || fail "--private-edge-url requires a value"
      private_edge_url="$2"
      shift 2
      ;;
    --agent-gateway-url)
      (($# >= 2)) || fail "--agent-gateway-url requires a value"
      agent_gateway_url="$2"
      shift 2
      ;;
    --backend-url)
      (($# >= 2)) || fail "--backend-url requires a value"
      backend_urls+=("$2")
      shift 2
      ;;
    --attempts)
      (($# >= 2)) || fail "--attempts requires a value"
      attempts="$2"
      shift 2
      ;;
    --require-backends)
      (($# >= 2)) || fail "--require-backends requires a value"
      required_backends="$2"
      shift 2
      ;;
    --public-only)
      check_private=false
      check_backends=false
      shift
      ;;
    --skip-assets)
      check_assets=false
      shift
      ;;
    --skip-registration)
      check_registration=false
      shift
      ;;
    --skip-device-authorization)
      check_device_authorization=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

if [[ "$check_backends" == true && -n "$backend_urls_csv" ]]; then
  IFS=, read -r -a environment_backends <<<"$backend_urls_csv"
  backend_urls+=("${environment_backends[@]}")
fi

require_command curl
require_command jq
require_command awk
require_command grep
require_command sed
require_command sha256sum
require_command sort

valid_uint "$attempts" && ((10#$attempts >= 1 && 10#$attempts <= 100)) \
  || fail "attempts must be between 1 and 100"
valid_uint "$required_backends" && ((10#$required_backends <= 32)) \
  || fail "required backend count must be between 0 and 32"
valid_uint "$connect_timeout_seconds" && ((10#$connect_timeout_seconds >= 1)) \
  || fail "connect timeout must be a positive integer"
valid_uint "$request_timeout_seconds" \
  && ((10#$request_timeout_seconds >= 1 && 10#$request_timeout_seconds >= 10#$connect_timeout_seconds)) \
  || fail "request timeout must be an integer greater than or equal to connect timeout"
[[ "$public_keycloak_prefix" =~ ^/[A-Za-z0-9._~/-]*$ \
  && "$public_keycloak_prefix" != */ ]] \
  || fail "public Keycloak prefix is invalid"
[[ "$public_realm" =~ ^[A-Za-z0-9._-]+$ \
  && "$private_realm" =~ ^[A-Za-z0-9._-]+$ \
  && "$public_client_id" =~ ^[A-Za-z0-9._-]+$ ]] \
  || fail "realm or client identifier is invalid"

public_base_url="$(trim_trailing_slash "$public_base_url")"
private_edge_url="$(trim_trailing_slash "$private_edge_url")"
agent_gateway_url="$(trim_trailing_slash "$agent_gateway_url")"
valid_base_url "$public_base_url" || fail "public base URL is invalid"
if [[ "$check_private" == true ]]; then
  valid_base_url "$private_edge_url" || fail "private edge URL is invalid"
  valid_base_url "$agent_gateway_url" || fail "Agent gateway URL is invalid"
fi

if [[ "$check_backends" == true ]]; then
  for index in "${!backend_urls[@]}"; do
    backend_urls[$index]="$(trim_trailing_slash "${backend_urls[$index]}")"
    valid_base_url "${backend_urls[$index]}" \
      || fail "backend URL is invalid: ${backend_urls[$index]}"
  done
fi
if [[ "$check_backends" == true ]] \
  && ((10#$required_backends > 0 \
  && ${#backend_urls[@]} != 10#$required_backends)); then
  fail "expected $required_backends direct backends, found ${#backend_urls[@]}"
fi

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-keycloak-e2e.XXXXXX")"
cleanup() {
  rm -rf "$test_dir"
}
trap cleanup EXIT HUP INT TERM

public_discovery_url="${public_base_url}${public_keycloak_prefix}/realms/${public_realm}/.well-known/openid-configuration"
public_issuer="${public_base_url}${public_keycloak_prefix}/realms/${public_realm}"
private_discovery_url="${private_edge_url}/realms/${private_realm}/.well-known/openid-configuration"
private_issuer="${private_edge_url}/realms/${private_realm}"
first_login_body=""
first_cookie_jar=""

probe_public_discovery() {
  local body="$test_dir/public-discovery.json" code
  code="$(http_code "$body" "$public_discovery_url")" \
    || fail "public OIDC discovery request failed"
  [[ "$code" == 200 ]] || fail "public OIDC discovery returned HTTP $code"
  assert_json_discovery "$body" "$public_issuer"
}

probe_public_login_once() {
  local sequence="$1"
  local start_headers="$test_dir/start-${sequence}.headers"
  local start_body="$test_dir/start-${sequence}.body"
  local cookie_jar="$test_dir/start-${sequence}.cookies"
  local login_headers="$test_dir/login-${sequence}.headers"
  local login_body="$test_dir/login-${sequence}.html"
  local start_url="${public_base_url}/api/v1/auth/oidc/start"
  local code location redirect_uri_encoded response login_code effective_url cookie_header

  code="$(curl --silent --show-error \
    --connect-timeout "$connect_timeout_seconds" \
    --max-time "$request_timeout_seconds" \
    --dump-header "$start_headers" \
    --cookie-jar "$cookie_jar" \
    --output "$start_body" \
    --write-out '%{http_code}' \
    "$start_url")" || fail "OIDC start request $sequence failed"
  [[ "$code" == 303 ]] || fail "OIDC start request $sequence returned HTTP $code instead of 303"

  location="$(header_value Location "$start_headers")" \
    || fail "OIDC start request $sequence omitted Location"
  [[ "$location" == "${public_issuer}/protocol/openid-connect/auth?"* ]] \
    || fail "OIDC start request $sequence redirected outside the public Keycloak realm"
  [[ "$location" == *"response_type=code"* \
    && "$location" == *"client_id=${public_client_id}"* \
    && "$location" == *"code_challenge_method=S256"* ]] \
    || fail "OIDC start request $sequence omitted code flow or PKCE parameters"
  redirect_uri_encoded="$(urlencode "${public_base_url}/api/v1/auth/oidc/callback")"
  [[ "$location" == *"redirect_uri=${redirect_uri_encoded}"* ]] \
    || fail "OIDC start request $sequence emitted the wrong callback URL"
  grep -Eq '([?&])state=[A-Za-z0-9_-]{32,}([&]|$)' <<<"$location" \
    || fail "OIDC start request $sequence omitted a strong state value"
  grep -Eq '([?&])nonce=[A-Za-z0-9_-]{32,}([&]|$)' <<<"$location" \
    || fail "OIDC start request $sequence omitted a strong nonce"
  grep -Eq '([?&])code_challenge=[A-Za-z0-9_-]{43,}([&]|$)' <<<"$location" \
    || fail "OIDC start request $sequence omitted a PKCE challenge"

  cookie_header="$(grep -i '^set-cookie: hc_oidc_transaction=' "$start_headers" | tail -n 1 || true)"
  [[ -n "$cookie_header" \
    && "${cookie_header,,}" == *"httponly"* \
    && "${cookie_header,,}" == *"secure"* \
    && "${cookie_header,,}" == *"samesite=lax"* \
    && "${cookie_header,,}" == *"max-age="* ]] \
    || fail "OIDC start request $sequence omitted the protected transaction cookie"

  response="$(curl --silent --show-error --location --max-redirs 5 \
    --connect-timeout "$connect_timeout_seconds" \
    --max-time "$request_timeout_seconds" \
    --cookie "$cookie_jar" \
    --cookie-jar "$cookie_jar" \
    --dump-header "$login_headers" \
    --output "$login_body" \
    --write-out $'%{http_code}\n%{url_effective}' \
    "$location")" || fail "Keycloak login request $sequence failed"
  login_code="${response%%$'\n'*}"
  effective_url="${response#*$'\n'}"
  [[ "$login_code" == 200 ]] \
    || fail "Keycloak login request $sequence returned HTTP $login_code"
  [[ "$effective_url" == "${public_issuer}/"* ]] \
    || fail "Keycloak login request $sequence ended outside the public realm"
  grep -qi '<html' "$login_body" \
    || fail "Keycloak login request $sequence did not return HTML"
  grep -q 'name="username"' "$login_body" \
    || fail "Keycloak login request $sequence omitted the username field"
  grep -q 'name="password"' "$login_body" \
    || fail "Keycloak login request $sequence omitted the password field"
  if grep -Eqi \
    '503 Service Unavailable|504 Gateway|No server is available|identity_provider_unavailable' \
    "$login_body"; then
    fail "Keycloak login request $sequence returned an upstream failure page"
  fi
  [[ -n "$first_login_body" ]] || first_login_body="$login_body"
  [[ -n "$first_cookie_jar" ]] || first_cookie_jar="$cookie_jar"
}

probe_login_assets() {
  local assets_file="$test_dir/assets.txt" path body code asset_count css_count js_count
  grep -Eo '(href|src)="[^"]+"' "$first_login_body" \
    | sed -E 's/^[^=]+="([^"]+)"$/\1/' \
    | grep "^${public_keycloak_prefix}/resources/" \
    | sort -u >"$assets_file" || true
  asset_count="$(wc -l <"$assets_file")"
  css_count="$(grep -Ec '[.]css([?].*)?$' "$assets_file" || true)"
  js_count="$(grep -Ec '[.]js([?].*)?$' "$assets_file" || true)"
  ((10#$asset_count >= 3 && 10#$css_count >= 1 && 10#$js_count >= 1)) \
    || fail "Keycloak login page did not reference the expected CSS and JavaScript assets"
  while IFS= read -r path; do
    body="$test_dir/asset-$(printf '%s' "$path" | sha256sum | awk '{print $1}')"
    code="$(http_code "$body" "${public_base_url}${path}")" \
      || fail "Keycloak login asset request failed: $path"
    [[ "$code" == 200 && -s "$body" ]] \
      || fail "Keycloak login asset is unavailable: $path (HTTP $code)"
  done <"$assets_file"
}

probe_registration_page() {
  local registration_reference registration_url
  local body="$test_dir/registration.html" code
  registration_reference="$(
    grep -Eo 'href="[^"]+/login-actions/registration[^"]*"' "$first_login_body" \
      | head -n 1 \
      | sed -E 's/^href="([^"]+)"$/\1/; s/&amp;/\&/g'
  )" || fail "Keycloak login page omitted the self-registration link"
  case "$registration_reference" in
    "${public_base_url}"/*)
      registration_url="$registration_reference"
      ;;
    /*)
      registration_url="${public_base_url}${registration_reference}"
      ;;
    *)
      fail "Keycloak self-registration link is not same-origin"
      ;;
  esac
  [[ "$registration_url" == "${public_issuer}/login-actions/registration?"* ]] \
    || fail "Keycloak self-registration link is outside the public realm"
  code="$(http_code "$body" \
    --cookie "$first_cookie_jar" \
    --cookie-jar "$first_cookie_jar" \
    "$registration_url")" \
    || fail "Keycloak self-registration request failed"
  [[ "$code" == 200 ]] || fail "Keycloak self-registration returned HTTP $code"
  for field in email firstName lastName password password-confirm; do
    grep -q "name=\"${field}\"" "$body" \
      || fail "Keycloak self-registration omitted the ${field} field"
  done
  if grep -Eqi \
    '503 Service Unavailable|504 Gateway|No server is available|identity_provider_unavailable' \
    "$body"; then
    fail "Keycloak self-registration returned an upstream failure page"
  fi
}

probe_private_edge() {
  local health_body="$test_dir/private-health.body"
  local discovery_body="$test_dir/private-discovery.json" code
  code="$(http_code "$health_body" "${private_edge_url}/health/ready")" \
    || fail "private Keycloak edge health request failed"
  [[ "$code" == 200 ]] || fail "private Keycloak edge health returned HTTP $code"
  code="$(http_code "$discovery_body" "$private_discovery_url")" \
    || fail "private OIDC discovery request failed"
  [[ "$code" == 200 ]] || fail "private OIDC discovery returned HTTP $code"
  assert_json_discovery "$discovery_body" "$private_issuer"
}

probe_device_authorization() {
  local body="$test_dir/device-authorization.json" code
  local expected_verification_uri="${private_issuer}/device"
  code="$(http_code "$body" \
    --header 'Content-Type: application/json' \
    --data '{}' \
    "${agent_gateway_url}/v1/web-ui/auth/device")" \
    || fail "HeteroNetwork device authorization request failed"
  [[ "$code" == 200 ]] || fail "HeteroNetwork device authorization returned HTTP $code"
  jq -e --arg verification_uri "$expected_verification_uri" '
    type == "object"
    and (.handle | type == "string" and test("^[A-Za-z0-9_-]{32,}$"))
    and (.user_code | type == "string" and test("^[A-Z0-9]{4}-[A-Z0-9]{4}$"))
    and .verification_uri == $verification_uri
    and (.verification_uri_complete | type == "string" and startswith($verification_uri + "?user_code="))
    and (.expires_in | type == "number" and floor == . and . >= 60 and . <= 900)
    and (.interval | type == "number" and floor == . and . >= 1 and . <= 30)
  ' "$body" >/dev/null || fail "HeteroNetwork device authorization response is invalid"
}

probe_backend() {
  local backend="$1" sequence="$2"
  local private_body="$test_dir/backend-${sequence}-private.json"
  local public_body="$test_dir/backend-${sequence}-public.json"
  local code private_authority private_scheme private_port
  local public_authority public_scheme public_port
  private_scheme="${private_edge_url%%://*}"
  private_authority="${private_edge_url#*://}"
  if [[ "$private_authority" == *:* ]]; then
    private_port="${private_authority##*:}"
  elif [[ "$private_scheme" == https ]]; then
    private_port=443
  else
    private_port=80
  fi
  public_scheme="${public_base_url%%://*}"
  public_authority="${public_base_url#*://}"
  if [[ "$public_authority" == *:* ]]; then
    public_port="${public_authority##*:}"
  elif [[ "$public_scheme" == https ]]; then
    public_port=443
  else
    public_port=80
  fi

  code="$(http_code "$private_body" \
    --header "Host: ${private_authority}" \
    --header "X-Forwarded-Host: ${private_authority}" \
    --header "X-Forwarded-Proto: ${private_scheme}" \
    --header "X-Forwarded-Port: ${private_port}" \
    "${backend}/realms/${private_realm}/.well-known/openid-configuration")" \
    || fail "private realm probe failed for backend $backend"
  [[ "$code" == 200 ]] || fail "backend $backend private realm returned HTTP $code"
  assert_json_discovery "$private_body" "$private_issuer"

  code="$(http_code "$public_body" \
    --header "Host: ${public_authority}" \
    --header "X-Forwarded-Host: ${public_authority}" \
    --header "X-Forwarded-Proto: ${public_scheme}" \
    --header "X-Forwarded-Port: ${public_port}" \
    "${backend}/realms/${public_realm}/.well-known/openid-configuration")" \
    || fail "public realm probe failed for backend $backend"
  [[ "$code" == 200 ]] || fail "backend $backend public realm returned HTTP $code"
  assert_json_discovery "$public_body" "$public_issuer"
}

if [[ "$check_public" == true ]]; then
  probe_public_discovery
  for ((attempt = 1; attempt <= 10#$attempts; attempt++)); do
    probe_public_login_once "$attempt"
  done
  if [[ "$check_assets" == true ]]; then
    probe_login_assets
  fi
  if [[ "$check_registration" == true ]]; then
    probe_registration_page
  fi
  log "public OIDC login passed ${attempts}/${attempts} attempts"
fi

if [[ "$check_private" == true ]]; then
  probe_private_edge
  if [[ "$check_device_authorization" == true ]]; then
    probe_device_authorization
  fi
  log "private edge and device authorization passed"
fi

if [[ "$check_backends" == true ]]; then
  for index in "${!backend_urls[@]}"; do
    probe_backend "${backend_urls[$index]}" "$((index + 1))"
  done
  if ((${#backend_urls[@]} > 0)); then
    log "direct replica discovery passed ${#backend_urls[@]}/${#backend_urls[@]} backends"
  fi
fi

log 'ok'
