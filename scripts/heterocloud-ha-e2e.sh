#!/usr/bin/env bash
set -euo pipefail

umask 077

public_base_url="${HETEROCLOUD_HA_E2E_PUBLIC_BASE_URL:-https://heterocloud.mizuame.app}"
attempts="${HETEROCLOUD_HA_E2E_ATTEMPTS:-20}"
origin_attempts="${HETEROCLOUD_HA_E2E_ORIGIN_ATTEMPTS:-5}"
min_origins="${HETEROCLOUD_HA_E2E_MIN_ORIGINS:-2}"
expected_ready_nodes="${HETEROCLOUD_HA_E2E_EXPECTED_READY_NODES:-0}"
connect_timeout_seconds="${HETEROCLOUD_HA_E2E_CONNECT_TIMEOUT_SECONDS:-5}"
request_timeout_seconds="${HETEROCLOUD_HA_E2E_REQUEST_TIMEOUT_SECONDS:-20}"
kubectl_bin="${KUBECTL:-kubectl}"
gateway_service="${HETEROCLOUD_HA_E2E_GATEWAY_SERVICE:-envoy-gateway-system/envoy-heterocloud-edge-heterocloud-edge-dd522bfb}"
check_kubernetes=true
declare -a origins=()
declare -a deployments=(
  "heterocloud/heterocloud-heterocloud"
  "heterocloud/heterocloud-heterocloud-worker"
  "heterocloud/heterocloud-heterocloud-owner-console"
  "heterocloud-dns/heterocloud-dns"
)

usage() {
  cat <<'EOF'
Usage: heterocloud-ha-e2e.sh [OPTIONS]

Validates the HeteroCloud public path, every published origin, and the
Kubernetes HA state that supplies those origins.

Options:
  --public-base-url URL     Public HeteroCloud URL.
  --origin IP               Expected public origin; repeatable. Kubernetes
                            Service status is used when this is omitted.
  --attempts N              Requests through Cloudflare. Default: 20.
  --origin-attempts N       Requests to each direct origin. Default: 5.
  --min-origins N           Minimum published origin count. Default: 2.
  --expected-ready-nodes N  Require exactly N Ready Kubernetes nodes.
  --gateway-service NS/NAME LoadBalancer Service that publishes HeteroCloud.
  --deployment NS/NAME     Add a Deployment readiness gate; repeatable.
  --skip-default-deployments
                            Remove the built-in HeteroCloud readiness gates.
  --skip-kubernetes         Run only HTTP checks; at least one --origin is
                            then required.
  -h, --help                Show this help.
EOF
}

fail() {
  printf 'HeteroCloud HA E2E: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'HeteroCloud HA E2E: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

valid_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

trim_trailing_slash() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  printf '%s\n' "$value"
}

valid_namespaced_name() {
  [[ "$1" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]]
}

while (($# > 0)); do
  case "$1" in
    --public-base-url)
      (($# >= 2)) || fail "--public-base-url requires a value"
      public_base_url="$2"
      shift 2
      ;;
    --origin)
      (($# >= 2)) || fail "--origin requires a value"
      origins+=("$2")
      shift 2
      ;;
    --attempts)
      (($# >= 2)) || fail "--attempts requires a value"
      attempts="$2"
      shift 2
      ;;
    --origin-attempts)
      (($# >= 2)) || fail "--origin-attempts requires a value"
      origin_attempts="$2"
      shift 2
      ;;
    --min-origins)
      (($# >= 2)) || fail "--min-origins requires a value"
      min_origins="$2"
      shift 2
      ;;
    --expected-ready-nodes)
      (($# >= 2)) || fail "--expected-ready-nodes requires a value"
      expected_ready_nodes="$2"
      shift 2
      ;;
    --gateway-service)
      (($# >= 2)) || fail "--gateway-service requires a value"
      gateway_service="$2"
      shift 2
      ;;
    --deployment)
      (($# >= 2)) || fail "--deployment requires a value"
      deployments+=("$2")
      shift 2
      ;;
    --skip-default-deployments)
      deployments=()
      shift
      ;;
    --skip-kubernetes)
      check_kubernetes=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown option: $1" ;;
  esac
done

require_command curl
require_command jq
require_command awk
require_command cmp
require_command grep
require_command sort

for value_name in attempts origin_attempts min_origins expected_ready_nodes \
  connect_timeout_seconds request_timeout_seconds; do
  value="${!value_name}"
  valid_uint "$value" || fail "$value_name must be an integer"
done
((10#$attempts >= 1 && 10#$attempts <= 1000)) \
  || fail "attempts must be between 1 and 1000"
((10#$origin_attempts >= 1 && 10#$origin_attempts <= 100)) \
  || fail "origin-attempts must be between 1 and 100"
((10#$min_origins >= 1 && 10#$min_origins <= 64)) \
  || fail "min-origins must be between 1 and 64"
((10#$expected_ready_nodes <= 256)) \
  || fail "expected-ready-nodes must be between 0 and 256"
((10#$connect_timeout_seconds >= 1 \
  && 10#$request_timeout_seconds >= 10#$connect_timeout_seconds)) \
  || fail "HTTP timeouts are invalid"

public_base_url="$(trim_trailing_slash "$public_base_url")"
if [[ "$public_base_url" =~ ^(https?)://([A-Za-z0-9.-]+)(:([0-9]+))?$ ]]; then
  public_scheme="${BASH_REMATCH[1]}"
  public_host="${BASH_REMATCH[2]}"
  public_port="${BASH_REMATCH[4]:-}"
else
  fail "public base URL must contain only a scheme and DNS hostname"
fi
if [[ -z "$public_port" ]]; then
  [[ "$public_scheme" == https ]] && public_port=443 || public_port=80
fi

for deployment in "${deployments[@]}"; do
  valid_namespaced_name "$deployment" || fail "invalid Deployment name: $deployment"
done
valid_namespaced_name "$gateway_service" || fail "invalid gateway Service name: $gateway_service"

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/heterocloud-ha-e2e.XXXXXX")"
cleanup() {
  rm -rf "$test_dir"
}
trap cleanup EXIT HUP INT TERM

request() {
  local output="$1" headers="$2" expected="$3"
  shift 3
  local code
  code="$(curl --silent --show-error \
    --connect-timeout "$connect_timeout_seconds" \
    --max-time "$request_timeout_seconds" \
    --dump-header "$headers" \
    --output "$output" \
    --write-out '%{http_code}' \
    "$@")" || fail "request failed: ${*: -1}"
  [[ "$code" == "$expected" ]] \
    || fail "${*: -1} returned HTTP $code, expected $expected"
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
    END { if (value == "") exit 1; print value }
  ' "$path"
}

probe_http_surface() {
  local label="$1" repetitions="$2" origin="${3:-}"
  local -a resolve=()
  local index body headers location discovery issuer
  if [[ -n "$origin" ]]; then
    # Public origins can use a Cloudflare Origin CA certificate that is only
    # trusted by Cloudflare. The aggregate path below still verifies public TLS.
    resolve=(--insecure --resolve "${public_host}:${public_port}:${origin}")
  fi

  for ((index = 1; index <= repetitions; index++)); do
    body="$test_dir/${label}-health-${index}.body"
    headers="$test_dir/${label}-health-${index}.headers"
    request "$body" "$headers" 200 "${resolve[@]}" \
      "$public_base_url/api/v1/health/live"
  done

  body="$test_dir/${label}-root.body"
  headers="$test_dir/${label}-root.headers"
  request "$body" "$headers" 200 "${resolve[@]}" "$public_base_url/"

  body="$test_dir/${label}-oidc.body"
  headers="$test_dir/${label}-oidc.headers"
  request "$body" "$headers" 303 "${resolve[@]}" \
    "$public_base_url/api/v1/auth/oidc/start"
  location="$(header_value location "$headers")" \
    || fail "$label OIDC start did not return Location"
  [[ "$location" == "$public_base_url/id/realms/heterocloud/protocol/openid-connect/auth"* ]] \
    || fail "$label OIDC redirect targets an unexpected issuer: $location"
  grep -Eiq '^set-cookie: .*HttpOnly' "$headers" \
    || fail "$label OIDC start did not set an HttpOnly transaction cookie"

  discovery="$test_dir/${label}-discovery.json"
  headers="$test_dir/${label}-discovery.headers"
  issuer="$public_base_url/id/realms/heterocloud"
  request "$discovery" "$headers" 200 "${resolve[@]}" \
    "$issuer/.well-known/openid-configuration"
  jq -e --arg issuer "$issuer" \
    '.issuer == $issuer
     and (.authorization_endpoint | startswith($issuer + "/"))
     and (.token_endpoint | startswith($issuer + "/"))
     and (.jwks_uri | startswith($issuer + "/"))' \
    "$discovery" >/dev/null \
    || fail "$label OIDC discovery document is invalid"

  body="$test_dir/${label}-login.body"
  headers="$test_dir/${label}-login.headers"
  request "$body" "$headers" 200 "${resolve[@]}" "$location"
  grep -Eq 'name="(username|email)"' "$body" \
    || fail "$label Keycloak login form has no identity field"
  grep -Eq 'name="password"' "$body" \
    || fail "$label Keycloak login form has no password field"
}

if [[ "$check_kubernetes" == true ]]; then
  require_command "$kubectl_bin"
  nodes_json="$test_dir/nodes.json"
  "$kubectl_bin" get nodes -o json >"$nodes_json" \
    || fail "cannot query Kubernetes Nodes"
  not_ready="$(jq -r '
    .items[]
    | select(([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) != 1)
    | .metadata.name
  ' "$nodes_json")"
  [[ -z "$not_ready" ]] \
    || fail "Kubernetes has non-Ready nodes: ${not_ready//$'\n'/, }"
  ready_nodes="$(jq '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length' "$nodes_json")"
  if ((10#$expected_ready_nodes > 0)); then
    ((ready_nodes == 10#$expected_ready_nodes)) \
      || fail "expected $expected_ready_nodes Ready nodes, found $ready_nodes"
  fi

  for deployment in "${deployments[@]}"; do
    namespace="${deployment%%/*}"
    name="${deployment#*/}"
    deployment_json="$test_dir/deployment-${namespace}-${name}.json"
    "$kubectl_bin" -n "$namespace" get deployment "$name" -o json >"$deployment_json" \
      || fail "cannot query Deployment $deployment"
    jq -e '
      (.spec.replicas // 1) > 0
      and (.status.observedGeneration // 0) >= .metadata.generation
      and (.status.readyReplicas // 0) == (.spec.replicas // 1)
      and (.status.availableReplicas // 0) == (.spec.replicas // 1)
      and (.status.unavailableReplicas // 0) == 0
    ' "$deployment_json" >/dev/null \
      || fail "Deployment $deployment is not fully Ready"
  done

  gateway_namespace="${gateway_service%%/*}"
  gateway_name="${gateway_service#*/}"
  gateway_json="$test_dir/gateway-service.json"
  "$kubectl_bin" -n "$gateway_namespace" get service "$gateway_name" -o json >"$gateway_json" \
    || fail "cannot query gateway Service $gateway_service"
  mapfile -t service_origins < <(jq -r '.status.loadBalancer.ingress[]?.ip // empty' "$gateway_json" | sort -u)
  ((${#service_origins[@]} >= 10#$min_origins)) \
    || fail "gateway publishes ${#service_origins[@]} origins; minimum is $min_origins"

  ready_public_ips="$test_dir/ready-public-ips"
  jq -r '
    .items[]
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
    | select(.metadata.labels["networking.heteronetwork.io/public-ingress"] == "true")
    | .metadata.annotations["networking.heteronetwork.io/public-ip"] // empty
  ' "$nodes_json" | sort -u >"$ready_public_ips"
  for origin in "${service_origins[@]}"; do
    grep -Fxq "$origin" "$ready_public_ips" \
      || fail "gateway publishes $origin but no Ready public-ingress Node owns it"
  done

  if ((${#origins[@]} == 0)); then
    origins=("${service_origins[@]}")
  else
    supplied="$test_dir/supplied-origins"
    published="$test_dir/published-origins"
    printf '%s\n' "${origins[@]}" | sort -u >"$supplied"
    printf '%s\n' "${service_origins[@]}" | sort -u >"$published"
    cmp -s "$supplied" "$published" \
      || fail "supplied origins do not exactly match gateway Service status"
  fi
  log "Kubernetes HA state passed: Ready nodes=$ready_nodes, origins=${#origins[@]}"
elif ((${#origins[@]} == 0)); then
  fail "--skip-kubernetes requires at least one --origin"
fi

for origin in "${origins[@]}"; do
  [[ "$origin" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] \
    || fail "origin is not an IPv4 address: $origin"
done
mapfile -t origins < <(printf '%s\n' "${origins[@]}" | sort -u)
((${#origins[@]} >= 10#$min_origins)) \
  || fail "only ${#origins[@]} direct origins were supplied; minimum is $min_origins"

for origin in "${origins[@]}"; do
  probe_http_surface "origin-${origin//./-}" "$origin_attempts" "$origin"
  log "direct origin $origin passed $origin_attempts health attempts and OIDC"
done

probe_http_surface cloudflare "$attempts"
log "Cloudflare path passed $attempts health attempts and full OIDC"
log "all HA checks passed"
