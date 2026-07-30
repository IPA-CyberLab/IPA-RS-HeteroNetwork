#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
node_script="$script_dir/customer-console-node.sh"
unit_path="$repo_root/deploy/systemd/heteronetwork-customer-console.service"
doc_path="$repo_root/docs/CUSTOMER_CONSOLE.md"
route_test="$repo_root/customerui/webconsole-customer-route.test.mjs"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-customer-console-smoke.XXXXXX")"

cleanup() {
  rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'customer console smoke: %s\n' "$*" >&2
  exit 1
}

assert_line() {
  local expected="$1" path="$2"
  grep -Fxq -- "$expected" "$path" \
    || fail "missing expected line '$expected' in $path"
}

assert_contains() {
  local expected="$1" path="$2"
  grep -Fq -- "$expected" "$path" \
    || fail "missing expected content '$expected' in $path"
}

for path in "$node_script" "$unit_path" "$doc_path" "$route_test"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "required file is missing: $path"
done

bash -n "$node_script" "$0"
/usr/bin/node --check "$repo_root/webconsole/server.mjs"
/usr/bin/node --check "$repo_root/customerui/app.js"

plan_path="$test_dir/plan"
env \
  HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL=https://cloud.example.test \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=https://identity.example.test/realms/heteronetwork-customers \
  "$node_script" plan >"$plan_path"

assert_line "mode=dry-run" "$plan_path"
assert_line "console_mode=customer" "$plan_path"
assert_line "operator_environment_fallback=false" "$plan_path"
assert_line "service=heteronetwork-customer-console.service" "$plan_path"
assert_line "service_user=heteronetwork-customer-console" "$plan_path"
assert_line "backend=http://127.0.0.1:28088" "$plan_path"
assert_line "public_url=https://cloud.example.test" "$plan_path"
assert_line "public_paths=/cloud,/v1/customer" "$plan_path"
assert_line "public_tls_termination=required" "$plan_path"
assert_line "customer_api_url=http://127.0.0.1:19881" "$plan_path"
assert_line "issuer=https://identity.example.test/realms/heteronetwork-customers" "$plan_path"
assert_line "oidc_client_id=heteronetwork-customer-console" "$plan_path"
assert_line "oidc_audience=heteronetwork-customer-api" "$plan_path"
assert_line "required_role=heteronetwork-customer" "$plan_path"

launcher_path="$test_dir/customer-console-start"
"$node_script" render-start >"$launcher_path"
assert_contains "exec /usr/bin/env -i" "$launcher_path"
assert_contains "HOST=127.0.0.1" "$launcher_path"
assert_contains "PORT=28088" "$launcher_path"
assert_contains "HETERONETWORK_CONSOLE_MODE=customer" "$launcher_path"
assert_contains \
  "HETERONETWORK_CUSTOMER_OIDC_CLIENT_ID=heteronetwork-customer-console" \
  "$launcher_path"
assert_contains \
  "HETERONETWORK_CUSTOMER_OIDC_AUDIENCE=heteronetwork-customer-api" \
  "$launcher_path"
assert_contains \
  "HETERONETWORK_CUSTOMER_ROLES=heteronetwork-customer" \
  "$launcher_path"
assert_contains 'chmod 0755 "$staged"' "$node_script"
if grep -Eq \
  'HETERONETWORK_WEB_|HETERONETWORK_CONTROL_PLANE_URL|heteronetwork-(admin|operator|viewer)' \
  "$launcher_path"; then
  fail "launcher contains an operator-plane fallback"
fi

for invalid_case in http-public private-public wrong-realm nonloopback-http; do
  case "$invalid_case" in
    http-public)
      invalid_public=https://cloud.example.test
      invalid_public="${invalid_public/https:/http:}"
      invalid_issuer=https://identity.example.test/realms/heteronetwork-customers
      invalid_api=http://127.0.0.1:19881
      ;;
    private-public)
      invalid_public=https://10.250.0.6
      invalid_issuer=https://identity.example.test/realms/heteronetwork-customers
      invalid_api=http://127.0.0.1:19881
      ;;
    wrong-realm)
      invalid_public=https://cloud.example.test
      invalid_issuer=https://identity.example.test/realms/master
      invalid_api=http://127.0.0.1:19881
      ;;
    nonloopback-http)
      invalid_public=https://cloud.example.test
      invalid_issuer=https://identity.example.test/realms/heteronetwork-customers
      invalid_api=http://10.250.0.4:19881
      ;;
  esac
  if env \
    HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL="$invalid_public" \
    HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$invalid_issuer" \
    HETERONETWORK_CUSTOMER_API_URL="$invalid_api" \
    "$node_script" validate-config \
      >"$test_dir/$invalid_case.out" 2>&1; then
    fail "invalid configuration was accepted: $invalid_case"
  fi
done

assert_line "User=heteronetwork-customer-console" "$unit_path"
assert_line "Group=heteronetwork-customer-console" "$unit_path"
assert_line \
  "EnvironmentFile=/etc/heteronetwork/customer-console/customer-console.env" \
  "$unit_path"
assert_line \
  "ExecStart=/opt/heteronetwork/libexec/customer-console-start" \
  "$unit_path"
assert_line "NoNewPrivileges=true" "$unit_path"
assert_line "ProtectSystem=strict" "$unit_path"
assert_line "CapabilityBoundingSet=" "$unit_path"
if grep -Eq 'HETERONETWORK_WEB_|heteronetwork-(admin|operator|viewer)' "$unit_path"; then
  fail "systemd unit contains an operator-plane fallback"
fi

assert_contains '`HETERONETWORK_CONSOLE_MODE=customer`' "$doc_path"
assert_contains '`http://127.0.0.1:19881`' "$doc_path"
assert_contains '`127.0.0.1:19882`' "$doc_path"
assert_contains '`heteronetwork-customer-console`' "$doc_path"
assert_contains '`heteronetwork-customer-api`' "$doc_path"
assert_contains '`heteronetwork-customer`' "$doc_path"
assert_contains "LoadCredential=customer-controller.token:" "$doc_path"
assert_contains "location ^~ /cloud/" "$doc_path"
assert_contains "location ^~ /v1/customer/" "$doc_path"
assert_contains "location / {" "$doc_path"

if command -v systemd-analyze >/dev/null 2>&1; then
  parsed_unit="$test_dir/heteronetwork-customer-console.service"
  sed \
    's#^ExecStart=.*#ExecStart=/bin/true#' \
    "$unit_path" >"$parsed_unit"
  systemd-analyze verify "$parsed_unit"
fi

(cd "$repo_root" && /usr/bin/node --test \
  customerui/webconsole-customer-route.test.mjs)

printf 'Customer console smoke passed.\n'
