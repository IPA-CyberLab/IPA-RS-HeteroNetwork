#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
node_script="$script_dir/customer-keycloak-node.sh"
bootstrap_script="$script_dir/customer-keycloak-bootstrap.sh"
systemd_dir="$script_dir/../deploy/systemd"
doc_path="$script_dir/../docs/CUSTOMER_KEYCLOAK.md"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-customer-keycloak-smoke.XXXXXX")"

cleanup() {
  rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'customer Keycloak smoke: %s\n' "$*" >&2
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

for path in "$node_script" "$bootstrap_script"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "script is missing: $path"
  bash -n "$path"
done

plan_path="$test_dir/plan"
env \
  HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=https://identity.example.test/realms/heteronetwork-customers \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS=10.250.0.21 \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=https://console.example.test/cloud/callback \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=https://console.example.test \
  "$node_script" plan >"$plan_path"

assert_line "mode=dry-run" "$plan_path"
assert_line "identity_plane=customer" "$plan_path"
assert_line "operator_identity_plane_mutated=false" "$plan_path"
assert_line "database=heteronetwork_customer_identity" "$plan_path"
assert_line "database_role=heteronetwork_customer_identity" "$plan_path"
assert_line "database_schema=customer_identity" "$plan_path"
assert_line "realm=heteronetwork-customers" "$plan_path"
assert_line "backend=http://127.0.0.1:28080" "$plan_path"
assert_line "management=http://127.0.0.1:29000" "$plan_path"
assert_line "cache_bind=10.250.0.21:27800" "$plan_path"
assert_line "public_tls_termination=required" "$plan_path"
assert_line "token_authorized_party=heteronetwork-customer-console" "$plan_path"
assert_line "token_audience=heteronetwork-customer-api" "$plan_path"
assert_line "realm_roles=heteronetwork-customer,org-admin" "$plan_path"
if grep -Fxq "service=heteronetwork-keycloak.service" "$plan_path"; then
  fail "dry-run selected the operator Keycloak service"
fi

if env \
  HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=http://identity.example.test/realms/heteronetwork-customers \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS=10.250.0.21 \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=https://console.example.test/cloud/callback \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=https://console.example.test \
  "$node_script" plan >"$test_dir/invalid-http.out" 2>&1; then
  fail "HTTP customer issuer was accepted"
fi

if env \
  HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=https://10.250.0.1/realms/heteronetwork-customers \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS=10.250.0.21 \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=https://console.example.test/cloud/callback \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=https://console.example.test \
  "$node_script" plan >"$test_dir/invalid-private.out" 2>&1; then
  fail "private customer issuer was accepted"
fi

if env \
  HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=https://identity.example.test/realms/heteronetwork-customers \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS=10.250.0.21 \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=https://console.example.test/\* \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=https://console.example.test \
  "$node_script" plan >"$test_dir/invalid-wildcard.out" 2>&1; then
  fail "wildcard customer callback was accepted"
fi

manifest_path="$test_dir/manifest.json"
env \
  HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=https://identity.example.test/realms/heteronetwork-customers \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=https://console.example.test/cloud/callback \
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=https://console.example.test \
  "$bootstrap_script" render >"$manifest_path"

jq -e '
  .realm.realm == "heteronetwork-customers"
  and .realm.sslRequired == "external"
  and .realm.registrationAllowed == false
  and .defaultRoles == ["heteronetwork-customer"]
  and (.roles | map(.name) == ["heteronetwork-customer", "org-admin"])
  and (.roles[1] | has("composites") | not)
  and (.clients | map(.clientId) == [
    "heteronetwork-customer-console",
    "heteronetwork-customer-api"
  ])
  and .clients[0].publicClient == true
  and .clients[0].standardFlowEnabled == true
  and .clients[0].directAccessGrantsEnabled == false
  and .clients[0].attributes["pkce.code.challenge.method"] == "S256"
  and .clients[1].bearerOnly == true
  and .protocolMappers[0].config["included.client.audience"]
    == "heteronetwork-customer-api"
  and .tokenContract.authorizedParty == "heteronetwork-customer-console"
  and .tokenContract.audience == "heteronetwork-customer-api"
  and .tokenContract.authorizedParty != .tokenContract.audience
  and .tokenContract.requiredApplicationRole == "heteronetwork-customer"
  and .tokenContract.organizationModifierRole == "org-admin"
' "$manifest_path" >/dev/null \
  || fail "rendered customer realm contract is invalid"

if jq -e '
  [
    .roles[].name,
    .defaultRoles[],
    .clients[].clientId
  ] | any(
    . == "heteronetwork-admin"
    or . == "heteronetwork-operator"
    or . == "heteronetwork-viewer"
  )
' "$manifest_path" >/dev/null; then
  fail "rendered customer realm grants an operator role"
fi

"$bootstrap_script" self-test >/dev/null

for unit in \
  heteronetwork-customer-keycloak-database.service \
  heteronetwork-customer-keycloak.service \
  heteronetwork-customer-keycloak-bootstrap.service; do
  [[ -f "$systemd_dir/$unit" && ! -L "$systemd_dir/$unit" ]] \
    || fail "systemd unit is missing: $unit"
done
assert_contains \
  "ExecStart=/opt/heteronetwork/libexec/customer-keycloak-node.sh provision-database" \
  "$systemd_dir/heteronetwork-customer-keycloak-database.service"
assert_contains \
  "ExecStart=/opt/heteronetwork/libexec/customer-keycloak-start" \
  "$systemd_dir/heteronetwork-customer-keycloak.service"
assert_contains \
  "LoadCredential=db-password:/etc/heteronetwork/customer-keycloak/secrets/db.password" \
  "$systemd_dir/heteronetwork-customer-keycloak.service"
assert_contains \
  "ExecStart=/opt/heteronetwork/libexec/customer-keycloak-bootstrap.sh apply" \
  "$systemd_dir/heteronetwork-customer-keycloak-bootstrap.service"

assert_contains \
  "hashtextextended('heteronetwork-customer-keycloak-database-v1', 0)" \
  "$node_script"
assert_contains \
  "CREATE DATABASE heteronetwork_customer_identity OWNER heteronetwork_customer_identity" \
  "$node_script"
assert_contains \
  "CREATE SCHEMA IF NOT EXISTS customer_identity" \
  "$node_script"
if grep -Fq \
  "ALTER ROLE heteronetwork_customer_identity PASSWORD" \
  "$node_script"; then
  fail "idempotent provisioning would rotate an existing database password"
fi
assert_contains \
  "refusing to replace installed customer secret" \
  "$node_script"
assert_contains \
  'verify_role_has_no_composites "$ORG_ADMIN_ROLE"' \
  "$bootstrap_script"
if grep -Fq \
  'ensure_role_composite "$ORG_ADMIN_ROLE"' \
  "$bootstrap_script"; then
  fail "org-admin was configured as a global application composite"
fi
assert_contains "The customer installer never reads or writes the operator Keycloak" \
  "$doc_path"
assert_contains "public customer services must never accept tokens from the private operator" \
  "$doc_path"

if command -v systemd-analyze >/dev/null 2>&1; then
  verification_path="$test_dir/systemd-verify"
  systemd-analyze verify \
    "$systemd_dir/heteronetwork-customer-keycloak-database.service" \
    "$systemd_dir/heteronetwork-customer-keycloak.service" \
    "$systemd_dir/heteronetwork-customer-keycloak-bootstrap.service" \
    >"$verification_path" 2>&1 || true
  if grep -Ei \
    'unknown (key|lvalue)|missing[[:space:]]*=|failed to parse|invalid section' \
    "$verification_path" >/dev/null; then
    cat "$verification_path" >&2
    fail "systemd unit syntax validation failed"
  fi
fi

printf 'Customer Keycloak shell smoke passed.\n'
