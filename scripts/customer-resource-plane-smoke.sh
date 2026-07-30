#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
node_script="$script_dir/customer-resource-plane-node.sh"
template="$repo_root/deploy/systemd/heteronetwork-customer-resource-plane.conf"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-customer-resource-plane.XXXXXX")"

cleanup() {
  rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'customer resource-plane smoke: %s\n' "$*" >&2
  exit 1
}

assert_line() {
  local expected="$1" path="$2"
  grep -Fxq -- "$expected" "$path" \
    || fail "missing expected line '$expected' in $path"
}

assert_mode() {
  local expected="$1" path="$2"
  [[ "$(stat -c '%a' -- "$path")" == "$expected" ]] \
    || fail "unexpected mode for $path"
}

for path in "$node_script" "$template"; do
  [[ -f "$path" && ! -L "$path" ]] \
    || fail "required file is missing: $path"
done

bash -n "$node_script" "$0"

bundle="$test_dir/token-bundle"
"$node_script" init-token "$bundle" >"$test_dir/init.out"
token_file="$bundle/customer-controller.token"
[[ -f "$token_file" && ! -L "$token_file" ]] \
  || fail "init-token did not create a regular token file"
assert_mode 700 "$bundle"
assert_mode 400 "$token_file"
[[ "$(stat -c '%h' -- "$token_file")" == "1" ]] \
  || fail "generated token has an unsafe hard-link count"
token="$(tr -d '\n' <"$token_file")"
[[ "$token" =~ ^[0-9a-f]{64}$ ]] \
  || fail "init-token did not generate 256 bits encoded as lowercase hex"
token_inode="$(stat -c '%i' -- "$token_file")"
token_digest="$(sha256sum "$token_file" | awk '{print $1}')"
"$node_script" init-token "$bundle" >"$test_dir/init-again.out"
[[ "$(stat -c '%i' -- "$token_file")" == "$token_inode" \
  && "$(sha256sum "$token_file" | awk '{print $1}')" == "$token_digest" ]] \
  || fail "init-token overwrote an existing token"

issuer="https://identity.customer.example.com/realms/heteronetwork-customers"
controller_listen="10.250.0.4:19882"
backchannel="http://127.0.0.1:28080/realms/heteronetwork-customers"
fallbacks="http://10.250.0.5:28080/realms/heteronetwork-customers,http://10.250.0.6:28080/realms/heteronetwork-customers"

run_node() {
  env \
    PATH="$fake_bin:/usr/bin:/bin" \
    HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TESTING=1 \
    HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TEST_ROOT="$fake_root" \
    HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
    HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
    HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL="$backchannel" \
    HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS="$fallbacks" \
    HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE="$bundle" \
    HETERONETWORK_SMOKE_STATE="$fake_state" \
    HETERONETWORK_SMOKE_SYSTEMCTL_LOG="$systemctl_log" \
    "$node_script" "$@"
}

fake_root="$test_dir/root"
fake_bin="$test_dir/bin"
fake_state="$test_dir/state"
systemctl_log="$test_dir/systemctl.log"
mkdir -p "$fake_root" "$fake_bin" "$fake_state/active"
: >"$systemctl_log"
: >"$fake_state/active/heteronetwork-control-plane.service"

cat >"$fake_bin/id" <<'EOF'
#!/bin/sh
if [ "${1-}" = "-u" ]; then
  printf '0\n'
  exit 0
fi
exec /usr/bin/id "$@"
EOF

cat >"$fake_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"
command_name=${1-}
shift || true
case "$command_name" in
  show)
    if [ -e "$HETERONETWORK_SMOKE_STATE/unloaded" ]; then
      printf 'not-found\n'
    else
      printf 'loaded\n'
    fi
    ;;
  is-active)
    quiet=false
    while [ "${1-}" = "--quiet" ]; do
      quiet=true
      shift
    done
    unit=${1-}
    if [ -e "$HETERONETWORK_SMOKE_STATE/active/$unit" ]; then
      if [ "$quiet" = false ]; then
        printf 'active\n'
      fi
      exit 0
    fi
    if [ "$quiet" = false ]; then
      printf 'inactive\n'
    fi
    exit 3
    ;;
  restart)
    : >"$HETERONETWORK_SMOKE_STATE/active/${1-}"
    ;;
  daemon-reload)
    ;;
  *)
    exit 1
    ;;
esac
EOF
chmod 0755 "$fake_bin/id" "$fake_bin/systemctl"

plan="$test_dir/plan"
run_node plan >"$plan"
assert_line "mode=dry-run" "$plan"
assert_line "service=heteronetwork-control-plane.service" "$plan"
assert_line "customer_api_enabled=true" "$plan"
assert_line "customer_api_listen=127.0.0.1:19881" "$plan"
assert_line "customer_controller_listen=$controller_listen" "$plan"
assert_line "customer_oidc_issuer=$issuer" "$plan"
assert_line "customer_oidc_client_id=heteronetwork-customer-console" "$plan"
assert_line "customer_oidc_audience=heteronetwork-customer-api" "$plan"
assert_line "customer_oidc_required_role=heteronetwork-customer" "$plan"
assert_line "customer_oidc_backchannel_configured=true" "$plan"
assert_line "customer_oidc_fallback_count=2" "$plan"
assert_line "controller_token=validated-redacted" "$plan"
if grep -Fq -- "$token" "$plan"; then
  fail "plan disclosed the controller token"
fi

run_node validate-config >"$test_dir/validate.out"
env \
  PATH="$fake_bin:/usr/bin:/bin" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TESTING=1 \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TEST_ROOT="$fake_root" \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE="$token_file" \
  "$node_script" validate-config >"$test_dir/validate-direct-file.out"

invalid_config() {
  local label="$1" invalid_issuer="$2" invalid_listen="$3"
  local invalid_backchannel="$4" invalid_fallbacks="$5"
  if env \
    PATH="$fake_bin:/usr/bin:/bin" \
    HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TESTING=1 \
    HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TEST_ROOT="$fake_root" \
    HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$invalid_issuer" \
    HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$invalid_listen" \
    HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL="$invalid_backchannel" \
    HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS="$invalid_fallbacks" \
    HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE="$bundle" \
    "$node_script" validate-config >"$test_dir/invalid-$label.out" 2>&1; then
    fail "invalid configuration was accepted: $label"
  fi
}

invalid_config http-issuer \
  "http://identity.customer.example.com/realms/heteronetwork-customers" \
  "$controller_listen" "$backchannel" "$fallbacks"
invalid_config wrong-realm \
  "https://identity.customer.example.com/realms/heteronetwork" \
  "$controller_listen" "$backchannel" "$fallbacks"
invalid_config loopback-listen "$issuer" "127.0.0.1:19882" \
  "$backchannel" "$fallbacks"
invalid_config public-listen "$issuer" "203.0.113.10:19882" \
  "$backchannel" "$fallbacks"
invalid_config operator-fallback "$issuer" "$controller_listen" \
  "$backchannel" "http://10.250.0.5:18080/realms/heteronetwork"

unsafe="$test_dir/unsafe"
mkdir -m 0700 "$unsafe"
printf 'too-short\n' >"$unsafe/weak.token"
chmod 0400 "$unsafe/weak.token"
if env \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE="$unsafe/weak.token" \
  "$node_script" validate-config >"$test_dir/unsafe-weak.out" 2>&1; then
  fail "short token was accepted"
fi

printf '%s\n' "$token" >"$unsafe/weak-permissions.token"
chmod 0644 "$unsafe/weak-permissions.token"
if env \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE="$unsafe/weak-permissions.token" \
  "$node_script" validate-config >"$test_dir/unsafe-permissions.out" 2>&1; then
  fail "group/world-readable token was accepted"
fi

ln -s "$token_file" "$unsafe/symlink.token"
if env \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE="$unsafe/symlink.token" \
  "$node_script" validate-config >"$test_dir/unsafe-symlink.out" 2>&1; then
  fail "symlink token was accepted"
fi

cp "$token_file" "$unsafe/hardlink.token"
chmod 0400 "$unsafe/hardlink.token"
ln "$unsafe/hardlink.token" "$unsafe/hardlink-alias.token"
if env \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE="$unsafe/hardlink.token" \
  "$node_script" validate-config >"$test_dir/unsafe-hardlink.out" 2>&1; then
  fail "hard-linked token was accepted"
fi

install_output="$test_dir/install.out"
run_node install >"$install_output" 2>&1
config_dir="$fake_root/etc/heteronetwork/customer-resource-plane"
env_file="$config_dir/customer-resource-plane.env"
installed_token="$config_dir/customer-controller.token"
drop_in="$fake_root/etc/systemd/system/heteronetwork-control-plane.service.d/40-customer-resource-plane.conf"

for path in "$env_file" "$installed_token" "$drop_in"; do
  [[ -f "$path" && ! -L "$path" ]] \
    || fail "install did not create a safe regular file: $path"
  [[ "$(stat -c '%h' -- "$path")" == "1" ]] \
    || fail "installed file has an unsafe hard-link count: $path"
done
assert_mode 700 "$config_dir"
assert_mode 600 "$env_file"
assert_mode 400 "$installed_token"
assert_mode 644 "$drop_in"
cmp -s "$installed_token" "$token_file" \
  || fail "installed token differs from the source bundle"
[[ "$(stat -c '%i' -- "$installed_token")" != "$token_inode" ]] \
  || fail "installed token is linked to the source bundle"
cmp -s "$drop_in" "$template" \
  || fail "installed drop-in differs from its template"

expected_env="$test_dir/expected.env"
cat >"$expected_env" <<EOF
HETERONETWORK_CUSTOMER_API_ENABLED=true
HETERONETWORK_CUSTOMER_API_LISTEN=127.0.0.1:19881
HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN=$controller_listen
HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=$issuer
HETERONETWORK_CUSTOMER_OIDC_CLIENT_ID=heteronetwork-customer-console
HETERONETWORK_CUSTOMER_OIDC_AUDIENCE=heteronetwork-customer-api
HETERONETWORK_CUSTOMER_OIDC_REQUIRED_ROLE=heteronetwork-customer
HETERONETWORK_CUSTOMER_OIDC_SCOPES=openid profile email
HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL=$backchannel
HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS=$fallbacks
EOF
cmp -s "$env_file" "$expected_env" \
  || fail "installed environment does not match the fixed contract"
grep -Fxq "daemon-reload" "$systemctl_log" \
  || fail "install did not reload systemd"
grep -Fxq "restart heteronetwork-control-plane.service" "$systemctl_log" \
  || fail "install did not restart the active Control Plane"
if grep -Fq -- "$token" "$install_output" \
  || grep -Fq -- "$token" "$systemctl_log"; then
  fail "install disclosed the controller token"
fi

run_node install >"$test_dir/reinstall.out" 2>&1
cmp -s "$installed_token" "$token_file" \
  || fail "idempotent install changed the token"

other_bundle="$test_dir/other-token-bundle"
"$node_script" init-token "$other_bundle" >/dev/null
if env \
  PATH="$fake_bin:/usr/bin:/bin" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TESTING=1 \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TEST_ROOT="$fake_root" \
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL="$issuer" \
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN="$controller_listen" \
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE="$other_bundle" \
  HETERONETWORK_SMOKE_STATE="$fake_state" \
  HETERONETWORK_SMOKE_SYSTEMCTL_LOG="$systemctl_log" \
  "$node_script" install >"$test_dir/mismatched-token.out" 2>&1; then
  fail "install accepted a different token over an existing replica token"
fi
cmp -s "$installed_token" "$token_file" \
  || fail "failed token rotation changed the installed token"

status="$test_dir/status"
run_node status >"$status"
assert_line "load_state=loaded" "$status"
assert_line "active_state=active" "$status"
assert_line "customer_resource_plane_installed=true" "$status"
assert_line "installed_files_secure=true" "$status"

source_before_disable="$(sha256sum "$token_file" | awk '{print $1}')"
run_node disable >"$test_dir/disable.out" 2>&1
[[ ! -e "$env_file" && ! -e "$installed_token" && ! -e "$drop_in" ]] \
  || fail "disable left installed resource-plane files behind"
[[ -f "$token_file" \
  && "$(sha256sum "$token_file" | awk '{print $1}')" == "$source_before_disable" ]] \
  || fail "disable changed the source token bundle"
[[ "$(grep -Fxc "daemon-reload" "$systemctl_log")" -ge 2 ]] \
  || fail "disable did not reload systemd"

rm -f "$fake_state/active/heteronetwork-control-plane.service"
: >"$systemctl_log"
run_node install >"$test_dir/inactive-install.out" 2>&1
grep -Fxq "daemon-reload" "$systemctl_log" \
  || fail "inactive install did not reload systemd"
if grep -Fxq "restart heteronetwork-control-plane.service" "$systemctl_log"; then
  fail "inactive install restarted the Control Plane"
fi
run_node disable >"$test_dir/inactive-disable.out" 2>&1
if grep -Fxq "restart heteronetwork-control-plane.service" "$systemctl_log"; then
  fail "inactive disable restarted the Control Plane"
fi

: >"$fake_state/unloaded"
if run_node install >"$test_dir/unloaded.out" 2>&1; then
  fail "install accepted an unloaded Control Plane service"
fi
rm -f "$fake_state/unloaded"

printf 'Customer resource-plane smoke passed.\n'
