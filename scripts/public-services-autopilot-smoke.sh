#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
autopilot=$script_dir/public-services-autopilot.sh
control_plane_unit=$script_dir/../deploy/systemd/heteronetwork-control-plane.service
test_root=$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-public-services-smoke.XXXXXX")
fake_bin=$test_root/fake-bin
fake_state=$test_root/fake-state
fixture=$test_root/status.json
relay_fixture=$test_root/relay-status.json
gateway_fixture=$test_root/gateway-status.json
systemctl_log=$test_root/systemctl.log
output_log=$test_root/output.log
secret='DatabaseSecret_DoNotPrint_473921'
database_autopilot_token='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
keycloak_autopilot_token='fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'

cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf '%s\n' "public-services autopilot smoke: $*" >&2
  exit 1
}

mkdir -p "$fake_bin" "$fake_state/active"

cat >"$fake_bin/curl" <<'EOF'
#!/bin/sh
last_argument=
for last_argument do :; done
case "$last_argument" in
  http://127.0.0.1:9780/v1/status)
    cat "$HETERONETWORK_SMOKE_STATUS_FIXTURE"
    ;;
  http://127.0.0.1:9780/v1/web-ui/endpoints)
    cat "$HETERONETWORK_SMOKE_GATEWAY_STATUS_FIXTURE"
    ;;
  http://*/v1/status)
    cat "$HETERONETWORK_SMOKE_RELAY_STATUS_FIXTURE"
    ;;
  *)
    exit 1
    ;;
esac
EOF

cat >"$fake_bin/pg_isready" <<'EOF'
#!/bin/sh
[ ! -e "$HETERONETWORK_SMOKE_STATE/postgres-down" ]
EOF

cat >"$fake_bin/chown" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$fake_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu

command_name=${1-}
shift || true
printf '%s' "$command_name" >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"
for argument do
  printf ' %s' "$argument" >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"
done
printf '\n' >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"

case "$command_name" in
  show)
    unit_name=${1-}
    property=
    for argument do
      case "$argument" in
        --property=*) property=${argument#--property=} ;;
      esac
    done
    case "$property" in
      LoadState) printf 'loaded\n' ;;
      User|Group) printf 'heteronetwork-services\n' ;;
      ActiveState)
        if [ -e "$HETERONETWORK_SMOKE_STATE/active/$unit_name" ]; then
          printf 'active\n'
        else
          printf 'inactive\n'
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  is-active)
    [ "${1-}" = --quiet ] && shift
    [ -e "$HETERONETWORK_SMOKE_STATE/active/${1-}" ]
    ;;
  start|restart)
    while [ "${1-}" = --no-block ]; do
      shift
    done
    unit_name=${1-}
    if [ -e "$HETERONETWORK_SMOKE_STATE/fail-$command_name-$unit_name" ]; then
      exit 1
    fi
    : >"$HETERONETWORK_SMOKE_STATE/active/$unit_name"
    ;;
  stop|kill)
    if [ "$command_name" = kill ]; then
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --*) shift ;;
          *) break ;;
        esac
      done
    fi
    rm -f "$HETERONETWORK_SMOKE_STATE/active/${1-}"
    ;;
  daemon-reload) ;;
  *) exit 1 ;;
esac
EOF

chmod 0755 "$fake_bin/curl" "$fake_bin/pg_isready" \
  "$fake_bin/chown" "$fake_bin/systemctl"

export PATH=$fake_bin:/usr/bin:/bin
export HETERONETWORK_PUBLIC_SERVICES_TESTING=1
export HETERONETWORK_PUBLIC_SERVICES_TEST_ROOT=$test_root/root
export HETERONETWORK_SMOKE_STATUS_FIXTURE=$fixture
export HETERONETWORK_SMOKE_RELAY_STATUS_FIXTURE=$relay_fixture
export HETERONETWORK_SMOKE_GATEWAY_STATUS_FIXTURE=$gateway_fixture
export HETERONETWORK_SMOKE_STATE=$fake_state
export HETERONETWORK_SMOKE_SYSTEMCTL_LOG=$systemctl_log

public_services_dir=$test_root/root/etc/heteronetwork/public-services
password_file=$test_root/root/etc/heteronetwork/postgres-autopilot/bundle/secrets/application.password
ca_file=$test_root/root/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt
services_env=$public_services_dir/services.env
database_url=$public_services_dir/database-url
database_autopilot_token_file=$public_services_dir/database-autopilot.token
keycloak_autopilot_token_file=$public_services_dir/keycloak-autopilot.token
agent_drop_in=$test_root/root/etc/systemd/system/heteronetwork-agent.service.d/30-public-services.conf

b64() {
  printf '%s' "$1" | base64 | tr -d '\r\n'
}

root_public_key=$(printf 'root-public-key-material-0000000000' | head -c 32 | base64 | tr -d '\r\n')
trusted_public_key=$(printf 'trusted-public-key-material-000000' | head -c 32 | base64 | tr -d '\r\n')
enrollment_public_key=$(printf 'enroll-public-key-material-0000000' | head -c 32 | base64 | tr -d '\r\n')
rotation_public_key=$(printf 'rotate-public-key-material-0000000' | head -c 32 | base64 | tr -d '\r\n')

mkdir -p "$public_services_dir"
cat >"$public_services_dir/bootstrap.env" <<EOF
HETERONETWORK_PUBLIC_SERVICES_CLUSTER_ID_B64=$(b64 cluster-smoke)
HETERONETWORK_PUBLIC_SERVICES_VPN_POOL_B64=$(b64 10.250.0.0/16)
HETERONETWORK_PUBLIC_SERVICES_ISSUER_NODE_ID_B64=$(b64 issuer-root)
HETERONETWORK_PUBLIC_SERVICES_ISSUER_KEY_ID_B64=$(b64 root)
HETERONETWORK_PUBLIC_SERVICES_ISSUER_PUBLIC_KEY_B64=$(b64 "$root_public_key")
HETERONETWORK_PUBLIC_SERVICES_TRUSTED_ISSUER_KEYS_B64=$(b64 "issuer-next,root-next,$trusted_public_key")
HETERONETWORK_PUBLIC_SERVICES_ENROLLMENT_TRUSTED_ISSUER_KEY_B64=$(b64 "issuer-enrollment,web-enrollment,$enrollment_public_key,604800;issuer-rotation,web-rotation,$rotation_public_key,2592000")
HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64=$(b64 https://sso.example/realms/heteronetwork)
HETERONETWORK_PUBLIC_SERVICES_OIDC_CLIENT_ID_B64=$(b64 heteronetwork-web)
HETERONETWORK_PUBLIC_SERVICES_OIDC_AUTH_BASE_URL_B64=$(b64 '')
HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_BASE_URL_B64=$(b64 http://127.0.0.1:18080/realms/heteronetwork)
HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64=$(b64 '')
HETERONETWORK_PUBLIC_SERVICES_OIDC_SCOPES_B64=$(b64 'openid profile email')
HETERONETWORK_PUBLIC_SERVICES_CONTROL_PLANE_URLS_B64=$(b64 'https://seed-a.example,https://seed-b.example')
HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN=$database_autopilot_token
HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=$keycloak_autopilot_token
HETERONETWORK_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS=15
HETERONETWORK_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS=45
EOF
chmod 0600 "$public_services_dir/bootstrap.env"

write_status() {
  status_state=$1
  status_assessed_at=$2
  status_local_addr=${3:-163.220.236.51:51820}
  cat >"$fixture" <<EOF
{
  "node_id": "node-0e1c0dadf2fab64e23dfe42c9a073f1b",
  "vpn_ip": "10.250.0.4",
  "nat_classification": {
    "connectivity_state": "$status_state",
    "mapping_behavior": "no_nat",
    "strategy": "direct_candidate",
    "local_addr": "$status_local_addr",
    "observed_endpoint": "$status_local_addr",
    "assessed_at": "$status_assessed_at",
    "observations": [
      {
        "local_addr": "$status_local_addr",
        "reflexive_addr": "$status_local_addr"
      },
      {
        "local_addr": "$status_local_addr",
        "reflexive_addr": "$status_local_addr"
      }
    ]
  }
}
EOF
}

write_relay_status() {
  relay_status_endpoint=$1
  relay_status_health=${2:-healthy}
  cat >"$relay_fixture" <<EOF
{
  "relay_node": "node-0e1c0dadf2fab64e23dfe42c9a073f1b",
  "health": "$relay_status_health",
  "capability": {
    "enabled_by_policy": true,
    "public_endpoint": "$relay_status_endpoint",
    "admission_url": "http://10.250.0.4:18447"
  }
}
EOF
}

write_gateway_status() {
  gateway_status_ip=$1
  gateway_status_phase=${2:-ready}
  case "$gateway_status_ip" in
    *:*) gateway_status_host="[$gateway_status_ip]" ;;
    *) gateway_status_host=$gateway_status_ip ;;
  esac
  cat >"$gateway_fixture" <<EOF
{
  "public_gateway": {
    "phase": "$gateway_status_phase",
    "public_ip": "$gateway_status_ip",
    "url": "https://$gateway_status_host/"
  }
}
EOF
}

set_active() {
  : >"$fake_state/active/$1"
}

set_inactive() {
  rm -f "$fake_state/active/$1"
}

prepare_dependencies() {
  dependency_relay_endpoint=${1:-163.220.236.51:18445}
  mkdir -p "$(dirname "$password_file")" "$(dirname "$ca_file")"
  printf '%s\n' "$secret" >"$password_file"
  printf '%s\n' 'test-ca' >"$ca_file"
  write_relay_status "$dependency_relay_endpoint"
  write_gateway_status 163.220.236.51
  rm -f "$fake_state/postgres-down"
  set_active heteronetwork-agent.service
  set_active heteronetwork-gateway.service
  set_active heteronetwork-relay.service
}

reset_auto_services() {
  set_inactive heteronetwork-control-plane.service
  set_inactive heteronetwork-signal.service
  set_inactive heteronetwork-stun.service
  rm -f \
    "$services_env" \
    "$database_url" \
    "$database_autopilot_token_file" \
    "$keycloak_autopilot_token_file" \
    "$agent_drop_in"
}

run_reconciler() {
  : >"$systemctl_log"
  if ! sh "$autopilot" >>"$output_log" 2>&1; then
    fail "reconciler invocation failed"
  fi
}

assert_active() {
  [ -e "$fake_state/active/$1" ] || fail "$1 is not active"
}

assert_inactive() {
  [ ! -e "$fake_state/active/$1" ] || fail "$1 is still active"
}

assert_demoted() {
  assert_inactive heteronetwork-control-plane.service
  assert_inactive heteronetwork-signal.service
  assert_inactive heteronetwork-stun.service
  [ ! -e "$services_env" ] || fail "service environment survived demotion"
  [ ! -e "$database_url" ] || fail "database URL survived demotion"
  { [ ! -e "$database_autopilot_token_file" ] &&
    [ ! -L "$database_autopilot_token_file" ]; } ||
    fail "database autopilot credential survived demotion"
  { [ ! -e "$keycloak_autopilot_token_file" ] &&
    [ ! -L "$keycloak_autopilot_token_file" ]; } ||
    fail "Keycloak autopilot credential survived demotion"
  [ ! -e "$agent_drop_in" ] || fail "Agent routes survived demotion"
}

fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
prepare_dependencies
reset_auto_services
write_status public "$fresh_time"
run_reconciler

grep -q '^restart --no-block heteronetwork-agent.service$' "$systemctl_log" ||
  fail "initial promotion did not defer the Agent restart"
[ -f "$agent_drop_in" ] ||
  fail "deferred Agent activation rolled back the staged routes"
[ "$(grep -c 'restart .*heteronetwork-agent.service$' "$systemctl_log")" -eq 1 ] ||
  fail "deferred Agent activation triggered a restart loop"
assert_inactive heteronetwork-signal.service
assert_inactive heteronetwork-stun.service
assert_inactive heteronetwork-control-plane.service
run_reconciler

[ -f "$services_env" ] || fail "service environment was not generated"
[ -f "$database_url" ] || fail "database URL was not generated"
[ -f "$database_autopilot_token_file" ] ||
  fail "database autopilot credential was not generated"
[ -f "$keycloak_autopilot_token_file" ] ||
  fail "Keycloak autopilot credential was not generated"
[ -f "$agent_drop_in" ] || fail "Agent drop-in was not generated"
[ "$(stat -c '%a' "$services_env")" = 640 ] ||
  fail "service environment mode is not 0640"
[ "$(stat -c '%a' "$database_url")" = 400 ] ||
  fail "database URL mode is not 0400"
[ "$(stat -c '%a' "$database_autopilot_token_file")" = 400 ] ||
  fail "database autopilot credential mode is not 0400"
[ "$(stat -c '%a' "$keycloak_autopilot_token_file")" = 400 ] ||
  fail "Keycloak autopilot credential mode is not 0400"
[ "$(stat -c '%a' "$agent_drop_in")" = 644 ] ||
  fail "Agent drop-in mode is not 0644"
[ "$(tr -d '\r\n' <"$database_autopilot_token_file")" = \
    "$database_autopilot_token" ] ||
  fail "database autopilot credential content is wrong"
[ "$(tr -d '\r\n' <"$keycloak_autopilot_token_file")" = \
    "$keycloak_autopilot_token" ] ||
  fail "Keycloak autopilot credential content is wrong"
assert_active heteronetwork-signal.service
assert_active heteronetwork-stun.service
assert_active heteronetwork-control-plane.service

if grep -q '^HETERONETWORK_DATABASE_URL_PATH=' "$services_env"; then
  fail "database URL path bypassed the systemd credential"
fi
grep -Fqx \
  'LoadCredential=database-url:/etc/heteronetwork/public-services/database-url' \
  "$control_plane_unit" || fail "Control Plane database credential is not loaded by systemd"
grep -Fqx \
  'LoadCredential=database-autopilot.token:/etc/heteronetwork/public-services/database-autopilot.token' \
  "$control_plane_unit" ||
  fail "Control Plane database autopilot credential is not loaded by systemd"
grep -Fqx \
  'LoadCredential=keycloak-autopilot.token:/etc/heteronetwork/public-services/keycloak-autopilot.token' \
  "$control_plane_unit" ||
  fail "Control Plane Keycloak autopilot credential is not loaded by systemd"
grep -q '^HETERONETWORK_LISTEN="10.250.0.4:19088"$' "$services_env" ||
  fail "automatic Control Plane listen address is wrong"
grep -q '^HETERONETWORK_ADVERTISE_CONTROL_PLANE_URL="http://10.250.0.4:19088"$' \
  "$services_env" || fail "automatic Control Plane advertisement is wrong"
grep -q '^HETERONETWORK_SIGNAL_LISTEN="127.0.0.1:19443"$' "$services_env" ||
  fail "automatic Signal listen address is wrong"
grep -q '^HETERONETWORK_STUN_LISTEN="0.0.0.0:19444"$' "$services_env" ||
  fail "automatic STUN listen address is wrong"
grep -q '^HETERONETWORK_STUN_HTTP_LISTEN="10.250.0.4:19446"$' "$services_env" ||
  fail "automatic STUN HTTP listen address is wrong"
grep -q '^HETERONETWORK_SERVICE_INSTANCE_ID="auto-services-node-0e1c0dadf2fab64e23dfe42c9a073f1b"$' \
  "$services_env" || fail "automatic service instance ID can collide with the enrollment signer"
grep -q '^HETERONETWORK_SERVICE_OWNER_HOST_ID="node-0e1c0dadf2fab64e23dfe42c9a073f1b"$' \
  "$services_env" || fail "automatic service owner host ID is wrong"
grep -q '^HETERONETWORK_SERVICE_OWNER_NODE_ID="node-0e1c0dadf2fab64e23dfe42c9a073f1b"$' \
  "$services_env" || fail "automatic service owner node ID is wrong"
grep -q '^HETERONETWORK_ADVERTISE_STUN_URL="udp://163.220.236.51:19444"$' \
  "$services_env" || fail "automatic STUN advertisement is wrong"
grep -q '^HETERONETWORK_ADVERTISE_RELAY_URL="udp://163.220.236.51:18445"$' \
  "$services_env" || fail "Relay advertisement is wrong"
grep -Fq \
  "HETERONETWORK_TRUSTED_NODE_ENROLLMENT_ISSUER_KEYS=\"issuer-enrollment,web-enrollment,$enrollment_public_key,604800;issuer-rotation,web-rotation,$rotation_public_key,2592000\"" \
  "$services_env" || fail "restricted enrollment verifier rotation list was not preserved"
grep -Fqx \
  "HETERONETWORK_TRUSTED_ISSUER_KEYS=\"issuer-next,root-next,$trusted_public_key\"" \
  "$services_env" || fail "trusted root rotation key was not preserved"
grep -q 'SIGNAL_UPSTREAM=127.0.0.1:19443' "$agent_drop_in" ||
  fail "Signal gateway route is missing"
grep -q 'RELAY_ADMISSION_UPSTREAM=10.250.0.4:18447' "$agent_drop_in" ||
  fail "Relay admission gateway route is missing"
if grep -q 'CONTROL_PLANE_HOST\|CONTROL_PLANE_UPSTREAM' "$agent_drop_in"; then
  fail "automatic services replaced the signer-enabled Control Plane route"
fi
if grep -q 'NODE_ENROLLMENT_ISSUER_PRIVATE_KEY' "$services_env"; then
  fail "automatic Control Plane received a private enrollment signer"
fi
if grep -Fq "$database_autopilot_token" "$services_env" ||
  grep -Fq "$keycloak_autopilot_token" "$services_env"; then
  fail "an autopilot credential was written to the service environment"
fi

signal_start_line=$(grep -n '^start heteronetwork-signal.service$' "$systemctl_log" |
  cut -d: -f1)
stun_start_line=$(grep -n '^start heteronetwork-stun.service$' "$systemctl_log" |
  cut -d: -f1)
control_plane_start_line=$(grep -n '^start heteronetwork-control-plane.service$' \
  "$systemctl_log" | cut -d: -f1)
[ "$signal_start_line" -lt "$control_plane_start_line" ] ||
  fail "Control Plane started before Signal"
[ "$stun_start_line" -lt "$control_plane_start_line" ] ||
  fail "Control Plane started before STUN"

sed -i \
  's/^HETERONETWORK_PUBLIC_SERVICES_TRUSTED_ISSUER_KEYS_B64=.*/HETERONETWORK_PUBLIC_SERVICES_TRUSTED_ISSUER_KEYS_B64=/' \
  "$public_services_dir/bootstrap.env"
run_reconciler
if grep -q '^HETERONETWORK_TRUSTED_ISSUER_KEYS=' "$services_env"; then
  fail "empty trusted root rotation list was emitted as an invalid CLI value"
fi

services_checksum=$(cksum "$services_env")
database_checksum=$(cksum "$database_url")
database_autopilot_token_checksum=$(cksum "$database_autopilot_token_file")
keycloak_autopilot_token_checksum=$(cksum "$keycloak_autopilot_token_file")
drop_in_checksum=$(cksum "$agent_drop_in")
chmod 0640 "$database_url"
run_reconciler
[ "$(cksum "$services_env")" = "$services_checksum" ] ||
  fail "idempotent run rewrote the service environment"
[ "$(cksum "$database_url")" = "$database_checksum" ] ||
  fail "idempotent run rewrote the database URL"
[ "$(stat -c '%a' "$database_url")" = 400 ] ||
  fail "idempotent run did not repair database URL permissions"
[ "$(cksum "$database_autopilot_token_file")" = \
    "$database_autopilot_token_checksum" ] ||
  fail "idempotent run rewrote the database autopilot credential"
[ "$(cksum "$keycloak_autopilot_token_file")" = \
    "$keycloak_autopilot_token_checksum" ] ||
  fail "idempotent run rewrote the Keycloak autopilot credential"
[ "$(cksum "$agent_drop_in")" = "$drop_in_checksum" ] ||
  fail "idempotent run rewrote the Agent drop-in"
if grep -Eq '^(start|stop|restart|kill) ' "$systemctl_log"; then
  fail "idempotent run changed a service"
fi

chmod 0640 "$database_autopilot_token_file" "$keycloak_autopilot_token_file"
run_reconciler
[ "$(stat -c '%a' "$database_autopilot_token_file")" = 400 ] ||
  fail "database autopilot credential permissions were not repaired"
[ "$(stat -c '%a' "$keycloak_autopilot_token_file")" = 400 ] ||
  fail "Keycloak autopilot credential permissions were not repaired"

sed -i \
  's/^HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN=.*/HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN=A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/' \
  "$public_services_dir/bootstrap.env"
run_reconciler
assert_demoted
sed -i \
  "s/^HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN=.*/HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN=$database_autopilot_token/" \
  "$public_services_dir/bootstrap.env"

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
run_reconciler
sed -i \
  "s/^HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=.*/HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=${keycloak_autopilot_token%?}/" \
  "$public_services_dir/bootstrap.env"
run_reconciler
assert_demoted
sed -i \
  "s/^HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=.*/HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=$keycloak_autopilot_token/" \
  "$public_services_dir/bootstrap.env"

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
ln -s "$test_root/credential-symlink-target" "$database_autopilot_token_file"
run_reconciler
assert_demoted

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
run_reconciler
write_status private "$fresh_time"
run_reconciler
assert_demoted
grep -q '^restart heteronetwork-agent.service$' "$systemctl_log" ||
  fail "Agent was not restarted after route withdrawal"

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
run_reconciler
write_status public '2000-01-01T00:00:00Z'
run_reconciler
assert_demoted

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
run_reconciler
rm -f "$password_file"
run_reconciler
assert_demoted

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
run_reconciler
set_inactive heteronetwork-relay.service
run_reconciler
assert_demoted

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
run_reconciler
write_relay_status '163.220.236.52:18445'
run_reconciler
assert_demoted

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
write_gateway_status 163.220.236.51 error
run_reconciler
assert_demoted

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time" '[2001:::8888]:51820'
run_reconciler
assert_demoted

prepare_dependencies '[2001:4860:4860::8888]:18445'
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time" '[2001:4860:4860::8888]:51820'
write_gateway_status '2001:4860:4860::8888'
run_reconciler
run_reconciler
assert_active heteronetwork-signal.service
assert_active heteronetwork-stun.service
assert_active heteronetwork-control-plane.service
grep -Fqx 'HETERONETWORK_STUN_LISTEN="[::]:19444"' "$services_env" ||
  fail "IPv6 STUN listen address is wrong"
grep -Fqx 'HETERONETWORK_ADVERTISE_SIGNAL_URL="https://[2001:4860:4860::8888]"' \
  "$services_env" || fail "IPv6 Signal advertisement is wrong"
grep -Fqx 'HETERONETWORK_ADVERTISE_STUN_URL="udp://[2001:4860:4860::8888]:19444"' \
  "$services_env" || fail "IPv6 STUN advertisement is wrong"
grep -Fqx 'HETERONETWORK_ADVERTISE_RELAY_URL="udp://[2001:4860:4860::8888]:18445"' \
  "$services_env" || fail "IPv6 Relay advertisement is wrong"
grep -Fqx 'HETERONETWORK_ADVERTISE_WEB_UI_URL="https://[2001:4860:4860::8888]"' \
  "$services_env" || fail "IPv6 Web UI advertisement is wrong"
grep -q '^HETERONETWORK_LISTEN="10.250.0.4:19088"$' "$services_env" ||
  fail "IPv6 promotion changed the overlay Control Plane listener"

prepare_dependencies
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time"
: >"$fake_state/fail-start-heteronetwork-control-plane.service"
run_reconciler
run_reconciler
rm -f "$fake_state/fail-start-heteronetwork-control-plane.service"
assert_demoted

if grep -Fq "$secret" "$output_log" ||
  grep -Fq "$secret" "$systemctl_log" ||
  grep -Fq "$database_autopilot_token" "$output_log" ||
  grep -Fq "$database_autopilot_token" "$systemctl_log" ||
  grep -Fq "$keycloak_autopilot_token" "$output_log" ||
  grep -Fq "$keycloak_autopilot_token" "$systemctl_log"; then
  fail "a secret was printed"
fi

printf '%s\n' 'public-services autopilot smoke: ok'
