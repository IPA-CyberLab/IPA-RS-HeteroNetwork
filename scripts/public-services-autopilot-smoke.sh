#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
autopilot=$script_dir/public-services-autopilot.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-public-services-smoke.XXXXXX")
fake_bin=$test_root/fake-bin
fake_state=$test_root/fake-state
fixture=$test_root/status.json
relay_fixture=$test_root/relay-status.json
systemctl_log=$test_root/systemctl.log
output_log=$test_root/output.log
secret='DatabaseSecret_DoNotPrint_473921'

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
export HETERONETWORK_SMOKE_STATE=$fake_state
export HETERONETWORK_SMOKE_SYSTEMCTL_LOG=$systemctl_log

public_services_dir=$test_root/root/etc/heteronetwork/public-services
password_file=$test_root/root/etc/heteronetwork/postgres-autopilot/bundle/secrets/application.password
ca_file=$test_root/root/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt
services_env=$public_services_dir/services.env
database_url=$public_services_dir/database-url
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
  rm -f "$fake_state/postgres-down"
  set_active heteronetwork-agent.service
  set_active heteronetwork-gateway.service
  set_active heteronetwork-relay.service
}

reset_auto_services() {
  set_inactive heteronetwork-control-plane.service
  set_inactive heteronetwork-signal.service
  set_inactive heteronetwork-stun.service
  rm -f "$services_env" "$database_url" "$agent_drop_in"
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
  [ ! -e "$agent_drop_in" ] || fail "Agent routes survived demotion"
}

fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
prepare_dependencies
reset_auto_services
write_status public "$fresh_time"
run_reconciler

[ -f "$services_env" ] || fail "service environment was not generated"
[ -f "$database_url" ] || fail "database URL was not generated"
[ -f "$agent_drop_in" ] || fail "Agent drop-in was not generated"
[ "$(stat -c '%a' "$services_env")" = 640 ] ||
  fail "service environment mode is not 0640"
[ "$(stat -c '%a' "$database_url")" = 640 ] ||
  fail "database URL mode is not 0640"
[ "$(stat -c '%a' "$agent_drop_in")" = 644 ] ||
  fail "Agent drop-in mode is not 0644"
assert_active heteronetwork-signal.service
assert_active heteronetwork-stun.service
assert_active heteronetwork-control-plane.service

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
grep -q '^HETERONETWORK_ADVERTISE_STUN_URL="udp://163.220.236.51:19444"$' \
  "$services_env" || fail "automatic STUN advertisement is wrong"
grep -q '^HETERONETWORK_ADVERTISE_RELAY_URL="udp://163.220.236.51:18445"$' \
  "$services_env" || fail "Relay advertisement is wrong"
grep -Fq \
  "HETERONETWORK_TRUSTED_NODE_ENROLLMENT_ISSUER_KEYS=\"issuer-enrollment,web-enrollment,$enrollment_public_key,604800;issuer-rotation,web-rotation,$rotation_public_key,2592000\"" \
  "$services_env" || fail "restricted enrollment verifier rotation list was not preserved"
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

services_checksum=$(cksum "$services_env")
database_checksum=$(cksum "$database_url")
drop_in_checksum=$(cksum "$agent_drop_in")
run_reconciler
[ "$(cksum "$services_env")" = "$services_checksum" ] ||
  fail "idempotent run rewrote the service environment"
[ "$(cksum "$database_url")" = "$database_checksum" ] ||
  fail "idempotent run rewrote the database URL"
[ "$(cksum "$agent_drop_in")" = "$drop_in_checksum" ] ||
  fail "idempotent run rewrote the Agent drop-in"
if grep -Eq '^(start|stop|restart|kill) ' "$systemctl_log"; then
  fail "idempotent run changed a service"
fi

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
write_status public "$fresh_time" '[2001:::8888]:51820'
run_reconciler
assert_demoted

prepare_dependencies '[2001:4860:4860::8888]:18445'
reset_auto_services
fresh_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_status public "$fresh_time" '[2001:4860:4860::8888]:51820'
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
rm -f "$fake_state/fail-start-heteronetwork-control-plane.service"
assert_demoted

if grep -Fq "$secret" "$output_log" || grep -Fq "$secret" "$systemctl_log"; then
  fail "a database secret was printed"
fi

printf '%s\n' 'public-services autopilot smoke: ok'
