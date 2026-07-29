#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
autopilot="$script_dir/keycloak-autopilot.sh"
helper_contract="$script_dir/keycloak-ha-node.sh"
systemd_dir="$script_dir/../deploy/systemd"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-keycloak-smoke.XXXXXX")"
test_root="$test_dir/root"
fake_bin="$test_dir/fake-bin"
fake_state="$test_dir/fake-state"
fixture_dir="$test_dir/fixtures"
request_dir="$test_dir/requests"
output_log="$test_dir/output.log"
helper_log="$test_dir/helper.log"
systemctl_log="$test_dir/systemctl.log"
curl_argv_log="$test_dir/curl-argv.log"
curl_counter="$test_dir/curl-counter"

readonly bearer_token="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
readonly database_secret="DatabaseSecret_DoNotPrint_729154"
readonly bootstrap_secret="BootstrapSecret_DoNotPrint_418630"
readonly cluster_id="cluster-keycloak-smoke"
readonly node_id="node-keycloak-local"
readonly vpn_ip="10.250.0.21"
readonly archive_url="https://downloads.example.test/keycloak-26.6.4.tar.gz"
readonly oidc_probe_path="/realms/heteronetwork/.well-known/openid-configuration"
readonly keycloak_sha256="386b566bbea05527226e275c43e5cf6f218896ad2441ac4be5c39f1226772e8f"

cleanup() {
  rm -rf "$test_dir"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'keycloak autopilot smoke: %s\n' "$*" >&2
  exit 1
}

assert_active() {
  [[ -e "$fake_state/active/$1" ]] || fail "$1 is not active"
}

assert_inactive() {
  [[ ! -e "$fake_state/active/$1" ]] || fail "$1 is still active"
}

count_helper_command() {
  local command="$1"
  awk -v command="$command" '$1 == command { count += 1 } END { print count + 0 }' \
    "$helper_log"
}

b64() {
  printf '%s' "$1" | base64 | tr -d '\r\n'
}

latest_request() {
  local latest
  latest="$(find "$request_dir" -maxdepth 1 -type f -name '*.json' \
    -printf '%f\n' | sort -n | tail -n 1)"
  [[ -n "$latest" ]] || fail "no reconciliation request was captured"
  printf '%s/%s\n' "$request_dir" "$latest"
}

write_response() {
  local path="$1" assigned="$2" replica_node_id="$3" replica_vpn_ip="$4"
  jq -cn \
    --arg cluster_id "$cluster_id" \
    --arg node_id "$replica_node_id" \
    --arg vpn_ip "$replica_vpn_ip" \
    --argjson assigned "$assigned" '{
      cluster_id: $cluster_id,
      placement_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      desired_replicas: 3,
      lease_ttl_seconds: 45,
      reconcile_after_seconds: 15,
      assigned: $assigned,
      replicas: [{
        node_id: $node_id,
        vpn_ip: $vpn_ip,
        version: "26.6.4",
        ready: false,
        lease_expires_at: "2030-01-01T00:00:00Z"
      }],
      generated_at: "2026-07-29T00:00:00Z"
    }' >"$path"
}

mkdir -p \
  "$fake_bin" \
  "$fake_state/active" \
  "$fixture_dir" \
  "$request_dir" \
  "$test_root/etc/heteronetwork" \
  "$test_root/opt/heteronetwork/libexec"
touch "$output_log" "$helper_log" "$systemctl_log" "$curl_argv_log"

cat >"$fake_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s' "${1:-}" >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"
for argument in "${@:2}"; do
  printf ' %s' "$argument" >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"
done
printf '\n' >>"$HETERONETWORK_SMOKE_SYSTEMCTL_LOG"

command_name="${1:-}"
shift || true
case "$command_name" in
  is-active)
    [[ "${1:-}" != "--quiet" ]] || shift
    [[ -e "$HETERONETWORK_SMOKE_STATE/active/${1:-}" ]]
    ;;
  start|restart|reload-or-restart)
    unit="${1:-}"
    [[ ! -e "$HETERONETWORK_SMOKE_STATE/fail-${command_name}-${unit}" ]] \
      || exit 1
    : >"$HETERONETWORK_SMOKE_STATE/active/$unit"
    if [[ "$unit" == "heteronetwork-keycloak.service" ]]; then
      : >"$HETERONETWORK_SMOKE_STATE/keycloak-ready"
    fi
    ;;
  stop)
    unit="${1:-}"
    rm -f "$HETERONETWORK_SMOKE_STATE/active/$unit"
    if [[ "$unit" == "heteronetwork-keycloak.service" ]]; then
      rm -f "$HETERONETWORK_SMOKE_STATE/keycloak-ready"
    fi
    ;;
  daemon-reload)
    ;;
  *)
    exit 1
    ;;
esac
EOF

cat >"$fake_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf 'curl' >>"$HETERONETWORK_SMOKE_CURL_ARGV_LOG"
for argument in "$@"; do
  printf ' %s' "$argument" >>"$HETERONETWORK_SMOKE_CURL_ARGV_LOG"
done
printf '\n' >>"$HETERONETWORK_SMOKE_CURL_ARGV_LOG"

url="${*: -1}"
config=""
data_binary=""
output=""
while (($# > 0)); do
  case "$1" in
    --config)
      config="$2"
      shift 2
      ;;
    --data-binary)
      data_binary="$2"
      shift 2
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

case "$url" in
  http://127.0.0.1:9780/v1/status)
    cat "$HETERONETWORK_SMOKE_STATUS_FIXTURE"
    ;;
  http://127.0.0.1:19000/health/ready)
    [[ -e "$HETERONETWORK_SMOKE_STATE/keycloak-ready" \
      && ! -e "$HETERONETWORK_SMOKE_STATE/keycloak-health-down" ]]
    printf '{"status":"UP"}\n'
    ;;
  */v1/keycloak-autopilot/reconcile)
    [[ ! -e "$HETERONETWORK_SMOKE_STATE/api-down" ]] || exit 7
    [[ -f "$config" && "$(stat -c '%a' "$config")" == "600" ]] || exit 8
    grep -Fqx \
      "header = \"Authorization: Bearer ${HETERONETWORK_SMOKE_BEARER_TOKEN}\"" \
      "$config" || exit 9
    request="${data_binary#@}"
    [[ "$request" != "$data_binary" && -f "$request" && -n "$output" ]] || exit 10
    jq -e \
      'type == "object"
       and (keys == ["eligible", "node_id", "ready", "version", "vpn_ip"])
       and (.eligible | type == "boolean")
       and (.ready | type == "boolean")' \
      "$request" >/dev/null || exit 11
    counter=0
    [[ ! -f "$HETERONETWORK_SMOKE_CURL_COUNTER" ]] \
      || counter="$(<"$HETERONETWORK_SMOKE_CURL_COUNTER")"
    counter=$((counter + 1))
    printf '%s\n' "$counter" >"$HETERONETWORK_SMOKE_CURL_COUNTER"
    cp "$request" "$HETERONETWORK_SMOKE_REQUEST_DIR/$counter.json"
    if jq -e '.eligible == false' "$request" >/dev/null; then
      cp "$HETERONETWORK_SMOKE_WITHDRAW_RESPONSE_FIXTURE" "$output"
    else
      cp "$HETERONETWORK_SMOKE_RESPONSE_FIXTURE" "$output"
    fi
    ;;
  *)
    exit 12
    ;;
esac
EOF

cat >"$test_root/opt/heteronetwork/libexec/keycloak-ha-node.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
printf '%s\n' "$command_name" >>"$HETERONETWORK_SMOKE_HELPER_LOG"
case "$command_name" in
  prepare-edge)
    ;;
  prepare)
    [[ "${HETERONETWORK_KEYCLOAK_ARCHIVE_URL:-}" \
      == "$HETERONETWORK_SMOKE_ARCHIVE_URL" ]]
    : >"$HETERONETWORK_SMOKE_STATE/prepared"
    ;;
  prepared)
    [[ -e "$HETERONETWORK_SMOKE_STATE/prepared" ]]
    ;;
  configure)
    expected_secret_dir="$HETERONETWORK_SMOKE_ROOT/etc/heteronetwork/postgres-autopilot/bundle/secrets"
    [[ "${HETERONETWORK_KEYCLOAK_CLUSTER_BIND_ADDRESS:-}" \
      == "$HETERONETWORK_SMOKE_VPN_IP" ]]
    [[ "${HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE:-}" \
      == "$expected_secret_dir/keycloak.password" ]]
    [[ "${HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE:-}" \
      == "$expected_secret_dir/keycloak-bootstrap-admin.password" ]]
    : >"$HETERONETWORK_SMOKE_STATE/configured"
    ;;
  activate)
    [[ -e "$HETERONETWORK_SMOKE_STATE/configured" ]]
    if ! systemctl is-active --quiet heteronetwork-keycloak.service; then
      systemctl start heteronetwork-keycloak.service
    fi
    systemctl start heteronetwork-keycloak-backchannel.service
    curl --fail --silent --show-error \
      --connect-timeout 2 --max-time 5 \
      http://127.0.0.1:19000/health/ready >/dev/null
    ;;
  deactivate)
    systemctl stop heteronetwork-keycloak-backchannel.service
    systemctl stop heteronetwork-keycloak.service
    ;;
  configure-edge-proxy)
    [[ "${HETERONETWORK_KEYCLOAK_EDGE_LISTEN_PORT:-}" == "18079" ]]
    [[ "${HETERONETWORK_KEYCLOAK_EDGE_HEALTH_PATH:-}" \
      == "/realms/heteronetwork/.well-known/openid-configuration" ]]
    printf '%s\n' "${HETERONETWORK_KEYCLOAK_EDGE_UPSTREAMS:-}" \
      >"$HETERONETWORK_SMOKE_STATE/edge-upstreams"
    if systemctl is-active --quiet heteronetwork-keycloak-edge-proxy.service; then
      systemctl reload-or-restart heteronetwork-keycloak-edge-proxy.service
    else
      systemctl start heteronetwork-keycloak-edge-proxy.service
    fi
    ;;
  deactivate-edge-proxy)
    systemctl stop heteronetwork-keycloak-edge-proxy.service
    ;;
  *)
    exit 2
    ;;
esac
EOF

chmod 0755 \
  "$fake_bin/systemctl" \
  "$fake_bin/curl" \
  "$test_root/opt/heteronetwork/libexec/keycloak-ha-node.sh"

export PATH="$fake_bin:/usr/bin:/bin"
export HETERONETWORK_KEYCLOAK_AUTOPILOT_TESTING=1
export HETERONETWORK_KEYCLOAK_AUTOPILOT_TEST_ROOT="$test_root"
export HETERONETWORK_KEYCLOAK_AUTOPILOT_HELPER="$test_root/opt/heteronetwork/libexec/keycloak-ha-node.sh"
export HETERONETWORK_SMOKE_ROOT="$test_root"
export HETERONETWORK_SMOKE_STATE="$fake_state"
export HETERONETWORK_SMOKE_HELPER_LOG="$helper_log"
export HETERONETWORK_SMOKE_SYSTEMCTL_LOG="$systemctl_log"
export HETERONETWORK_SMOKE_CURL_ARGV_LOG="$curl_argv_log"
export HETERONETWORK_SMOKE_CURL_COUNTER="$curl_counter"
export HETERONETWORK_SMOKE_REQUEST_DIR="$request_dir"
export HETERONETWORK_SMOKE_STATUS_FIXTURE="$fixture_dir/status.json"
export HETERONETWORK_SMOKE_RESPONSE_FIXTURE="$fixture_dir/response.json"
export HETERONETWORK_SMOKE_WITHDRAW_RESPONSE_FIXTURE="$fixture_dir/withdraw-response.json"
export HETERONETWORK_SMOKE_BEARER_TOKEN="$bearer_token"
export HETERONETWORK_SMOKE_ARCHIVE_URL="$archive_url"
export HETERONETWORK_SMOKE_VPN_IP="$vpn_ip"

config_dir="$test_root/etc/heteronetwork"
bundle_dir="$config_dir/postgres-autopilot/bundle"
secret_dir="$bundle_dir/secrets"
agent_drop_in="$test_root/etc/systemd/system/heteronetwork-agent.service.d/30-keycloak-gateway.conf"
mkdir -p "$secret_dir"

cat >"$config_dir/keycloak-autopilot.env" <<EOF
HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN=$bearer_token
HETERONETWORK_KEYCLOAK_CLUSTER_ID_B64=$(b64 "$cluster_id")
HETERONETWORK_KEYCLOAK_CONTROL_PLANE_URLS_B64='$(b64 https://control-a.example.test) $(b64 https://control-b.example.test)'
HETERONETWORK_KEYCLOAK_VERSION=26.6.4
HETERONETWORK_KEYCLOAK_ARCHIVE_URL_B64=$(b64 "$archive_url")
HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256=$keycloak_sha256
HETERONETWORK_KEYCLOAK_OIDC_PROBE_PATH_B64=$(b64 "$oidc_probe_path")
EOF
chmod 0600 "$config_dir/keycloak-autopilot.env"

printf '%s\n' "$cluster_id" >"$bundle_dir/cluster-id"
cat >"$bundle_dir/manifest.env" <<EOF
HETERONETWORK_DB_MEMBER_IDENTITIES=postgres-a=$node_id,postgres-b=node-keycloak-b,postgres-c=node-keycloak-c
EOF
printf '%s\n' "$database_secret" >"$secret_dir/keycloak.password"
printf '%s\n' "$bootstrap_secret" >"$secret_dir/keycloak-bootstrap-admin.password"
chmod 0600 \
  "$secret_dir/keycloak.password" \
  "$secret_dir/keycloak-bootstrap-admin.password"

cat >"$fixture_dir/status.json" <<EOF
{"node_id":"$node_id","vpn_ip":"$vpn_ip"}
EOF
write_response "$fixture_dir/response.json" true "$node_id" "$vpn_ip"
write_response \
  "$fixture_dir/withdraw-response.json" false node-keycloak-remote 10.250.0.22

touch \
  "$fake_state/active/heteronetwork-agent.service" \
  "$fake_state/active/heteronetwork-db.service" \
  "$fake_state/active/heteronetwork-db-proxy.service"

run_autopilot() {
  if ! "$autopilot" "$1" >>"$output_log" 2>&1; then
    tail -n 20 "$output_log" >&2
    fail "autopilot $1 failed"
  fi
}

run_autopilot prepare
[[ -e "$fake_state/prepared" ]] || fail "prepare did not stage Keycloak"
[[ "$(tail -n 1 "$helper_log")" == "prepare" ]] \
  || fail "prepare did not call the helper prepare command"
[[ "$(count_helper_command prepare-edge)" == "1" ]] \
  || fail "prepare did not stage the lightweight edge dependencies"

run_autopilot reconcile
assert_active heteronetwork-keycloak.service
assert_active heteronetwork-keycloak-backchannel.service
assert_active heteronetwork-keycloak-edge-proxy.service
[[ "$(<"$fake_state/edge-upstreams")" == "$vpn_ip:18080" ]] \
  || fail "selected single-replica edge upstream is wrong"
[[ -f "$agent_drop_in" ]] || fail "Agent Keycloak gateway drop-in is missing"
grep -Fq 'OIDC_UPSTREAM=127.0.0.1:18079' "$agent_drop_in" \
  || fail "Agent Keycloak gateway does not target loopback port 18079"
grep -Fq "OIDC_PROBE_PATH=$oidc_probe_path" "$agent_drop_in" \
  || fail "Agent Keycloak discovery probe path is wrong"
first_request="$request_dir/1.json"
jq -e \
  --arg node_id "$node_id" \
  --arg vpn_ip "$vpn_ip" '
    . == {
      node_id: $node_id,
      vpn_ip: $vpn_ip,
      eligible: true,
      ready: false,
      version: "26.6.4"
    }
  ' "$first_request" >/dev/null \
  || fail "initial reconciliation request violated the API contract"

run_autopilot reconcile
jq -e '.eligible == true and .ready == true' "$(latest_request)" >/dev/null \
  || fail "an active selected replica did not report ready"

chmod 0640 "$secret_dir/keycloak.password"
run_autopilot reconcile
jq -e '.eligible == false and .ready == false' "$(latest_request)" >/dev/null \
  || fail "an active ineligible replica reported ready"
chmod 0600 "$secret_dir/keycloak.password"
write_response "$fixture_dir/response.json" true "$node_id" "$vpn_ip"
run_autopilot reconcile
assert_active heteronetwork-keycloak.service
assert_active heteronetwork-keycloak-backchannel.service

state_before_outage="$(find "$fake_state/active" -maxdepth 1 -type f \
  -printf '%f\n' | sort)"
edge_before_outage="$(<"$fake_state/edge-upstreams")"
drop_in_before_outage="$(sha256sum "$agent_drop_in")"
activate_before_outage="$(count_helper_command activate)"
deactivate_before_outage="$(count_helper_command deactivate)"
edge_reconcile_before_outage="$(count_helper_command configure-edge-proxy)"
touch "$fake_state/api-down"
run_autopilot reconcile
rm -f "$fake_state/api-down"
[[ "$(find "$fake_state/active" -maxdepth 1 -type f -printf '%f\n' | sort)" \
  == "$state_before_outage" ]] \
  || fail "Control Plane outage changed active services"
[[ "$(<"$fake_state/edge-upstreams")" == "$edge_before_outage" ]] \
  || fail "Control Plane outage changed edge upstreams"
[[ "$(sha256sum "$agent_drop_in")" == "$drop_in_before_outage" ]] \
  || fail "Control Plane outage changed the Agent drop-in"
[[ "$(count_helper_command activate)" == "$activate_before_outage" \
  && "$(count_helper_command deactivate)" == "$deactivate_before_outage" \
  && "$(count_helper_command configure-edge-proxy)" == "$edge_reconcile_before_outage" ]] \
  || fail "Control Plane outage changed Keycloak placement"

write_response \
  "$fixture_dir/response.json" false node-keycloak-remote 10.250.0.22
run_autopilot reconcile
assert_inactive heteronetwork-keycloak.service
assert_inactive heteronetwork-keycloak-backchannel.service
assert_active heteronetwork-keycloak-edge-proxy.service
[[ "$(<"$fake_state/edge-upstreams")" == "10.250.0.22:18080" ]] \
  || fail "non-selected node did not proxy to the selected replica"
[[ -f "$agent_drop_in" ]] \
  || fail "non-selected node lost its local Keycloak gateway"

write_response "$fixture_dir/response.json" true "$node_id" "$vpn_ip"
touch \
  "$fake_state/active/heteronetwork-keycloak.service" \
  "$fake_state/active/heteronetwork-keycloak-backchannel.service" \
  "$fake_state/keycloak-ready" \
  "$fake_state/keycloak-health-down"
printf '0\n' \
  >"$test_root/var/lib/heteronetwork-keycloak-autopilot/restart-failures"
rm -f "$test_root/var/lib/heteronetwork-keycloak-autopilot/cooldown-until"
run_autopilot reconcile
[[ "$(<"$test_root/var/lib/heteronetwork-keycloak-autopilot/restart-failures")" == "0" ]] \
  || fail "starting Keycloak consumed a failure before its activation timeout"
activation_started_at_path="$test_root/var/lib/heteronetwork-keycloak-autopilot/activation-started-at"
[[ -f "$activation_started_at_path" ]] \
  || fail "starting Keycloak did not persist its activation window"
printf '%s\n' "$(( $(date +%s) - 91 ))" >"$activation_started_at_path"
run_autopilot reconcile
[[ "$(<"$test_root/var/lib/heteronetwork-keycloak-autopilot/restart-failures")" == "1" ]] \
  || fail "timed-out Keycloak activation did not consume one failure"
assert_inactive heteronetwork-keycloak.service
assert_inactive heteronetwork-keycloak-backchannel.service
rm -f "$fake_state/keycloak-health-down"
run_autopilot reconcile
[[ "$(<"$test_root/var/lib/heteronetwork-keycloak-autopilot/restart-failures")" == "0" ]] \
  || fail "healthy Keycloak did not reset the activation failure counter"

rm -f \
  "$fake_state/active/heteronetwork-keycloak.service" \
  "$fake_state/active/heteronetwork-keycloak-backchannel.service"
touch "$fake_state/fail-start-heteronetwork-keycloak.service"
rm -f \
  "$fake_state/keycloak-ready" \
  "$test_root/var/lib/heteronetwork-keycloak-autopilot/restart-failures" \
  "$test_root/var/lib/heteronetwork-keycloak-autopilot/cooldown-until"

run_autopilot reconcile
run_autopilot reconcile
run_autopilot reconcile

cooldown_path="$test_root/var/lib/heteronetwork-keycloak-autopilot/cooldown-until"
[[ -f "$cooldown_path" ]] || fail "three activation failures did not enter cooldown"
now="$(date +%s)"
cooldown_until="$(<"$cooldown_path")"
((cooldown_until > now && cooldown_until <= now + 120)) \
  || fail "cooldown duration is not 120 seconds"
assert_inactive heteronetwork-keycloak.service
assert_inactive heteronetwork-keycloak-backchannel.service
jq -e '.eligible == false and .ready == false' "$(latest_request)" >/dev/null \
  || fail "failed candidate was not withdrawn"

activations_before_cooldown_reconcile="$(count_helper_command activate)"
rm -f "$fake_state/fail-start-heteronetwork-keycloak.service"
run_autopilot reconcile
[[ "$(count_helper_command activate)" == "$activations_before_cooldown_reconcile" ]] \
  || fail "cooldown candidate was reactivated"
jq -e '.eligible == false' "$(latest_request)" >/dev/null \
  || fail "cooldown candidate remained eligible"

prepare_before_edge_only="$(count_helper_command prepare)"
prepare_edge_before_edge_only="$(count_helper_command prepare-edge)"
rm -f "$fake_state/prepared"
touch "$bundle_dir/.proxy-only"
run_autopilot prepare
rm -f "$bundle_dir/.proxy-only"
[[ ! -e "$fake_state/prepared" ]] \
  || fail "an edge-only node downloaded the Keycloak replica release"
[[ "$(count_helper_command prepare)" == "$prepare_before_edge_only" ]] \
  || fail "an edge-only node invoked full Keycloak preparation"
[[ "$(count_helper_command prepare-edge)" \
  == "$((prepare_edge_before_edge_only + 1))" ]] \
  || fail "an edge-only node skipped lightweight proxy preparation"

grep -Fqx \
  'ExecStart=/opt/heteronetwork/libexec/keycloak-autopilot.sh prepare' \
  "$systemd_dir/heteronetwork-keycloak-prepare.service" \
  || fail "prepare unit command contract is wrong"
grep -Fqx \
  'ExecStart=/opt/heteronetwork/libexec/keycloak-autopilot.sh reconcile' \
  "$systemd_dir/heteronetwork-keycloak-autopilot.service" \
  || fail "reconcile unit command contract is wrong"
grep -Fqx \
  'ConfigurationDirectory=heteronetwork/keycloak heteronetwork/keycloak-backchannel heteronetwork/keycloak-edge-proxy' \
  "$systemd_dir/heteronetwork-keycloak-autopilot.service" \
  || fail "reconcile unit does not create its protected configuration directories"
grep -Fqx 'Unit=heteronetwork-keycloak-autopilot.service' \
  "$systemd_dir/heteronetwork-keycloak-autopilot.timer" \
  || fail "timer does not target the reconcile service"
if grep -Fq \
  'Requires=heteronetwork-agent.service heteronetwork-keycloak-prepare.service' \
  "$systemd_dir/heteronetwork-keycloak-autopilot.service"; then
  fail "reconciliation still hard-requires full Keycloak preparation"
fi
grep -Fqx 'TimeoutStartSec=900s' \
  "$systemd_dir/heteronetwork-keycloak-prepare.service" \
  || fail "replica preparation is not bounded"
grep -Fq 'readonly KEYCLOAK_VERSION="26.6.4"' "$helper_contract" \
  || fail "helper Keycloak version is not pinned"
grep -Fq 'prepare-edge)' "$helper_contract" \
  || fail "helper omitted lightweight edge preparation"
grep -Fq "readonly KEYCLOAK_ARCHIVE_SHA256=\"$keycloak_sha256\"" \
  "$helper_contract" || fail "helper archive digest is not pinned"
grep -Fq 'ACTIVATION_READY_ATTEMPTS="3"' "$helper_contract" \
  || fail "helper activation readiness attempts are not lease-safe"
grep -Fq 'ACTIVATION_READY_INTERVAL_SECONDS="3"' "$helper_contract" \
  || fail "helper activation readiness interval is not lease-safe"
grep -Fq 'ACTIVATION_READY_REQUEST_TIMEOUT_SECONDS="2"' "$helper_contract" \
  || fail "helper activation readiness request is not lease-safe"
grep -Fq 'readonly ACTIVATION_TIMEOUT_SECONDS="90"' "$autopilot" \
  || fail "autopilot activation window is not bounded"
grep -Fq '"http://127.0.0.1:${management_port}/health/ready"' "$helper_contract" \
  || fail "helper activation does not probe management readiness"
if grep -Fq 'systemctl restart heteronetwork-keycloak.service' "$helper_contract"; then
  fail "helper restarts an already-active Keycloak replica"
fi
if grep -Fq 'start --optimized --import-realm' "$helper_contract"; then
  fail "normal Keycloak restart still imports realms"
fi
grep -Fq 'test("^[a-f0-9]{64}$")' "$autopilot" \
  || fail "autopilot placement ID contract is not full SHA-256"

for secret in "$database_secret" "$bootstrap_secret" "$bearer_token"; do
  if grep -Fq "$secret" \
    "$output_log" "$helper_log" "$systemctl_log" "$curl_argv_log"; then
    fail "a secret was exposed in logs or process arguments"
  fi
done
if find "$test_root/run/heteronetwork-keycloak-autopilot" -maxdepth 1 \
  -type f \( -name 'curl.*' -o -name 'request.*' -o -name 'response*' \) \
  -print -quit | grep -q .; then
  fail "temporary bearer or reconciliation files survived cleanup"
fi

printf '%s\n' 'keycloak autopilot smoke: ok'
