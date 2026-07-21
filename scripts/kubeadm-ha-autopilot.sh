#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_AGENT_API_URL="http://127.0.0.1:9780"
readonly DEFAULT_STATE_DIR="/etc/heteronetwork/kubernetes"
readonly DEFAULT_COORDINATION_TIMEOUT_SECONDS="3600"
readonly STAGE_PORT="17444"
readonly BUNDLE_PORT="17445"

state_dir="${HETERONETWORK_KUBEADM_STATE_DIR:-$DEFAULT_STATE_DIR}"
config_path="${HETERONETWORK_KUBEADM_AUTOPILOT_CONFIG:-$state_dir/autopilot.env}"
agent_api_url="${HETERONETWORK_AGENT_API_URL:-$DEFAULT_AGENT_API_URL}"
coordination_timeout_seconds="${HETERONETWORK_KUBEADM_COORDINATION_TIMEOUT_SECONDS:-$DEFAULT_COORDINATION_TIMEOUT_SECONDS}"
helper="/opt/heteronetwork/libexec/kubeadm-ha-node.sh"
completion_path="$state_dir/autopilot.complete"
cohort_path="$state_dir/cohort.tsv"

log() {
  printf 'heteronetwork-kubernetes: %s\n' "$*"
}

die() {
  printf 'heteronetwork-kubernetes: error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "autopilot must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' is unavailable"
}

validate_config() {
  [[ "${HETERONETWORK_KUBEADM_COHORT_TAG:-}" =~ ^kubernetes-ha-[a-f0-9]{16}$ ]] \
    || die "invalid Kubernetes HA cohort tag"
  [[ "${HETERONETWORK_KUBEADM_EXPECTED_CONTROL_PLANES:-}" == "3" ]] \
    || die "Kubernetes HA autopilot currently requires exactly three control planes"
  [[ "${HETERONETWORK_KUBEADM_BUNDLE_BEARER_TOKEN:-}" =~ ^[a-f0-9]{64}$ ]] \
    || die "invalid join-bundle bearer token"
  [[ "$coordination_timeout_seconds" =~ ^[0-9]+$ ]] \
    && ((10#$coordination_timeout_seconds >= 300 && 10#$coordination_timeout_seconds <= 7200)) \
    || die "coordination timeout must be between 300 and 7200 seconds"
}

install_coordination_dependencies() {
  require_command apt-get
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl iputils-ping jq socat util-linux
}

wait_until() {
  local description="$1"
  shift
  local deadline=$((SECONDS + coordination_timeout_seconds))
  until "$@"; do
    ((SECONDS < deadline)) || die "timed out waiting for $description"
    sleep 3
  done
}

agent_is_ready() {
  curl -fsS --connect-timeout 2 --max-time 5 "$agent_api_url/healthz" >/dev/null 2>&1
}

read_agent_status() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/status"
}

read_peer_map() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/peers"
}

write_cohort_snapshot() {
  local status peers local_node_id local_ip temporary count
  status="$(read_agent_status)" || return 1
  peers="$(read_peer_map)" || return 1
  local_node_id="$(jq -er '.node_id | select(type == "string" and length > 0)' <<<"$status")" \
    || return 1
  local_ip="$(jq -er '.vpn_ip | select(type == "string" and length > 0)' <<<"$status")" \
    || return 1
  temporary="$(mktemp "$state_dir/cohort.XXXXXX")"
  {
    printf '%s\t%s\n' "$local_ip" "$local_node_id"
    jq -r --arg tag "$HETERONETWORK_KUBEADM_COHORT_TAG" \
      '.peers[] | select(any(.tags[]?; . == $tag)) | [.vpn_ip, .node_id] | @tsv' \
      <<<"$peers"
  } | LC_ALL=C sort -V -u >"$temporary"
  count="$(wc -l <"$temporary" | tr -d ' ')"
  if ((10#$count > 10#$HETERONETWORK_KUBEADM_EXPECTED_CONTROL_PLANES)); then
    rm -f "$temporary"
    die "cohort contains more nodes than its enrollment limit"
  fi
  if [[ "$count" != "$HETERONETWORK_KUBEADM_EXPECTED_CONTROL_PLANES" ]]; then
    rm -f "$temporary"
    return 1
  fi
  install -o root -g root -m 0600 "$temporary" "$cohort_path"
  rm -f "$temporary"
}

cohort_is_reachable() {
  local ip
  while IFS=$'\t' read -r ip _node_id; do
    ping -c 1 -W 2 "$ip" >/dev/null 2>&1 || return 1
  done <"$cohort_path"
}

cohort_ip_at() {
  sed -n "$((10#$1 + 1))p" "$cohort_path" | cut -f1
}

local_cohort_index() {
  local local_node_id
  local_node_id="$(jq -er '.node_id' < <(read_agent_status))"
  awk -F '\t' -v node_id="$local_node_id" '$2 == node_id { print NR - 1; found = 1 } END { if (!found) exit 1 }' "$cohort_path"
}

control_plane_addresses() {
  cut -f1 "$cohort_path" | paste -sd, -
}

write_stage_handler() {
  cat >"$state_dir/serve-stage-ready.sh" <<EOF
#!/bin/sh
set -eu
request=
IFS= read -r request || true
request=\$(printf '%s' "\$request" | tr -d '\\r')
while IFS= read -r line; do
  line=\$(printf '%s' "\$line" | tr -d '\\r')
  [ -n "\$line" ] || break
done
if [ "\$request" = "GET /ready HTTP/1.1" ] && [ -f "$state_dir/stage.ready" ]; then
  body=ready
  status='200 OK'
else
  body=waiting
  status='503 Service Unavailable'
fi
printf 'HTTP/1.1 %s\\r\\nContent-Type: text/plain\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' "\$status" "\${#body}" "\$body"
EOF
  chmod 0700 "$state_dir/serve-stage-ready.sh"
}

start_stage_server() {
  local local_ip="$1"
  write_stage_handler
  cat >/etc/systemd/system/heteronetwork-kubeadm-stage.service <<EOF
[Unit]
Description=HeteroNetwork Kubernetes bootstrap stage endpoint
After=heteronetwork-agent.service
Requires=heteronetwork-agent.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:${STAGE_PORT},bind=${local_ip},reuseaddr,fork EXEC:${state_dir}/serve-stage-ready.sh,nofork
Restart=on-failure
RestartSec=2s
RuntimeMaxSec=3600
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=${state_dir}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl restart heteronetwork-kubeadm-stage.service
}

stage_is_ready() {
  curl -fsS --connect-timeout 2 --max-time 5 "http://$1:${STAGE_PORT}/ready" >/dev/null 2>&1
}

wait_for_stage() {
  local ip="$1"
  wait_until "Kubernetes bootstrap stage on $ip" stage_is_ready "$ip"
}

write_bundle_handler() {
  cat >"$state_dir/serve-join-bundle.sh" <<'EOF'
#!/bin/sh
set -eu
. /etc/heteronetwork/kubernetes/bundle-server.env
request=
authorized=
IFS= read -r request || true
request=$(printf '%s' "$request" | tr -d '\r')
while IFS= read -r line; do
  line=$(printf '%s' "$line" | tr -d '\r')
  [ -n "$line" ] || break
  [ "$line" = "Authorization: Bearer $BUNDLE_BEARER_TOKEN" ] && authorized=1
done
if [ "$request" != "GET /v1/kubernetes/join-bundle HTTP/1.1" ]; then
  body='not found'
  printf 'HTTP/1.1 404 Not Found\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "${#body}" "$body"
  exit 0
fi
if [ -z "$authorized" ]; then
  body='unauthorized'
  printf 'HTTP/1.1 401 Unauthorized\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "${#body}" "$body"
  exit 0
fi
length=$(wc -c <"$BUNDLE_PATH" | tr -d ' ')
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n' "$length"
cat "$BUNDLE_PATH"
EOF
  chmod 0700 "$state_dir/serve-join-bundle.sh"
}

start_bundle_server() {
  local leader_ip="$1"
  local bundle_path="$state_dir/join-bundle.json"
  [[ -s "$bundle_path" ]] || die "kubeadm did not create a join bundle"
  cat >"$state_dir/bundle-server.env" <<EOF
BUNDLE_BEARER_TOKEN=${HETERONETWORK_KUBEADM_BUNDLE_BEARER_TOKEN}
BUNDLE_PATH=${bundle_path}
EOF
  chmod 0600 "$state_dir/bundle-server.env"
  write_bundle_handler
  cat >/etc/systemd/system/heteronetwork-kubeadm-join-bundle.service <<EOF
[Unit]
Description=HeteroNetwork temporary Kubernetes join-bundle endpoint
After=heteronetwork-agent.service
Requires=heteronetwork-agent.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:${BUNDLE_PORT},bind=${leader_ip},reuseaddr,fork EXEC:${state_dir}/serve-join-bundle.sh,nofork
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=${state_dir}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl restart heteronetwork-kubeadm-join-bundle.service
}

download_join_bundle() {
  local leader_ip="$1"
  local temporary curl_config
  temporary="$(mktemp "$state_dir/join-bundle.XXXXXX")"
  curl_config="$(mktemp "$state_dir/curl.XXXXXX")"
  chmod 0600 "$temporary" "$curl_config"
  cat >"$curl_config" <<EOF
fail
silent
show-error
connect-timeout = 2
max-time = 10
header = "Authorization: Bearer ${HETERONETWORK_KUBEADM_BUNDLE_BEARER_TOKEN}"
EOF
  if ! curl --config "$curl_config" \
    "http://${leader_ip}:${BUNDLE_PORT}/v1/kubernetes/join-bundle" -o "$temporary"; then
    rm -f "$temporary" "$curl_config"
    return 1
  fi
  rm -f "$curl_config"
  jq -e '
    (.apiServerEndpoint | type == "string" and length > 0) and
    (.token | test("^[a-z0-9]{6}\\.[a-z0-9]{16}$")) and
    (.caCertHash | test("^sha256:[a-f0-9]{64}$")) and
    (.certificateKey | test("^[a-f0-9]{64}$"))
  ' "$temporary" >/dev/null || {
    rm -f "$temporary"
    return 1
  }
  install -o root -g root -m 0600 "$temporary" "$state_dir/join-bundle.json"
  rm -f "$temporary"
}

stop_bundle_server() {
  systemctl stop heteronetwork-kubeadm-join-bundle.service 2>/dev/null || true
  rm -f "$state_dir/bundle-server.env" "$state_dir/join-bundle.json"
}

write_completion() {
  local local_ip="$1"
  cat >"$completion_path" <<EOF
cohort=${HETERONETWORK_KUBEADM_COHORT_TAG}
node_ip=${local_ip}
control_planes=$(control_plane_addresses)
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  chmod 0600 "$completion_path"
  rm -f "$config_path"
}

run_autopilot() {
  require_root
  if [[ -f "$completion_path" ]]; then
    log "setup is already complete"
    return
  fi
  [[ -f "$config_path" ]] || die "autopilot configuration is missing"
  # shellcheck disable=SC1090
  . "$config_path"
  validate_config
  install_coordination_dependencies
  for command in curl jq ping socat systemctl; do
    require_command "$command"
  done
  [[ -x "$helper" ]] || die "kubeadm HA helper is missing"
  install -d -o root -g root -m 0700 "$state_dir"
  exec 9>"$state_dir/autopilot.lock"
  flock -n 9 || {
    log "another autopilot process is active"
    return
  }

  wait_until "the local HeteroNetwork Agent" agent_is_ready
  wait_until "all cohort nodes to enroll" write_cohort_snapshot
  wait_until "HeteroNetwork reachability within the cohort" cohort_is_reachable

  local local_index local_ip previous_ip leader_ip addresses
  local_index="$(local_cohort_index)"
  local_ip="$(cohort_ip_at "$local_index")"
  leader_ip="$(cohort_ip_at 0)"
  addresses="$(control_plane_addresses)"
  [[ -n "$local_ip" && -n "$leader_ip" && -n "$addresses" ]] || die "invalid cohort snapshot"
  export HETERONETWORK_KUBEADM_NODE_IP="$local_ip"
  export HETERONETWORK_KUBEADM_CONTROL_PLANES="$addresses"

  log "preparing control plane $((10#$local_index + 1))/${HETERONETWORK_KUBEADM_EXPECTED_CONTROL_PLANES} at $local_ip"
  "$helper" prepare
  start_stage_server "$local_ip"

  if [[ "$local_index" == "0" ]]; then
    "$helper" init
    start_bundle_server "$leader_ip"
    touch "$state_dir/stage.ready"
    "$helper" install-flannel
    while IFS=$'\t' read -r local_ip _node_id; do
      wait_for_stage "$local_ip"
    done <"$cohort_path"
    "$helper" finalize
    "$helper" verify-cluster
    stop_bundle_server
  else
    previous_ip="$(cohort_ip_at "$((10#$local_index - 1))")"
    wait_for_stage "$previous_ip"
    wait_until "the Kubernetes join bundle" download_join_bundle "$leader_ip"
    "$helper" join-control-plane
    touch "$state_dir/stage.ready"
    export KUBECONFIG=/etc/kubernetes/admin.conf
    wait_until "the local Kubernetes node to become Ready" \
      kubectl wait --for=condition=Ready "node/$(hostname -s | tr '[:upper:]_' '[:lower:]-' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//; s/-+/-/g' | cut -c1-63)" --timeout=10s
    rm -f "$state_dir/join-bundle.json"
  fi

  write_completion "$HETERONETWORK_KUBEADM_NODE_IP"
  log "three-control-plane Kubernetes HA setup completed"
}

self_test() {
  local temporary
  HETERONETWORK_KUBEADM_COHORT_TAG="kubernetes-ha-0123456789abcdef"
  HETERONETWORK_KUBEADM_EXPECTED_CONTROL_PLANES="3"
  HETERONETWORK_KUBEADM_BUNDLE_BEARER_TOKEN="$(printf 'a%.0s' {1..64})"
  coordination_timeout_seconds=300
  validate_config
  temporary="$(mktemp)"
  printf '10.250.0.10\tnode-c\n10.250.0.2\tnode-a\n10.250.0.3\tnode-b\n' \
    | LC_ALL=C sort -V >"$temporary"
  [[ "$(sed -n '1p' "$temporary")" == $'10.250.0.2\tnode-a' ]]
  [[ "$(sed -n '3p' "$temporary")" == $'10.250.0.10\tnode-c' ]]
  rm -f "$temporary"
  log "autopilot self-test passed"
}

case "${1:-}" in
  run) run_autopilot ;;
  self-test) self_test ;;
  *) printf 'Usage: kubeadm-ha-autopilot.sh {run|self-test}\n' >&2; exit 2 ;;
esac
