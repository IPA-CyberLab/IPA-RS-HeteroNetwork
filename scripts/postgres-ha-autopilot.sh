#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_AGENT_API_URL="http://127.0.0.1:9780"
readonly DEFAULT_STATE_DIR="/etc/heteronetwork/postgres-autopilot"
readonly DEFAULT_RECONCILE_INTERVAL_SECONDS="30"
readonly MIN_DATABASE_MEMBER_COUNT="3"
readonly MAX_DATABASE_MEMBER_COUNT="32"
readonly TARGET_DCS_MEMBER_COUNT="5"
readonly BUNDLE_PORT="17446"
readonly DATABASE_NETWORK_PLANE="underlay-v1"

state_dir="${HETERONETWORK_DB_AUTOPILOT_STATE_DIR:-$DEFAULT_STATE_DIR}"
config_path="${HETERONETWORK_DB_AUTOPILOT_CONFIG:-$state_dir/autopilot.env}"
agent_api_url="${HETERONETWORK_AGENT_API_URL:-$DEFAULT_AGENT_API_URL}"
reconcile_interval_seconds="${HETERONETWORK_DB_RECONCILE_INTERVAL_SECONDS:-$DEFAULT_RECONCILE_INTERVAL_SECONDS}"
helper="/opt/heteronetwork/libexec/postgres-ha-node.sh"
bundle_dir="$state_dir/bundle"
bundle_archive="$state_dir/bundle.tar.gz"
eligible_path="$state_dir/eligible.tsv"
applied_revision_path="$state_dir/applied-revision"
curl_config_path="$state_dir/curl.conf"
legacy_database_service_path="${HETERONETWORK_DB_LEGACY_SERVICE_PATH:-/etc/systemd/system/heteronetwork-db.service}"

log() {
  printf 'heteronetwork-postgres-autopilot: %s\n' "$*"
}

die() {
  printf 'heteronetwork-postgres-autopilot: error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "autopilot must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' is unavailable"
}

validate_config() {
  if [[ -z "${HETERONETWORK_DB_CLUSTER_ID:-}" \
    && -n "${HETERONETWORK_DB_CLUSTER_ID_B64:-}" ]]; then
    [[ "$HETERONETWORK_DB_CLUSTER_ID_B64" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] \
      || die "invalid encoded HeteroNetwork cluster ID"
    HETERONETWORK_DB_CLUSTER_ID="$(
      printf '%s' "$HETERONETWORK_DB_CLUSTER_ID_B64" | base64 -d
    )" || die "invalid encoded HeteroNetwork cluster ID"
    export HETERONETWORK_DB_CLUSTER_ID
  fi
  [[ "${HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN:-}" =~ ^[a-f0-9]{64}$ ]] \
    || die "invalid database autopilot bearer token"
  [[ -n "${HETERONETWORK_DB_CLUSTER_ID:-}" \
    && ${#HETERONETWORK_DB_CLUSTER_ID} -le 255 \
    && "$HETERONETWORK_DB_CLUSTER_ID" != *[[:cntrl:]]* ]] \
    || die "invalid HeteroNetwork cluster ID"
  [[ "${HETERONETWORK_DB_LOCAL_ROLE:-}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] \
    || die "invalid local node role"
  if [[ ! "$reconcile_interval_seconds" =~ ^[0-9]+$ ]] \
    || ((10#$reconcile_interval_seconds < 5 || 10#$reconcile_interval_seconds > 3600)); then
    die "reconcile interval must be between 5 and 3600 seconds"
  fi
  if [[ -n "${HETERONETWORK_DB_UNDERLAY_INTERFACE:-}" ]]; then
    [[ "$HETERONETWORK_DB_UNDERLAY_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] \
      || die "invalid database underlay interface"
    [[ "$HETERONETWORK_DB_UNDERLAY_INTERFACE" != "heteronetwork0" ]] \
      || die "database underlay interface must not be heteronetwork0"
  fi
}

install_coordination_dependencies() {
  [[ -f "$state_dir/dependencies.ready" ]] && return
  require_command apt-get
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update
  apt-get -o DPkg::Lock::Timeout=300 install --yes --no-install-recommends \
    ca-certificates curl iproute2 jq openssl python3 socat tar util-linux
  touch "$state_dir/dependencies.ready"
}

write_curl_config() {
  cat >"$curl_config_path" <<EOF
fail
silent
show-error
connect-timeout = 2
max-time = 15
header = "Authorization: Bearer ${HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN}"
EOF
  chmod 0600 "$curl_config_path"
}

agent_is_ready() {
  curl -fsS --connect-timeout 2 --max-time 5 "$agent_api_url/healthz" >/dev/null 2>&1
}

unmanaged_legacy_database_exists() {
  [[ -f "$legacy_database_service_path" && ! -d "$bundle_dir" ]]
}

read_agent_status() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/status"
}

read_peer_map() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/peers"
}

is_valid_ipv4() {
  local value="$1"
  local a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] \
    || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

candidate_ipv4_addresses() {
  jq -r '
    [
      .[]
      | select(.kind == "local_udp")
      | . as $candidate
      | try (
          .addr
          | capture("^(?<address>[0-9]+(?:\\.[0-9]+){3}):[0-9]+$")
          | {
              address: .address,
              priority: ($candidate.priority // 0),
              cost: ($candidate.cost // 4294967295)
            }
        )
    ]
    | sort_by([-.priority, .cost, .address])
    | .[].address
  '
}

select_underlay_candidate() {
  local candidates_json="$1"
  local forbidden_addresses="$2"
  local address
  while IFS= read -r address; do
    is_valid_ipv4 "$address" || continue
    if grep -Fxq "$address" <<<"$forbidden_addresses"; then
      continue
    fi
    printf '%s' "$address"
    return 0
  done < <(candidate_ipv4_addresses <<<"$candidates_json")
  return 1
}

local_identity_row() {
  local status vpn_ip node_id underlay_ip underlay_interface
  status="$(read_agent_status)" || return 1
  vpn_ip="$(jq -er \
    '.vpn_ip | select(type == "string" and test("^[0-9]+(\\.[0-9]+){3}$"))' \
    <<<"$status")" || return 1
  node_id="$(jq -er '.node_id | select(type == "string" and length > 0)' \
    <<<"$status")" || return 1
  underlay_interface="${HETERONETWORK_DB_UNDERLAY_INTERFACE:-}"
  if [[ -n "$underlay_interface" ]]; then
    underlay_ip="$(address_for_interface "$underlay_interface")" || return 1
  elif underlay_ip="$(address_for_interface tailscale0 2>/dev/null)"; then
    :
  else
    underlay_ip="$(select_underlay_candidate \
      "$(jq -c '.candidates // []' <<<"$status")" "$vpn_ip")" || return 1
  fi
  [[ "$underlay_ip" != "$vpn_ip" ]] || return 1
  underlay_interface="$(interface_for_address "$underlay_ip")" || return 1
  [[ "$underlay_interface" != "heteronetwork0" ]] || return 1
  printf '%s\t%s\t%s\n' "$vpn_ip" "$node_id" "$underlay_ip"
}

address_for_interface() {
  local interface="$1"
  ip -o -4 address show dev "$interface" scope global \
    | awk '
        {
          split($4, parts, "/")
          if (parts[1] != "") {
            count += 1
            address = parts[1]
          }
        }
        END {
          if (count != 1) {
            exit 1
          }
          print address
        }
      '
}

interface_for_address() {
  local address="$1"
  ip -o -4 address show scope global \
    | awk -v address="$address" '
        {
          split($4, parts, "/")
          if (parts[1] == address) {
            count += 1
            interface = $2
          }
        }
        END {
          if (count != 1) {
            exit 1
          }
          print interface
        }
      '
}

activate_overlay_discovery() {
  curl -fsS --connect-timeout 2 --max-time 5 \
    --header "Content-Type: application/json" \
    --data "$(
      jq -cn --arg destination "$1" --argjson port "$BUNDLE_PORT" '{
        destination: $destination,
        pin: false,
        protocol: "tcp",
        destination_port: $port,
        detector: "postgres-autopilot-discovery",
        application: "http",
        tcp_state: "syn_sent"
      }'
    )" \
    "$agent_api_url/v1/packet-flow" >/dev/null 2>&1 || true
}

underlay_from_member_descriptor() {
  local descriptor="$1"
  local expected_node_id="$2"
  jq -er \
    --arg node_id "$expected_node_id" \
    --arg network_plane "$DATABASE_NETWORK_PLANE" '
      select(.node_id == $node_id)
      | select(.network_plane == $network_plane)
      | .underlay_ip
      | select(type == "string")
    ' <<<"$descriptor"
}

peer_underlay_address() {
  local vpn_ip="$1"
  local expected_node_id="$2"
  local forbidden_addresses="$3"
  local descriptor underlay_ip
  activate_overlay_discovery "$vpn_ip"
  descriptor="$(curl --config "$curl_config_path" \
    "http://${vpn_ip}:${BUNDLE_PORT}/v1/postgres-ha/member" 2>/dev/null)" \
    || return 1
  underlay_ip="$(underlay_from_member_descriptor \
    "$descriptor" "$expected_node_id")" || return 1
  is_valid_ipv4 "$underlay_ip" || return 1
  grep -Fxq "$underlay_ip" <<<"$forbidden_addresses" && return 1
  peer_autopilot_is_ready "$underlay_ip" || return 1
  printf '%s' "$underlay_ip"
}

peer_autopilot_is_ready() {
  curl -fsS --connect-timeout 2 --max-time 5 \
    "http://$1:${BUNDLE_PORT}/health" >/dev/null 2>&1
}

validate_eligible_snapshot() {
  local path="$1"
  local vpn_ip node_id underlay_ip extra all_vpn_ips
  local -A seen_vpn_ips=()
  local -A seen_node_ids=()
  local -A seen_underlay_ips=()
  all_vpn_ips="$(cut -f1 "$path")"
  while IFS=$'\t' read -r vpn_ip node_id underlay_ip extra; do
    [[ -n "$vpn_ip" && -n "$node_id" && -n "$underlay_ip" && -z "${extra:-}" ]] \
      || return 1
    is_valid_ipv4 "$vpn_ip" || return 1
    is_valid_ipv4 "$underlay_ip" || return 1
    [[ "$vpn_ip" != "$underlay_ip" ]] || return 1
    grep -Fxq "$underlay_ip" <<<"$all_vpn_ips" && return 1
    [[ -z "${seen_vpn_ips[$vpn_ip]:-}" ]] || return 1
    [[ -z "${seen_node_ids[$node_id]:-}" ]] || return 1
    [[ -z "${seen_underlay_ips[$underlay_ip]:-}" ]] || return 1
    seen_vpn_ips["$vpn_ip"]=1
    seen_node_ids["$node_id"]=1
    seen_underlay_ips["$underlay_ip"]=1
  done <"$path"
}

write_eligible_snapshot() {
  local local_vpn_ip="$1"
  local local_node_id="$2"
  local local_underlay_ip="$3"
  local peers candidates temporary forbidden_addresses
  local vpn_ip node_id underlay_ip
  peers="$(read_peer_map)" || return 1
  forbidden_addresses="$(
    {
      printf '%s\n' "$local_vpn_ip"
      jq -r '
        .peers[]
        | select(.vpn_ip | type == "string")
        | .vpn_ip
      ' <<<"$peers"
    } | LC_ALL=C sort -u
  )" || return 1
  candidates="$(mktemp "$state_dir/eligible-candidates.XXXXXX")"
  temporary="$(mktemp "$state_dir/eligible.XXXXXX")"
  printf '%s\t%s\t%s\n' \
    "$local_vpn_ip" "$local_node_id" "$local_underlay_ip" >"$candidates"
  while IFS=$'\t' read -r vpn_ip node_id; do
    is_valid_ipv4 "$vpn_ip" || continue
    underlay_ip="$(peer_underlay_address \
      "$vpn_ip" "$node_id" "$forbidden_addresses")" \
      || continue
    printf '%s\t%s\t%s\n' "$vpn_ip" "$node_id" "$underlay_ip" >>"$candidates"
  done < <(
    jq -r '
      .peers[]
      | select(.role != "client")
      | select(.vpn_ip | type == "string" and test("^[0-9]+(\\.[0-9]+){3}$"))
      | [.vpn_ip, .node_id]
      | @tsv
    ' <<<"$peers"
  )
  if ! LC_ALL=C sort -V -u "$candidates" >"$temporary" \
    || ! validate_eligible_snapshot "$temporary"; then
    rm -f "$candidates" "$temporary"
    return 1
  fi
  if ! install -o root -g root -m 0600 "$temporary" "$eligible_path"; then
    rm -f "$candidates" "$temporary"
    return 1
  fi
  rm -f "$candidates" "$temporary"
}

eligible_count() {
  local count
  if [[ ! -f "$eligible_path" ]]; then
    printf '0\n'
    return
  fi
  count="$(wc -l <"$eligible_path" | tr -d '[:space:]')" || count=0
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  printf '%s\n' "$count"
}

initial_coordinator_underlay_ip() {
  awk -F '\t' 'NR == 1 { print $3 }' "$eligible_path"
}

manifest_value() {
  local directory="$1"
  local key="$2"
  awk -v key="$key" '
    index($0, key "=") == 1 {
      count += 1
      value = substr($0, length(key) + 2)
    }
    END {
      if (count != 1 || value == "") {
        exit 1
      }
      print value
    }
  ' "$directory/manifest.env"
}

load_bundle_manifest() {
  local directory="$1"
  [[ -f "$directory/manifest.env" && ! -L "$directory/manifest.env" ]] \
    || return 1
  manifest_cluster_name="$(manifest_value "$directory" HETERONETWORK_DB_CLUSTER_NAME)"
  manifest_members="$(manifest_value "$directory" HETERONETWORK_DB_MEMBERS)"
  manifest_dcs_members="$(manifest_value "$directory" HETERONETWORK_DB_DCS_MEMBERS)"
  manifest_service_name="$(manifest_value "$directory" HETERONETWORK_DB_SERVICE_NAME)"
  manifest_postgres_port="$(manifest_value "$directory" HETERONETWORK_DB_POSTGRES_PORT)"
  manifest_rest_port="$(manifest_value "$directory" HETERONETWORK_DB_REST_PORT)"
  manifest_revision="$(manifest_value "$directory" HETERONETWORK_DB_TOPOLOGY_REVISION)"
  manifest_network_plane="$(manifest_value "$directory" HETERONETWORK_DB_NETWORK_PLANE)"
  [[ "$manifest_revision" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$manifest_network_plane" == "$DATABASE_NETWORK_PLANE" ]] || return 1
  [[ -f "$directory/cluster-id" && ! -L "$directory/cluster-id" ]] || return 1
  [[ "$(<"$directory/cluster-id")" == "$HETERONETWORK_DB_CLUSTER_ID" ]] || return 1
}

run_helper_for_bundle() {
  local directory="$1"
  shift
  load_bundle_manifest "$directory" || die "invalid database bundle manifest"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_INTERFACE=${HETERONETWORK_DB_INTERFACE:-}" \
    "HETERONETWORK_DB_NODE_NAME=${HETERONETWORK_DB_NODE_NAME:-db-a}" \
    "HETERONETWORK_DB_NODE_ADDRESS=${HETERONETWORK_DB_NODE_ADDRESS:-10.255.255.254}" \
    "HETERONETWORK_DB_MEMBERS=$manifest_members" \
    "HETERONETWORK_DB_DCS_MEMBERS=$manifest_dcs_members" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$manifest_members" \
    "HETERONETWORK_DB_BUNDLE_DIR=$directory" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$manifest_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$manifest_network_plane" \
    "$helper" "$@"
}

validate_bundle_directory() {
  local directory="$1"
  load_bundle_manifest "$directory" || return 1
  run_helper_for_bundle "$directory" validate-bundle "$directory" >/dev/null 2>&1
}

safe_extract_bundle() {
  local archive="$1"
  local destination="$2"
  python3 - "$archive" "$destination" <<'PY'
import os
import pathlib
import shutil
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
destination.mkdir(mode=0o700, parents=True, exist_ok=False)
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        parts = tuple(part for part in path.parts if part not in ("", "."))
        if path.is_absolute() or ".." in parts:
            raise SystemExit("unsafe path in database bundle")
        if not member.isdir() and not member.isfile():
            raise SystemExit("non-regular object in database bundle")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        parts = tuple(part for part in path.parts if part not in ("", "."))
        if not parts:
            continue
        target = destination.joinpath(*parts)
        if member.isdir():
            target.mkdir(mode=member.mode & 0o777, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source = bundle.extractfile(member)
        if source is None:
            raise SystemExit("missing regular file payload in database bundle")
        with source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        os.chmod(target, member.mode & 0o777)
PY
}

install_bundle_directory() {
  local source="$1"
  validate_bundle_directory "$source" || die "downloaded database bundle failed validation"
  local previous="$state_dir/bundle.previous"
  rm -rf "$previous"
  if [[ -d "$bundle_dir" ]]; then
    mv "$bundle_dir" "$previous"
  fi
  if ! mv "$source" "$bundle_dir"; then
    [[ ! -d "$previous" ]] || mv "$previous" "$bundle_dir"
    die "failed to atomically install the database bundle"
  fi
  rm -rf "$previous"
}

write_bundle_handlers() {
  cat >"$state_dir/serve-bundle.sh" <<'EOF'
#!/bin/sh
set -eu
. /etc/heteronetwork/postgres-autopilot/bundle-server.env
request=
authorized=
IFS= read -r request || true
request=$(printf '%s' "$request" | tr -d '\r')
while IFS= read -r line; do
  line=$(printf '%s' "$line" | tr -d '\r')
  [ -n "$line" ] || break
  [ "$line" = "Authorization: Bearer $BUNDLE_BEARER_TOKEN" ] && authorized=1
done
if [ -z "$authorized" ]; then
  body=unauthorized
  printf 'HTTP/1.1 401 Unauthorized\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
    "${#body}" "$body"
  exit 0
fi
case "$request" in
  "GET /health HTTP/1.1")
    body=ready
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "${#body}" "$body"
    ;;
  "GET /v1/postgres-ha/member HTTP/1.1")
    if [ ! -s "$MEMBER_DESCRIPTOR" ]; then
      body=waiting
      printf 'HTTP/1.1 503 Service Unavailable\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "${#body}" "$body"
      exit 0
    fi
    length=$(wc -c <"$MEMBER_DESCRIPTOR" | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n' \
      "$length"
    cat "$MEMBER_DESCRIPTOR"
    ;;
  "GET /v1/postgres-ha/bundle HTTP/1.1")
    if [ ! -s "$BUNDLE_ARCHIVE" ]; then
      body=waiting
      printf 'HTTP/1.1 503 Service Unavailable\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "${#body}" "$body"
      exit 0
    fi
    length=$(wc -c <"$BUNDLE_ARCHIVE" | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n' \
      "$length"
    cat "$BUNDLE_ARCHIVE"
    ;;
  *)
    body='not found'
    printf 'HTTP/1.1 404 Not Found\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "${#body}" "$body"
    ;;
esac
EOF
  chmod 0700 "$state_dir/serve-bundle.sh"

  cat >"$state_dir/serve-underlay-health.sh" <<'EOF'
#!/bin/sh
set -eu
request=
IFS= read -r request || true
request=$(printf '%s' "$request" | tr -d '\r')
while IFS= read -r line; do
  line=$(printf '%s' "$line" | tr -d '\r')
  [ -n "$line" ] || break
done
case "$request" in
  "GET /health HTTP/1.1")
    body=ready
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "${#body}" "$body"
    ;;
  *)
    body='not found'
    printf 'HTTP/1.1 404 Not Found\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "${#body}" "$body"
    ;;
esac
EOF
  chmod 0700 "$state_dir/serve-underlay-health.sh"
}

render_bundle_listener_unit() {
  local description="$1"
  local listen_address="$2"
  local handler="$3"
  local dependencies="$4"
  cat <<EOF
[Unit]
Description=${description}
${dependencies}

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:${BUNDLE_PORT},bind=${listen_address},reuseaddr,fork EXEC:${handler},nofork
Restart=always
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=${state_dir}
RestrictAddressFamilies=AF_INET AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
}

install_bundle_listener_unit() {
  local service_name="$1"
  local description="$2"
  local listen_address="$3"
  local handler="$4"
  local dependencies="$5"
  local unit_name="${service_name}.service"
  local unit_path="/etc/systemd/system/${unit_name}"
  local unit_temporary unit_changed=0
  unit_temporary="$(mktemp "$state_dir/${unit_name}.XXXXXX")"
  render_bundle_listener_unit \
    "$description" "$listen_address" "$handler" "$dependencies" \
    >"$unit_temporary"
  if [[ ! -f "$unit_path" ]] || ! cmp -s "$unit_temporary" "$unit_path"; then
    install -o root -g root -m 0644 "$unit_temporary" "$unit_path"
    unit_changed=1
  fi
  rm -f "$unit_temporary"
  ((unit_changed == 0)) || systemctl daemon-reload
  systemctl enable "$unit_name" >/dev/null
  if ! systemctl is-active --quiet "$unit_name"; then
    systemctl start "$unit_name"
  elif ((unit_changed == 1)); then
    systemctl restart "$unit_name"
  fi
}

start_bundle_servers() {
  local vpn_ip="$1"
  local node_id="$2"
  local underlay_ip="$3"
  local descriptor_temporary
  descriptor_temporary="$(mktemp "$state_dir/member.json.XXXXXX")"
  jq -cn \
    --arg node_id "$node_id" \
    --arg underlay_ip "$underlay_ip" \
    --arg network_plane "$DATABASE_NETWORK_PLANE" \
    '{node_id: $node_id, underlay_ip: $underlay_ip, network_plane: $network_plane}' \
    >"$descriptor_temporary"
  chmod 0600 "$descriptor_temporary"
  mv "$descriptor_temporary" "$state_dir/member.json"
  cat >"$state_dir/bundle-server.env" <<EOF
BUNDLE_BEARER_TOKEN=${HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN}
BUNDLE_ARCHIVE=${bundle_archive}
MEMBER_DESCRIPTOR=${state_dir}/member.json
EOF
  chmod 0600 "$state_dir/bundle-server.env"
  write_bundle_handlers
  install_bundle_listener_unit \
    heteronetwork-postgres-bundle \
    "HeteroNetwork PostgreSQL HA overlay discovery and bundle endpoint" \
    "$vpn_ip" \
    "$state_dir/serve-bundle.sh" \
    $'Requires=heteronetwork-agent.service\nAfter=heteronetwork-agent.service'
  install_bundle_listener_unit \
    heteronetwork-postgres-underlay-probe \
    "HeteroNetwork PostgreSQL HA underlay reachability endpoint" \
    "$underlay_ip" \
    "$state_dir/serve-underlay-health.sh" \
    $'Wants=network-online.target\nAfter=network-online.target'
}

publish_bundle_archive() {
  [[ -d "$bundle_dir" ]] || return
  local temporary
  temporary="$(mktemp "$state_dir/bundle.tar.gz.XXXXXX")"
  tar --format=ustar --create --gzip --file "$temporary" --directory "$bundle_dir" .
  chmod 0600 "$temporary"
  mv "$temporary" "$bundle_archive"
}

download_best_bundle() {
  local current_revision=0
  if load_bundle_manifest "$bundle_dir" 2>/dev/null; then
    current_revision="$manifest_revision"
  fi
  local best_revision="$current_revision"
  local best_directory=""
  local vpn_ip _node_id _underlay_ip archive extracted candidate_revision
  while IFS=$'\t' read -r vpn_ip _node_id _underlay_ip; do
    archive="$(mktemp "$state_dir/download.XXXXXX")"
    if ! curl --config "$curl_config_path" \
      "http://${vpn_ip}:${BUNDLE_PORT}/v1/postgres-ha/bundle" \
      --output "$archive" 2>/dev/null; then
      rm -f "$archive"
      continue
    fi
    extracted="$state_dir/downloaded.$RANDOM.$RANDOM"
    if ! safe_extract_bundle "$archive" "$extracted" >/dev/null 2>&1 \
      || ! validate_bundle_directory "$extracted" \
      || bundle_uses_snapshot_vpn_address "$extracted"; then
      rm -f "$archive"
      rm -rf "$extracted"
      continue
    fi
    candidate_revision="$manifest_revision"
    rm -f "$archive"
    if ((10#$candidate_revision > 10#$best_revision)); then
      [[ -z "$best_directory" ]] || rm -rf "$best_directory"
      best_revision="$candidate_revision"
      best_directory="$extracted"
    else
      rm -rf "$extracted"
    fi
  done <"$eligible_path"

  if [[ -n "$best_directory" ]]; then
    install_bundle_directory "$best_directory"
    publish_bundle_archive
    log "installed replicated database topology revision $best_revision"
  fi
}

member_name_for_index() {
  python3 - "$1" <<'PY'
import string
import sys

index = int(sys.argv[1])
if not 0 <= index < 32:
    raise SystemExit("database member index is outside 0-31")
if index < 26:
    suffix = string.ascii_lowercase[index]
else:
    suffix = "a" + string.ascii_lowercase[index - 26]
print(f"db-{suffix}")
PY
}

initial_members_from_snapshot() {
  local output="" index=0 _vpn_ip _node_id underlay_ip name
  while IFS=$'\t' read -r _vpn_ip _node_id underlay_ip; do
    ((index < MAX_DATABASE_MEMBER_COUNT)) || break
    name="$(member_name_for_index "$index")"
    [[ -z "$output" ]] || output+=","
    output+="${name}=${underlay_ip}"
    index=$((index + 1))
  done <"$eligible_path"
  printf '%s' "$output"
}

first_members() {
  local input="$1"
  local count="$2"
  python3 - "$input" "$count" <<'PY'
import sys

members = sys.argv[1].split(",")
count = int(sys.argv[2])
if len(members) < count:
    raise SystemExit("not enough database members")
print(",".join(members[:count]))
PY
}

expand_members_from_snapshot() {
  python3 - "$1" "$eligible_path" "$MAX_DATABASE_MEMBER_COUNT" <<'PY'
import string
import sys

current = sys.argv[1].split(",")
snapshot = sys.argv[2]
limit = int(sys.argv[3])
addresses = {entry.split("=", 1)[1] for entry in current}
with open(snapshot, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 3:
            raise SystemExit("invalid eligible database member row")
        address = fields[2]
        if address in addresses or len(current) >= limit:
            continue
        index = len(current)
        suffix = string.ascii_lowercase[index] if index < 26 else "a" + string.ascii_lowercase[index - 26]
        current.append(f"db-{suffix}={address}")
        addresses.add(address)
print(",".join(current))
PY
}

member_count() {
  tr ',' '\n' <<<"$1" | wc -l | tr -d ' '
}

next_dcs_topology() {
  local all_members="$1"
  local current_dcs="$2"
  python3 - "$all_members" "$current_dcs" <<'PY'
import sys

members = sys.argv[1].split(",")
dcs = sys.argv[2].split(",")
dcs_names = {entry.split("=", 1)[0] for entry in dcs}
for entry in members:
    if entry.split("=", 1)[0] not in dcs_names:
        print(",".join([*dcs, entry]))
        break
else:
    raise SystemExit("no database member is available for DCS expansion")
PY
}

member_name_for_ip() {
  local input="$1"
  local address="$2"
  tr ',' '\n' <<<"$input" \
    | awk -F= -v address="$address" '$2 == address { print $1; found = 1 } END { if (!found) exit 1 }'
}

bundle_uses_snapshot_vpn_address() {
  local directory="$1"
  load_bundle_manifest "$directory" || return 0
  local vpn_ip _node_id _underlay_ip
  while IFS=$'\t' read -r vpn_ip _node_id _underlay_ip; do
    if member_name_for_ip "$manifest_members" "$vpn_ip" >/dev/null 2>&1; then
      return 0
    fi
  done <"$eligible_path"
  return 1
}

configure_helper_environment() {
  local directory="$1"
  local local_underlay_ip="$2"
  load_bundle_manifest "$directory" || die "database bundle manifest is unavailable"
  HETERONETWORK_DB_NODE_NAME="$(
    member_name_for_ip "$manifest_members" "$local_underlay_ip"
  )"
  HETERONETWORK_DB_NODE_ADDRESS="$local_underlay_ip"
  HETERONETWORK_DB_INTERFACE="$(interface_for_address "$local_underlay_ip")" \
    || die "database underlay address $local_underlay_ip is not assigned to exactly one interface"
  [[ "$HETERONETWORK_DB_INTERFACE" != "heteronetwork0" ]] \
    || die "database services must not bind to the HeteroNetwork overlay interface"
  export HETERONETWORK_DB_INTERFACE HETERONETWORK_DB_NODE_NAME HETERONETWORK_DB_NODE_ADDRESS
}

apply_local_bundle() {
  local local_underlay_ip="$1"
  load_bundle_manifest "$bundle_dir" || return
  local local_name
  if ! local_name="$(member_name_for_ip "$manifest_members" "$local_underlay_ip")"; then
    log "node is outside the ${MAX_DATABASE_MEMBER_COUNT}-member database replica limit"
    return
  fi
  configure_helper_environment "$bundle_dir" "$local_underlay_ip"
  local applied_revision=0
  [[ -f "$applied_revision_path" ]] && applied_revision="$(<"$applied_revision_path")"
  if [[ "$applied_revision" == "$manifest_revision" ]] \
    && systemctl is-active --quiet heteronetwork-db.service; then
    return
  fi
  local initial_state="existing"
  [[ "$manifest_revision" == "1" ]] && initial_state="new"
  log "applying database topology revision $manifest_revision as $local_name"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_INTERFACE=$HETERONETWORK_DB_INTERFACE" \
    "HETERONETWORK_DB_NODE_NAME=$local_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$local_underlay_ip" \
    "HETERONETWORK_DB_MEMBERS=$manifest_members" \
    "HETERONETWORK_DB_DCS_MEMBERS=$manifest_dcs_members" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=$initial_state" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$manifest_members" \
    "HETERONETWORK_DB_BUNDLE_DIR=$bundle_dir" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$manifest_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$manifest_network_plane" \
    "$helper" reconfigure-node
  printf '%s\n' "$manifest_revision" >"$applied_revision_path"
  chmod 0600 "$applied_revision_path"
}

bootstrap_bundle() {
  local members dcs_count dcs temporary
  members="$(initial_members_from_snapshot)"
  local count
  count="$(member_count "$members")"
  ((10#$count >= MIN_DATABASE_MEMBER_COUNT)) \
    || die "at least $MIN_DATABASE_MEMBER_COUNT ready Linux nodes are required"
  dcs_count="$MIN_DATABASE_MEMBER_COUNT"
  ((10#$count >= TARGET_DCS_MEMBER_COUNT)) && dcs_count="$TARGET_DCS_MEMBER_COUNT"
  dcs="$(first_members "$members" "$dcs_count")"
  temporary="$state_dir/bootstrap.$RANDOM.$RANDOM"
  env \
    "HETERONETWORK_DB_MEMBERS=$members" \
    "HETERONETWORK_DB_DCS_MEMBERS=$dcs" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=new" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=1" \
    "HETERONETWORK_DB_NETWORK_PLANE=$DATABASE_NETWORK_PLANE" \
    "$helper" init-bundle "$temporary"
  printf '%s\n' "$HETERONETWORK_DB_CLUSTER_ID" >"$temporary/cluster-id"
  chmod 0600 "$temporary/cluster-id"
  install_bundle_directory "$temporary"
  publish_bundle_archive
  log "created automatic database topology with $count replicas and $dcs_count DCS voters"
}

coordinator_underlay_ip_for_bundle() {
  local _vpn_ip _node_id underlay_ip
  while IFS=$'\t' read -r _vpn_ip _node_id underlay_ip; do
    if member_name_for_ip "$manifest_members" "$underlay_ip" >/dev/null 2>&1; then
      printf '%s' "$underlay_ip"
      return
    fi
  done <"$eligible_path"
  return 1
}

stage_topology() {
  local new_members="$1"
  local new_dcs="$2"
  local new_revision="$3"
  local local_underlay_ip="$4"
  local stage="$state_dir/stage.$RANDOM.$RANDOM"
  cp -a "$bundle_dir" "$stage"
  local local_name
  local_name="$(member_name_for_ip "$manifest_members" "$local_underlay_ip")"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_INTERFACE=$HETERONETWORK_DB_INTERFACE" \
    "HETERONETWORK_DB_NODE_NAME=$local_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$local_underlay_ip" \
    "HETERONETWORK_DB_MEMBERS=$new_members" \
    "HETERONETWORK_DB_DCS_MEMBERS=$new_dcs" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$new_members" \
    "HETERONETWORK_DB_BUNDLE_DIR=$stage" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$new_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$manifest_network_plane" \
    "$helper" extend-bundle "$stage" >/dev/null
  printf '%s\n' "$HETERONETWORK_DB_CLUSTER_ID" >"$stage/cluster-id"
  chmod 0600 "$stage/cluster-id"
  printf '%s' "$stage"
}

reconcile_as_coordinator() {
  local local_underlay_ip="$1"
  configure_helper_environment "$bundle_dir" "$local_underlay_ip"
  local dcs_result=""
  if systemctl is-active --quiet heteronetwork-db.service; then
    dcs_result="$(run_helper_for_bundle "$bundle_dir" reconcile-dcs 2>&1)" || {
      log "DCS reconciliation is waiting: $dcs_result"
      return
    }
    log "$dcs_result"
  fi

  load_bundle_manifest "$bundle_dir"
  local new_members new_dcs members_changed=0 dcs_changed=0
  new_members="$(expand_members_from_snapshot "$manifest_members")"
  new_dcs="$manifest_dcs_members"
  [[ "$new_members" == "$manifest_members" ]] || members_changed=1

  local dcs_count database_count
  dcs_count="$(member_count "$manifest_dcs_members")"
  database_count="$(member_count "$new_members")"
  if ((10#$dcs_count < TARGET_DCS_MEMBER_COUNT \
      && 10#$database_count >= TARGET_DCS_MEMBER_COUNT)) \
    && [[ "$dcs_result" == *"already matches the requested topology."* ]]; then
    new_dcs="$(next_dcs_topology "$new_members" "$manifest_dcs_members")"
    dcs_changed=1
  fi
  if ((members_changed == 0 && dcs_changed == 0)); then
    if systemctl is-active --quiet heteronetwork-db.service; then
      run_helper_for_bundle "$bundle_dir" reconcile-patroni >/dev/null 2>&1 || true
    fi
    return
  fi

  local next_revision stage
  next_revision="$((10#$manifest_revision + 1))"
  stage="$(stage_topology \
    "$new_members" "$new_dcs" "$next_revision" "$local_underlay_ip")"
  if ((dcs_changed == 1)); then
    configure_helper_environment "$stage" "$local_underlay_ip"
    run_helper_for_bundle "$stage" reconcile-dcs
  fi
  install_bundle_directory "$stage"
  publish_bundle_archive
  log "published database topology revision $next_revision"
  apply_local_bundle "$local_underlay_ip"
  run_helper_for_bundle "$bundle_dir" reconcile-patroni >/dev/null 2>&1 || true
}

reconcile_once() {
  local identity local_vpn_ip local_node_id local_underlay_ip
  identity="$(local_identity_row)" || {
    log "waiting for a non-overlay local UDP underlay candidate"
    return
  }
  IFS=$'\t' read -r local_vpn_ip local_node_id local_underlay_ip <<<"$identity"
  if unmanaged_legacy_database_exists; then
    log "existing database is not managed by autopilot; refusing a new bootstrap"
    return
  fi
  start_bundle_servers "$local_vpn_ip" "$local_node_id" "$local_underlay_ip"
  if ! write_eligible_snapshot \
    "$local_vpn_ip" "$local_node_id" "$local_underlay_ip"; then
    log "waiting for a valid underlay database peer map"
    return
  fi
  if [[ -d "$bundle_dir" ]] && ! load_bundle_manifest "$bundle_dir"; then
    log "existing database bundle lacks the ${DATABASE_NETWORK_PLANE} contract; refusing automatic migration"
    return
  fi
  if [[ -d "$bundle_dir" ]] && bundle_uses_snapshot_vpn_address "$bundle_dir"; then
    log "database bundle contains an overlay VPN address; refusing to apply it"
    return
  fi
  download_best_bundle

  if [[ ! -d "$bundle_dir" ]]; then
    local count
    count="$(eligible_count)"
    if ((10#$count < MIN_DATABASE_MEMBER_COUNT)); then
      log "waiting for $MIN_DATABASE_MEMBER_COUNT ready Linux nodes ($count ready)"
      return
    fi
    if [[ "$local_underlay_ip" != "$(initial_coordinator_underlay_ip)" ]]; then
      log "waiting for the initial database coordinator"
      return
    fi
    bootstrap_bundle
  fi

  publish_bundle_archive
  apply_local_bundle "$local_underlay_ip"
  load_bundle_manifest "$bundle_dir"
  local coordinator_underlay_ip
  coordinator_underlay_ip="$(coordinator_underlay_ip_for_bundle)" || {
    log "no reachable database coordinator is available"
    return
  }
  if [[ "$local_underlay_ip" == "$coordinator_underlay_ip" ]]; then
    reconcile_as_coordinator "$local_underlay_ip"
  fi
}

run_autopilot() {
  require_root
  [[ -f "$config_path" ]] || die "autopilot configuration is missing"
  # shellcheck disable=SC1090
  . "$config_path"
  validate_config
  [[ "$HETERONETWORK_DB_LOCAL_ROLE" != "client" ]] \
    || die "client nodes cannot host database replicas"
  [[ -x "$helper" ]] || die "PostgreSQL HA helper is missing"
  install -d -o root -g root -m 0700 "$state_dir"
  install_coordination_dependencies
  for command in base64 cmp curl flock ip jq openssl python3 socat systemctl tar; do
    require_command "$command"
  done
  write_curl_config
  until agent_is_ready; do
    log "waiting for the local HeteroNetwork Agent"
    sleep 3
  done

  exec 9>"$state_dir/autopilot.lock"
  flock -n 9 || die "another database autopilot process is active"
  while true; do
    reconcile_once
    sleep "$reconcile_interval_seconds"
  done
}

self_test() {
  local temporary script_dir
  temporary="$(mktemp -d /tmp/heteronetwork-postgres-autopilot.XXXXXX)"
  trap 'rm -rf "$temporary"' RETURN
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  helper="$script_dir/postgres-ha-node.sh"
  state_dir="$temporary/state"
  bundle_dir="$state_dir/bundle"
  bundle_archive="$state_dir/bundle.tar.gz"
  applied_revision_path="$state_dir/applied-revision"
  install -d -m 0700 "$state_dir"
  legacy_database_service_path="$temporary/heteronetwork-db.service"
  HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN="$(printf 'a%.0s' {1..64})"
  HETERONETWORK_DB_CLUSTER_ID="cluster-test"
  HETERONETWORK_DB_LOCAL_ROLE="worker"
  reconcile_interval_seconds=30
  validate_config
  if (
    HETERONETWORK_DB_UNDERLAY_INTERFACE="heteronetwork0"
    validate_config >/dev/null 2>&1
  ); then
    die "overlay underlay-interface self-test unexpectedly succeeded"
  fi
  touch "$legacy_database_service_path"
  unmanaged_legacy_database_exists
  rm -f "$legacy_database_service_path"
  if unmanaged_legacy_database_exists; then
    die "legacy database guard remained active without a service"
  fi
  eligible_path="$temporary/eligible.tsv"
  [[ "$(eligible_count)" == "0" ]]
  local selected_candidate candidate_fixture
  candidate_fixture='[
    {"kind":"local_udp","addr":"10.250.0.2:51820","priority":100,"cost":1},
    {"kind":"public_udp","addr":"203.0.113.20:51820","priority":90,"cost":10},
    {"kind":"local_udp","addr":"100.123.154.79:51820","priority":80,"cost":20}
  ]'
  selected_candidate="$(select_underlay_candidate \
    "$candidate_fixture" $'10.250.0.2\n10.250.0.3')"
  [[ "$selected_candidate" == "100.123.154.79" ]]
  if select_underlay_candidate \
    '[{"kind":"local_udp","addr":"10.250.0.2:51820"}]' \
    "10.250.0.2" >/dev/null; then
    die "overlay-only database candidate was accepted"
  fi
  local descriptor
  descriptor='{
    "node_id":"node-a",
    "underlay_ip":"100.123.154.79",
    "network_plane":"underlay-v1"
  }'
  [[ "$(underlay_from_member_descriptor "$descriptor" node-a)" == "100.123.154.79" ]]
  if underlay_from_member_descriptor "$descriptor" node-b >/dev/null 2>&1; then
    die "member descriptor with the wrong node identity was accepted"
  fi
  if underlay_from_member_descriptor \
    '{"node_id":"node-a","underlay_ip":"100.123.154.79","network_plane":"overlay"}' \
    node-a >/dev/null 2>&1; then
    die "member descriptor with the wrong network plane was accepted"
  fi
  write_bundle_handlers
  sh -n "$state_dir/serve-bundle.sh"
  sh -n "$state_dir/serve-underlay-health.sh"
  grep -Fq 'GET /v1/postgres-ha/member HTTP/1.1' "$state_dir/serve-bundle.sh"
  grep -Fq 'GET /v1/postgres-ha/bundle HTTP/1.1' "$state_dir/serve-bundle.sh"
  if grep -Fq 'GET /v1/postgres-ha/bundle HTTP/1.1' \
    "$state_dir/serve-underlay-health.sh"; then
    die "underlay health handler unexpectedly serves the private database bundle"
  fi
  if grep -Fq 'BUNDLE_BEARER_TOKEN' "$state_dir/serve-underlay-health.sh"; then
    die "underlay health handler unexpectedly exposes the bundle bearer"
  fi
  render_bundle_listener_unit \
    "underlay probe" \
    "100.123.154.79" \
    "$state_dir/serve-underlay-health.sh" \
    $'Wants=network-online.target\nAfter=network-online.target' \
    >"$temporary/underlay.service"
  grep -Fq 'bind=100.123.154.79' "$temporary/underlay.service"
  if grep -Fq 'heteronetwork-agent.service' "$temporary/underlay.service"; then
    die "underlay probe unexpectedly depends on the Agent"
  fi
  render_bundle_listener_unit \
    "overlay bundle" \
    "10.250.0.2" \
    "$state_dir/serve-bundle.sh" \
    $'Requires=heteronetwork-agent.service\nAfter=heteronetwork-agent.service' \
    >"$temporary/bundle.service"
  grep -Fq 'bind=10.250.0.2' "$temporary/bundle.service"
  grep -Fq 'Requires=heteronetwork-agent.service' "$temporary/bundle.service"

  printf '%s\n' \
    $'10.250.0.10\tnode-c\t163.220.236.52' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    | LC_ALL=C sort -V >"$eligible_path"
  validate_eligible_snapshot "$eligible_path"
  printf '%s\n' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.123.154.79' \
    >"$temporary/duplicate-underlay.tsv"
  if validate_eligible_snapshot "$temporary/duplicate-underlay.tsv"; then
    die "duplicate database underlay address was accepted"
  fi
  [[ "$(initial_coordinator_underlay_ip)" == "100.123.154.79" ]]
  local generated
  generated="$(initial_members_from_snapshot)"
  [[ "$generated" == \
    "db-a=100.123.154.79,db-b=100.89.33.61,db-c=163.220.236.52" ]]
  [[ "$generated" != *"10.250."* ]]
  generated="$(expand_members_from_snapshot \
    "db-a=100.123.154.79,db-b=100.89.33.61,db-c=163.220.236.52")"
  [[ "$(member_count "$generated")" == "3" ]]
  [[ "$(member_name_for_index 31)" == "db-af" ]]
  bootstrap_bundle >/dev/null 2>&1
  load_bundle_manifest "$bundle_dir"
  [[ "$(member_count "$manifest_members")" == "3" ]]
  [[ "$(member_count "$manifest_dcs_members")" == "3" ]]
  [[ "$manifest_revision" == "1" ]]
  [[ "$manifest_network_plane" == "$DATABASE_NETWORK_PLANE" ]]
  if bundle_uses_snapshot_vpn_address "$bundle_dir"; then
    die "underlay database bundle was classified as overlay-dependent"
  fi

  printf '%s\n' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    $'10.250.0.4\tnode-d\t163.220.236.51' \
    $'10.250.0.5\tnode-e\t100.94.130.38' \
    $'10.250.0.10\tnode-c\t163.220.236.52' \
    | LC_ALL=C sort -V >"$eligible_path"
  validate_eligible_snapshot "$eligible_path"
  generated="$(expand_members_from_snapshot "$manifest_members")"
  [[ "$(member_count "$generated")" == "5" ]]
  [[ "$generated" != *"10.250."* ]]
  local dcs_four dcs_five
  dcs_four="$(next_dcs_topology "$generated" "$manifest_dcs_members")"
  dcs_five="$(next_dcs_topology "$generated" "$dcs_four")"
  [[ "$(member_count "$dcs_four")" == "4" ]]
  [[ "$(member_count "$dcs_five")" == "5" ]]

  publish_bundle_archive
  local extracted="$state_dir/extracted"
  safe_extract_bundle "$bundle_archive" "$extracted"
  validate_bundle_directory "$extracted"
  local legacy_bundle="$state_dir/legacy-bundle"
  cp -a "$extracted" "$legacy_bundle"
  sed -i '/^HETERONETWORK_DB_NETWORK_PLANE=/d' "$legacy_bundle/manifest.env"
  if validate_bundle_directory "$legacy_bundle" >/dev/null 2>&1; then
    die "database bundle without an underlay contract was accepted"
  fi
  local malicious="$state_dir/malicious.tar.gz"
  python3 - "$malicious" <<'PY'
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz") as archive:
    entry = tarfile.TarInfo("../escape")
    entry.size = 1
    archive.addfile(entry, io.BytesIO(b"x"))
PY
  if safe_extract_bundle "$malicious" "$state_dir/unsafe" >/dev/null 2>&1; then
    die "unsafe archive self-test unexpectedly succeeded"
  fi
  [[ ! -e "$temporary/escape" ]]
  rm -rf "$temporary"
  trap - RETURN
  log "autopilot self-test passed"
}

case "${1:-}" in
  run) run_autopilot ;;
  self-test) self_test ;;
  *) printf 'Usage: postgres-ha-autopilot.sh {run|self-test}\n' >&2; exit 2 ;;
esac
