#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_AGENT_API_URL="http://127.0.0.1:9780"
readonly DEFAULT_STATE_DIR="/etc/heteronetwork/postgres-autopilot"
readonly DEFAULT_RECONCILE_INTERVAL_SECONDS="30"
readonly MIN_DATABASE_MEMBER_COUNT="3"
readonly MAX_DATABASE_MEMBER_COUNT="32"
readonly TARGET_DCS_MEMBER_COUNT="5"
readonly BUNDLE_PORT="17446"

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
}

install_coordination_dependencies() {
  [[ -f "$state_dir/dependencies.ready" ]] && return
  require_command apt-get
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update
  apt-get -o DPkg::Lock::Timeout=300 install --yes --no-install-recommends \
    ca-certificates curl iputils-ping jq openssl python3 socat tar util-linux
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

read_agent_status() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/status"
}

read_peer_map() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/peers"
}

local_vpn_ip() {
  read_agent_status \
    | jq -er '.vpn_ip | select(type == "string" and test("^[0-9]+(\\.[0-9]+){3}$"))'
}

peer_autopilot_is_ready() {
  curl --config "$curl_config_path" \
    "http://$1:${BUNDLE_PORT}/health" >/dev/null 2>&1
}

write_eligible_snapshot() {
  local status peers local_ip local_node_id candidates temporary ip node_id
  status="$(read_agent_status)" || return 1
  peers="$(read_peer_map)" || return 1
  local_ip="$(jq -er \
    '.vpn_ip | select(type == "string" and test("^[0-9]+(\\.[0-9]+){3}$"))' \
    <<<"$status")" || return 1
  local_node_id="$(jq -er '.node_id | select(type == "string" and length > 0)' \
    <<<"$status")" || return 1
  candidates="$(mktemp "$state_dir/eligible-candidates.XXXXXX")"
  temporary="$(mktemp "$state_dir/eligible.XXXXXX")"
  {
    printf '%s\t%s\n' "$local_ip" "$local_node_id"
    jq -r '
      .peers[]
      | select(.role != "client")
      | select(.vpn_ip | type == "string" and test("^[0-9]+(\\.[0-9]+){3}$"))
      | [.vpn_ip, .node_id]
      | @tsv
    ' <<<"$peers"
  } | LC_ALL=C sort -V -u >"$candidates"

  while IFS=$'\t' read -r ip node_id; do
    if [[ "$ip" == "$local_ip" ]] || peer_autopilot_is_ready "$ip"; then
      printf '%s\t%s\n' "$ip" "$node_id" >>"$temporary"
    fi
  done <"$candidates"
  install -o root -g root -m 0600 "$temporary" "$eligible_path"
  rm -f "$candidates" "$temporary"
}

eligible_count() {
  wc -l <"$eligible_path" | tr -d ' '
}

initial_coordinator_ip() {
  sed -n '1s/\t.*//p' "$eligible_path"
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
  [[ "$manifest_revision" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ -f "$directory/cluster-id" && ! -L "$directory/cluster-id" ]] || return 1
  [[ "$(<"$directory/cluster-id")" == "$HETERONETWORK_DB_CLUSTER_ID" ]] || return 1
}

run_helper_for_bundle() {
  local directory="$1"
  shift
  load_bundle_manifest "$directory" || die "invalid database bundle manifest"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_INTERFACE=${HETERONETWORK_DB_INTERFACE:-heteronetwork0}" \
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

write_bundle_handler() {
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
}

start_bundle_server() {
  local local_ip="$1"
  cat >"$state_dir/bundle-server.env" <<EOF
BUNDLE_BEARER_TOKEN=${HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN}
BUNDLE_ARCHIVE=${bundle_archive}
EOF
  chmod 0600 "$state_dir/bundle-server.env"
  write_bundle_handler
  cat >/etc/systemd/system/heteronetwork-postgres-bundle.service <<EOF
[Unit]
Description=HeteroNetwork replicated PostgreSQL HA bundle endpoint
After=heteronetwork-agent.service
Requires=heteronetwork-agent.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:${BUNDLE_PORT},bind=${local_ip},reuseaddr,fork EXEC:${state_dir}/serve-bundle.sh,nofork
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
  systemctl daemon-reload
  systemctl enable --now heteronetwork-postgres-bundle.service >/dev/null
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
  local ip _node_id archive extracted candidate_revision
  while IFS=$'\t' read -r ip _node_id; do
    archive="$(mktemp "$state_dir/download.XXXXXX")"
    if ! curl --config "$curl_config_path" \
      "http://${ip}:${BUNDLE_PORT}/v1/postgres-ha/bundle" \
      --output "$archive" 2>/dev/null; then
      rm -f "$archive"
      continue
    fi
    extracted="$state_dir/downloaded.$RANDOM.$RANDOM"
    if ! safe_extract_bundle "$archive" "$extracted" >/dev/null 2>&1 \
      || ! validate_bundle_directory "$extracted"; then
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
  local output="" index=0 ip _node_id name
  while IFS=$'\t' read -r ip _node_id; do
    ((index < MAX_DATABASE_MEMBER_COUNT)) || break
    name="$(member_name_for_index "$index")"
    [[ -z "$output" ]] || output+=","
    output+="${name}=${ip}"
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
        address = line.split("\t", 1)[0]
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

configure_helper_environment() {
  local directory="$1"
  local local_ip="$2"
  load_bundle_manifest "$directory" || die "database bundle manifest is unavailable"
  HETERONETWORK_DB_NODE_NAME="$(member_name_for_ip "$manifest_members" "$local_ip")"
  HETERONETWORK_DB_NODE_ADDRESS="$local_ip"
  export HETERONETWORK_DB_NODE_NAME HETERONETWORK_DB_NODE_ADDRESS
}

apply_local_bundle() {
  local local_ip="$1"
  load_bundle_manifest "$bundle_dir" || return
  local local_name
  if ! local_name="$(member_name_for_ip "$manifest_members" "$local_ip")"; then
    log "node is outside the ${MAX_DATABASE_MEMBER_COUNT}-member database replica limit"
    return
  fi
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
    "HETERONETWORK_DB_INTERFACE=${HETERONETWORK_DB_INTERFACE:-heteronetwork0}" \
    "HETERONETWORK_DB_NODE_NAME=$local_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$local_ip" \
    "HETERONETWORK_DB_MEMBERS=$manifest_members" \
    "HETERONETWORK_DB_DCS_MEMBERS=$manifest_dcs_members" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=$initial_state" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$manifest_members" \
    "HETERONETWORK_DB_BUNDLE_DIR=$bundle_dir" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$manifest_revision" \
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
    "$helper" init-bundle "$temporary"
  printf '%s\n' "$HETERONETWORK_DB_CLUSTER_ID" >"$temporary/cluster-id"
  chmod 0600 "$temporary/cluster-id"
  install_bundle_directory "$temporary"
  publish_bundle_archive
  log "created automatic database topology with $count replicas and $dcs_count DCS voters"
}

coordinator_ip_for_bundle() {
  local ip _node_id
  while IFS=$'\t' read -r ip _node_id; do
    if member_name_for_ip "$manifest_members" "$ip" >/dev/null 2>&1; then
      printf '%s' "$ip"
      return
    fi
  done <"$eligible_path"
  return 1
}

stage_topology() {
  local new_members="$1"
  local new_dcs="$2"
  local new_revision="$3"
  local stage="$state_dir/stage.$RANDOM.$RANDOM"
  cp -a "$bundle_dir" "$stage"
  local local_ip
  local_ip="$(local_vpn_ip)"
  local local_name
  local_name="$(member_name_for_ip "$manifest_members" "$local_ip")"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_NODE_NAME=$local_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$local_ip" \
    "HETERONETWORK_DB_MEMBERS=$new_members" \
    "HETERONETWORK_DB_DCS_MEMBERS=$new_dcs" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$new_members" \
    "HETERONETWORK_DB_BUNDLE_DIR=$stage" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$new_revision" \
    "$helper" extend-bundle "$stage" >/dev/null
  printf '%s\n' "$HETERONETWORK_DB_CLUSTER_ID" >"$stage/cluster-id"
  chmod 0600 "$stage/cluster-id"
  printf '%s' "$stage"
}

reconcile_as_coordinator() {
  local local_ip="$1"
  configure_helper_environment "$bundle_dir" "$local_ip"
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
  stage="$(stage_topology "$new_members" "$new_dcs" "$next_revision")"
  if ((dcs_changed == 1)); then
    configure_helper_environment "$stage" "$local_ip"
    run_helper_for_bundle "$stage" reconcile-dcs
  fi
  install_bundle_directory "$stage"
  publish_bundle_archive
  log "published database topology revision $next_revision"
  apply_local_bundle "$local_ip"
  run_helper_for_bundle "$bundle_dir" reconcile-patroni >/dev/null 2>&1 || true
}

reconcile_once() {
  local local_ip
  local_ip="$(local_vpn_ip)"
  start_bundle_server "$local_ip"
  write_eligible_snapshot
  download_best_bundle

  if [[ ! -d "$bundle_dir" ]]; then
    local count
    count="$(eligible_count)"
    if ((10#$count < MIN_DATABASE_MEMBER_COUNT)); then
      log "waiting for $MIN_DATABASE_MEMBER_COUNT ready Linux nodes ($count ready)"
      return
    fi
    if [[ "$local_ip" != "$(initial_coordinator_ip)" ]]; then
      log "waiting for the initial database coordinator"
      return
    fi
    bootstrap_bundle
  fi

  publish_bundle_archive
  apply_local_bundle "$local_ip"
  load_bundle_manifest "$bundle_dir"
  local coordinator_ip
  coordinator_ip="$(coordinator_ip_for_bundle)" || {
    log "no reachable database coordinator is available"
    return
  }
  if [[ "$local_ip" == "$coordinator_ip" ]]; then
    reconcile_as_coordinator "$local_ip"
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
  for command in curl flock jq openssl ping python3 socat systemctl tar; do
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
    if ! reconcile_once; then
      log "reconciliation failed; retrying"
    fi
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
  HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN="$(printf 'a%.0s' {1..64})"
  HETERONETWORK_DB_CLUSTER_ID="cluster-test"
  HETERONETWORK_DB_LOCAL_ROLE="worker"
  reconcile_interval_seconds=30
  validate_config
  eligible_path="$temporary/eligible.tsv"
  printf '10.250.0.10\tnode-c\n10.250.0.2\tnode-a\n10.250.0.3\tnode-b\n' \
    | LC_ALL=C sort -V >"$eligible_path"
  [[ "$(initial_coordinator_ip)" == "10.250.0.2" ]]
  local generated
  generated="$(initial_members_from_snapshot)"
  [[ "$generated" == "db-a=10.250.0.2,db-b=10.250.0.3,db-c=10.250.0.10" ]]
  generated="$(expand_members_from_snapshot \
    "db-a=10.250.0.2,db-b=10.250.0.3,db-c=10.250.0.10")"
  [[ "$(member_count "$generated")" == "3" ]]
  [[ "$(member_name_for_index 31)" == "db-af" ]]
  bootstrap_bundle >/dev/null 2>&1
  load_bundle_manifest "$bundle_dir"
  [[ "$(member_count "$manifest_members")" == "3" ]]
  [[ "$(member_count "$manifest_dcs_members")" == "3" ]]
  [[ "$manifest_revision" == "1" ]]

  printf '10.250.0.2\tnode-a\n10.250.0.3\tnode-b\n10.250.0.4\tnode-d\n10.250.0.5\tnode-e\n10.250.0.10\tnode-c\n' \
    | LC_ALL=C sort -V >"$eligible_path"
  generated="$(expand_members_from_snapshot "$manifest_members")"
  [[ "$(member_count "$generated")" == "5" ]]
  local dcs_four dcs_five
  dcs_four="$(next_dcs_topology "$generated" "$manifest_dcs_members")"
  dcs_five="$(next_dcs_topology "$generated" "$dcs_four")"
  [[ "$(member_count "$dcs_four")" == "4" ]]
  [[ "$(member_count "$dcs_five")" == "5" ]]

  publish_bundle_archive
  local extracted="$state_dir/extracted"
  safe_extract_bundle "$bundle_archive" "$extracted"
  validate_bundle_directory "$extracted"
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
