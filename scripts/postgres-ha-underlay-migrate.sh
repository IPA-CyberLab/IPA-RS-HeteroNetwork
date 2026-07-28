#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_CLUSTER_NAME="heteronetwork"
readonly DEFAULT_SERVICE_NAME="postgres.heteronetwork.internal"
readonly DEFAULT_STATE_DIR="/etc/heteronetwork/postgres-ha"
readonly DEFAULT_DATA_DIR="/var/lib/heteronetwork-postgres-ha"
readonly DEFAULT_CLIENT_CA_PATH="/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt"
readonly DEFAULT_POSTGRES_PORT="55432"
readonly DEFAULT_REST_PORT="18008"
readonly DEFAULT_DCS_CLIENT_PORT="12379"
readonly DEFAULT_DCS_PEER_PORT="12380"
readonly DEFAULT_DCS_METRICS_PORT="12381"
readonly DEFAULT_PROXY_PORT="25432"
readonly DEFAULT_POSTGRES_MAJOR="17"
readonly DEFAULT_NETWORK_PLANE="underlay-v1"
readonly DEFAULT_LEGACY_INTERFACE="heteronetwork0"
readonly DEFAULT_HELPER="/opt/heteronetwork/libexec/postgres-ha-node.sh"
readonly DEFAULT_ETCDCTL="/opt/heteronetwork/postgres-ha/etcdctl"
readonly DEFAULT_ETCD_SERVICE="heteronetwork-db-dcs.service"
readonly DEFAULT_PATRONI_SERVICE="heteronetwork-db.service"
readonly DEFAULT_SYSTEMD_UNIT_DIR="/etc/systemd/system"
readonly DEFAULT_AUTOPILOT_BUNDLE_DIR="/etc/heteronetwork/postgres-autopilot/bundle"
readonly MIN_DATABASE_MEMBER_COUNT="3"
readonly MAX_DATABASE_MEMBER_COUNT="32"
readonly MIN_DCS_MEMBER_COUNT="3"
readonly MAX_DCS_MEMBER_COUNT="9"

cluster_name="${HETERONETWORK_DB_CLUSTER_NAME:-$DEFAULT_CLUSTER_NAME}"
cluster_id="${HETERONETWORK_DB_CLUSTER_ID:-}"
legacy_members="${HETERONETWORK_DB_LEGACY_MEMBERS:-}"
members="${HETERONETWORK_DB_MEMBERS:-}"
member_identities="${HETERONETWORK_DB_MEMBER_IDENTITIES:-}"
legacy_dcs_members="${HETERONETWORK_DB_LEGACY_DCS_MEMBERS:-}"
dcs_members="${HETERONETWORK_DB_DCS_MEMBERS:-}"
dcs_bootstrap_members="${HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS:-}"
client_cidrs="${HETERONETWORK_DB_CLIENT_CIDRS:-}"
extra_hba_entries="${HETERONETWORK_DB_EXTRA_HBA_ENTRIES:-}"
service_name="${HETERONETWORK_DB_SERVICE_NAME:-$DEFAULT_SERVICE_NAME}"
state_dir="${HETERONETWORK_DB_STATE_DIR:-$DEFAULT_STATE_DIR}"
data_dir="${HETERONETWORK_DB_DATA_DIR:-$DEFAULT_DATA_DIR}"
dcs_data_dir="${HETERONETWORK_DB_DCS_DATA_DIR:-${data_dir}-dcs}"
client_ca_path="${HETERONETWORK_DB_CLIENT_CA_PATH:-$DEFAULT_CLIENT_CA_PATH}"
postgres_port="${HETERONETWORK_DB_POSTGRES_PORT:-$DEFAULT_POSTGRES_PORT}"
rest_port="${HETERONETWORK_DB_REST_PORT:-$DEFAULT_REST_PORT}"
dcs_client_port="${HETERONETWORK_DB_DCS_CLIENT_PORT:-$DEFAULT_DCS_CLIENT_PORT}"
dcs_peer_port="${HETERONETWORK_DB_DCS_PEER_PORT:-$DEFAULT_DCS_PEER_PORT}"
dcs_metrics_port="${HETERONETWORK_DB_DCS_METRICS_PORT:-$DEFAULT_DCS_METRICS_PORT}"
proxy_port="${HETERONETWORK_DB_PROXY_PORT:-$DEFAULT_PROXY_PORT}"
postgres_major="${HETERONETWORK_DB_POSTGRES_MAJOR:-$DEFAULT_POSTGRES_MAJOR}"
topology_revision="${HETERONETWORK_DB_TOPOLOGY_REVISION:-}"
network_plane="${HETERONETWORK_DB_NETWORK_PLANE:-$DEFAULT_NETWORK_PLANE}"

bundle_dir="${HETERONETWORK_DB_BUNDLE_DIR:-}"
node_name="${HETERONETWORK_DB_NODE_NAME:-}"
node_address=""
legacy_node_address=""
interface="${HETERONETWORK_DB_INTERFACE:-}"
legacy_interface="${HETERONETWORK_DB_LEGACY_INTERFACE:-$DEFAULT_LEGACY_INTERFACE}"
helper="${HETERONETWORK_DB_NODE_HELPER:-$DEFAULT_HELPER}"
etcdctl="${HETERONETWORK_DB_ETCDCTL:-$DEFAULT_ETCDCTL}"
etcd_service="${HETERONETWORK_DB_ETCD_SERVICE:-$DEFAULT_ETCD_SERVICE}"
patroni_service="${HETERONETWORK_DB_PATRONI_SERVICE:-$DEFAULT_PATRONI_SERVICE}"
systemd_unit_dir="${HETERONETWORK_DB_SYSTEMD_UNIT_DIR:-$DEFAULT_SYSTEMD_UNIT_DIR}"
autopilot_bundle_dir="$DEFAULT_AUTOPILOT_BUNDLE_DIR"

declare -a cleanup_targets=()
atomic_changed=0
lock_fd=""
rendered_temporary=""

usage() {
  cat <<'EOF'
Usage: postgres-ha-underlay-migrate.sh COMMAND [ARGS]

Commands:
  adopt-bundle OUTPUT_DIR LEGACY_BUNDLE_DIR
      Reuse the legacy CA and five cluster secrets, issue dual-SAN member
      certificates, and create an underlay-v1 migration bundle.
  prepare-node
      Install migration material, make Patroni use both DCS planes, and restart
      the local etcd voter with dual listeners while advertising its legacy URL.
  migrate-dcs-node
      Change only the local etcd member peer URL, restart local etcd with its
      final underlay config, and require every DCS endpoint to remain healthy.
  apply-node
      Reconfigure the existing Patroni member for the final underlay manifest,
      explicitly restart Patroni, and require a healthy local database role.
  cleanup-legacy-forwarders
      After full native-underlay DCS verification, remove only obsolete
      heteronetwork-dcs-ingress-{79,80}.service and
      heteronetwork-dcs-proxy-*-{79,80}.service units from /etc/systemd/system
      or /run/systemd/transient.
  self-test
      Run non-root bundle, SAN, renderer, and stubbed action tests.

Required environment for adopt-bundle:
  HETERONETWORK_DB_CLUSTER_ID
      Control Plane cluster UUID written to the autopilot bundle identity file.
  HETERONETWORK_DB_LEGACY_MEMBERS
      Existing name=VPN-IP members, comma separated.
  HETERONETWORK_DB_MEMBERS
      Final name=underlay-IP members in identical name order.
  HETERONETWORK_DB_MEMBER_IDENTITIES
      Matching name=HeteroNetwork-node-id entries.
  HETERONETWORK_DB_DCS_MEMBERS
      Final odd 3-9 voter map. Defaults to HETERONETWORK_DB_MEMBERS when valid.
  HETERONETWORK_DB_TOPOLOGY_REVISION
      Explicit positive migration revision.

Optional bundle environment:
  HETERONETWORK_DB_LEGACY_DCS_MEMBERS
      Existing voter VPN map. By default it is derived by voter name.
  HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS
      Must equal the final voter map for this in-place migration.
  HETERONETWORK_DB_CLIENT_CIDRS
  HETERONETWORK_DB_EXTRA_HBA_ENTRIES
      Comma-separated database:user:CIDR entries.

Required environment for node commands:
  HETERONETWORK_DB_BUNDLE_DIR
      Must be /etc/heteronetwork/postgres-autopilot/bundle so the verified
      migration bundle becomes the authoritative autopilot bundle.
  HETERONETWORK_DB_NODE_NAME
  HETERONETWORK_DB_INTERFACE
      Interface owning the final underlay address. It cannot be heteronetwork0.

Optional node environment:
  HETERONETWORK_DB_LEGACY_INTERFACE
      Interface owning the legacy VPN address. Default: heteronetwork0.

Run prepare-node on every Patroni member before the first migrate-dcs-node; it
restarts etcd only when the local member is also a voter and a stable quorum
plus one endpoint is healthy. Then run migrate-dcs-node on exactly one voter at
a time; that phase requires every endpoint to be healthy. Run apply-node only
after every voter has a healthy final underlay peer URL. No command creates a
data backup or replaces PostgreSQL/etcd data directories.
EOF
}

log() {
  printf 'heteronetwork-postgres-underlay-migrate: %s\n' "$*"
}

die() {
  printf 'heteronetwork-postgres-underlay-migrate: error: %s\n' "$*" >&2
  exit 1
}

cleanup_registered_targets() {
  local target base
  for target in "${cleanup_targets[@]:-}"; do
    [[ -n "$target" ]] || continue
    base="$(basename -- "$target")"
    case "$base" in
      *.hn-migrate.*|heteronetwork-postgres-ha-underlay-test.*)
        rm -rf -- "$target"
        ;;
    esac
  done
}

trap cleanup_registered_targets EXIT

register_cleanup_target() {
  cleanup_targets+=("$1")
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

require_non_root() {
  [[ "$(id -u)" != "0" ]] || die "self-test must run as a non-root user"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 \
    || die "required command '$1' is not available"
}

validate_name() {
  local value="$1"
  [[ ${#value} -le 63 && "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] \
    || die "invalid lowercase node or cluster name: $value"
}

validate_cluster_id() {
  local value="$1"
  [[ "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || die "HETERONETWORK_DB_CLUSTER_ID must be a lowercase RFC 4122 UUID"
}

validate_node_id() {
  local value="$1"
  [[ ${#value} -le 255 && "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] \
    || die "invalid HeteroNetwork node ID: $value"
}

validate_dns_name() {
  local value="$1"
  [[ ${#value} -le 253 && "$value" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] \
    || die "invalid lowercase DNS name: $value"
  [[ "$value" != *..* ]] || die "DNS name contains an empty label: $value"
}

validate_ipv4() {
  local value="$1"
  local a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" \
    && -n "${c:-}" && -n "${d:-}" ]] \
    || die "invalid IPv4 address: $value"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || die "invalid IPv4 address: $value"
    ((10#$octet <= 255)) || die "invalid IPv4 address: $value"
  done
}

validate_cidr() {
  local value="$1"
  local address prefix extra
  IFS=/ read -r address prefix extra <<<"$value"
  [[ -z "${extra:-}" && "$prefix" =~ ^[0-9]+$ ]] \
    || die "invalid IPv4 CIDR: $value"
  validate_ipv4 "$address"
  ((10#$prefix <= 32)) || die "invalid IPv4 CIDR prefix: $value"
}

validate_port() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] || die "invalid TCP port: $value"
  ((10#$value >= 1024 && 10#$value <= 65535)) \
    || die "port is outside 1024-65535: $value"
}

validate_absolute_path() {
  local value="$1"
  [[ "$value" =~ ^/[A-Za-z0-9._/+:-]+$ ]] \
    || die "path must be an absolute path without whitespace: $value"
  [[ "$value" != "/" && "$value" != *"//"* \
    && "/${value#/}/" != *"/../"* ]] \
    || die "unsafe absolute path: $value"
}

validate_interface_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] \
    || die "invalid interface name: $value"
}

validate_runtime_controls() {
  validate_absolute_path "$helper"
  validate_absolute_path "$etcdctl"
  validate_absolute_path "$systemd_unit_dir"
  [[ "$etcd_service" =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] \
    || die "invalid etcd systemd service name: $etcd_service"
  [[ "$patroni_service" =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] \
    || die "invalid Patroni systemd service name: $patroni_service"
}

mapping_count() {
  local input="$1"
  local -a entries
  IFS=, read -r -a entries <<<"$input"
  printf '%s\n' "${#entries[@]}"
}

mapping_value_for_name() {
  local input="$1"
  local expected_name="$2"
  local entry name value found=0 result=""
  local -a entries
  IFS=, read -r -a entries <<<"$input"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    value="${entry#*=}"
    if [[ "$name" == "$expected_name" ]]; then
      found=$((found + 1))
      result="$value"
    fi
  done
  ((found == 1)) || return 1
  printf '%s' "$result"
}

validate_member_mapping() {
  local input="$1"
  local label="$2"
  local minimum="$3"
  local maximum="$4"
  local require_odd="$5"
  local -a entries
  local entry name address
  local -A seen_names=()
  local -A seen_addresses=()

  [[ -n "$input" ]] || die "$label member map is required"
  IFS=, read -r -a entries <<<"$input"
  ((${#entries[@]} >= minimum && ${#entries[@]} <= maximum)) \
    || die "$label member count must be between $minimum and $maximum"
  if [[ "$require_odd" == "true" ]]; then
    ((${#entries[@]} % 2 == 1)) || die "$label member count must be odd"
  fi

  for entry in "${entries[@]}"; do
    [[ "$entry" == "${entry//[[:space:]]/}" && "$entry" == *=* ]] \
      || die "$label entry must use name=IPv4 without whitespace: $entry"
    name="${entry%%=*}"
    address="${entry#*=}"
    validate_name "$name"
    validate_ipv4 "$address"
    [[ -z "${seen_names[$name]:-}" ]] || die "duplicate $label name: $name"
    [[ -z "${seen_addresses[$address]:-}" ]] \
      || die "duplicate $label address: $address"
    seen_names["$name"]=1
    seen_addresses["$address"]=1
  done
}

validate_member_identities() {
  local -a entries
  local entry name node_id
  local -A seen_names=()
  local -A seen_ids=()

  [[ -n "$member_identities" ]] || die "member identity map is required"
  IFS=, read -r -a entries <<<"$member_identities"
  ((${#entries[@]} >= MIN_DATABASE_MEMBER_COUNT \
    && ${#entries[@]} <= MAX_DATABASE_MEMBER_COUNT)) \
    || die "member identity count is outside the supported range"

  for entry in "${entries[@]}"; do
    [[ "$entry" == "${entry//[[:space:]]/}" && "$entry" == *=* ]] \
      || die "member identity must use name=node-id without whitespace: $entry"
    name="${entry%%=*}"
    node_id="${entry#*=}"
    validate_name "$name"
    validate_node_id "$node_id"
    [[ -z "${seen_names[$name]:-}" ]] || die "duplicate identity name: $name"
    [[ -z "${seen_ids[$node_id]:-}" ]] \
      || die "duplicate HeteroNetwork node identity: $node_id"
    seen_names["$name"]=1
    seen_ids["$node_id"]=1
  done
}

derive_legacy_dcs_members() {
  local entry name address output=""
  local -a entries
  IFS=, read -r -a entries <<<"$dcs_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    address="$(mapping_value_for_name "$legacy_members" "$name")" \
      || die "DCS member $name is absent from the legacy member map"
    [[ -z "$output" ]] || output+=","
    output+="${name}=${address}"
  done
  printf '%s' "$output"
}

normalize_topology() {
  if [[ -z "$dcs_members" ]]; then
    dcs_members="$members"
  fi
  if [[ -z "$legacy_dcs_members" ]]; then
    legacy_dcs_members="$(derive_legacy_dcs_members)"
  fi
  if [[ -z "$dcs_bootstrap_members" ]]; then
    dcs_bootstrap_members="$dcs_members"
  fi
}

validate_client_cidrs() {
  [[ -n "$client_cidrs" ]] || return 0
  local -a entries
  local entry
  local -A seen=()
  IFS=, read -r -a entries <<<"$client_cidrs"
  ((${#entries[@]} <= 64)) || die "too many client CIDRs"
  for entry in "${entries[@]}"; do
    [[ "$entry" == "${entry//[[:space:]]/}" ]] \
      || die "client CIDRs must not contain whitespace"
    validate_cidr "$entry"
    [[ -z "${seen[$entry]:-}" ]] || die "duplicate client CIDR: $entry"
    seen["$entry"]=1
  done
}

validate_sql_identifier() {
  local value="$1"
  [[ ${#value} -le 63 && "$value" =~ ^[a-z_][a-z0-9_]*$ ]] \
    || die "invalid SQL identifier: $value"
}

validate_extra_hba_entries() {
  [[ -n "$extra_hba_entries" ]] || return 0
  local -a entries
  local entry database user cidr extra
  local -A seen=()
  IFS=, read -r -a entries <<<"$extra_hba_entries"
  ((${#entries[@]} <= 64)) || die "too many extra HBA entries"
  for entry in "${entries[@]}"; do
    [[ "$entry" == "${entry//[[:space:]]/}" ]] \
      || die "extra HBA entries must not contain whitespace"
    IFS=: read -r database user cidr extra <<<"$entry"
    [[ -z "${extra:-}" && -n "$database" && -n "$user" && -n "$cidr" ]] \
      || die "extra HBA entry must use database:user:CIDR: $entry"
    validate_sql_identifier "$database"
    validate_sql_identifier "$user"
    validate_cidr "$cidr"
    [[ -z "${seen[$entry]:-}" ]] || die "duplicate extra HBA entry: $entry"
    seen["$entry"]=1
  done
}

validate_topology() {
  normalize_topology
  validate_name "$cluster_name"
  validate_cluster_id "$cluster_id"
  validate_dns_name "$service_name"
  validate_member_mapping "$legacy_members" legacy-database \
    "$MIN_DATABASE_MEMBER_COUNT" "$MAX_DATABASE_MEMBER_COUNT" false
  validate_member_mapping "$members" final-database \
    "$MIN_DATABASE_MEMBER_COUNT" "$MAX_DATABASE_MEMBER_COUNT" false
  validate_member_mapping "$legacy_dcs_members" legacy-DCS \
    "$MIN_DCS_MEMBER_COUNT" "$MAX_DCS_MEMBER_COUNT" true
  validate_member_mapping "$dcs_members" final-DCS \
    "$MIN_DCS_MEMBER_COUNT" "$MAX_DCS_MEMBER_COUNT" true
  validate_member_mapping "$dcs_bootstrap_members" final-DCS-bootstrap \
    "$MIN_DCS_MEMBER_COUNT" "$MAX_DCS_MEMBER_COUNT" true
  validate_member_identities
  validate_client_cidrs
  validate_extra_hba_entries

  [[ "$network_plane" == "$DEFAULT_NETWORK_PLANE" ]] \
    || die "migration network plane must be $DEFAULT_NETWORK_PLANE"
  [[ "$topology_revision" =~ ^[1-9][0-9]*$ ]] \
    || die "HETERONETWORK_DB_TOPOLOGY_REVISION must be an explicit positive integer"
  [[ "$dcs_bootstrap_members" == "$dcs_members" ]] \
    || die "an in-place voter migration requires DCS bootstrap members to equal final DCS members"

  validate_absolute_path "$state_dir"
  validate_absolute_path "$data_dir"
  validate_absolute_path "$dcs_data_dir"
  validate_absolute_path "$client_ca_path"
  [[ "$data_dir" != "$dcs_data_dir" ]] \
    || die "PostgreSQL and etcd data directories must differ"
  validate_port "$postgres_port"
  validate_port "$rest_port"
  validate_port "$dcs_client_port"
  validate_port "$dcs_peer_port"
  validate_port "$dcs_metrics_port"
  validate_port "$proxy_port"
  [[ "$postgres_major" =~ ^[0-9]{2}$ ]] \
    || die "PostgreSQL major must be a two-digit version"
  [[ "$state_dir" == "$DEFAULT_STATE_DIR" \
    && "$data_dir" == "$DEFAULT_DATA_DIR" \
    && "$dcs_data_dir" == "${DEFAULT_DATA_DIR}-dcs" \
    && "$client_ca_path" == "$DEFAULT_CLIENT_CA_PATH" \
    && "$postgres_port" == "$DEFAULT_POSTGRES_PORT" \
    && "$rest_port" == "$DEFAULT_REST_PORT" \
    && "$dcs_client_port" == "$DEFAULT_DCS_CLIENT_PORT" \
    && "$dcs_peer_port" == "$DEFAULT_DCS_PEER_PORT" \
    && "$dcs_metrics_port" == "$DEFAULT_DCS_METRICS_PORT" \
    && "$proxy_port" == "$DEFAULT_PROXY_PORT" \
    && "$postgres_major" == "$DEFAULT_POSTGRES_MAJOR" ]] \
    || die "controlled autopilot migration requires the standard paths, ports, and PostgreSQL major"

  local -a legacy_entries final_entries identity_entries final_dcs_entries
  local entry name old_address new_address expected="" node_id
  local -A legacy_addresses=()
  local -A database_names=()
  local -A identity_names=()

  IFS=, read -r -a legacy_entries <<<"$legacy_members"
  IFS=, read -r -a final_entries <<<"$members"
  ((${#legacy_entries[@]} == ${#final_entries[@]})) \
    || die "legacy and final database member counts differ"
  for entry in "${legacy_entries[@]}"; do
    name="${entry%%=*}"
    old_address="${entry#*=}"
    new_address="$(mapping_value_for_name "$members" "$name")" \
      || die "legacy member $name has no final member"
    [[ "$old_address" != "$new_address" ]] \
      || die "legacy and final addresses are identical for $name"
    legacy_addresses["$old_address"]=1
    database_names["$name"]=1
    [[ -z "$expected" ]] || expected+=","
    expected+="${name}=${new_address}"
  done
  [[ "$expected" == "$members" ]] \
    || die "legacy and final database maps must use identical member ordering"
  for entry in "${final_entries[@]}"; do
    new_address="${entry#*=}"
    [[ -z "${legacy_addresses[$new_address]:-}" ]] \
      || die "final underlay address overlaps the legacy VPN address set: $new_address"
  done

  IFS=, read -r -a identity_entries <<<"$member_identities"
  ((${#identity_entries[@]} == ${#legacy_entries[@]})) \
    || die "database member and identity counts differ"
  expected=""
  for entry in "${legacy_entries[@]}"; do
    name="${entry%%=*}"
    node_id="$(mapping_value_for_name "$member_identities" "$name")" \
      || die "database member $name has no HeteroNetwork identity"
    identity_names["$name"]=1
    [[ -z "$expected" ]] || expected+=","
    expected+="${name}=${node_id}"
  done
  [[ "$expected" == "$member_identities" ]] \
    || die "member identities must use database member ordering"

  expected="$(derive_legacy_dcs_members)"
  [[ "$expected" == "$legacy_dcs_members" ]] \
    || die "legacy and final DCS maps do not describe the same ordered voter set"
  IFS=, read -r -a final_dcs_entries <<<"$dcs_members"
  for entry in "${final_dcs_entries[@]}"; do
    name="${entry%%=*}"
    new_address="${entry#*=}"
    [[ -n "${database_names[$name]:-}" ]] \
      || die "DCS voter $name is not a database member"
    [[ "$(mapping_value_for_name "$members" "$name")" == "$new_address" ]] \
      || die "DCS voter $name has a non-database underlay address"
  done
}

manifest_keys() {
  cat <<'EOF'
HETERONETWORK_DB_CLUSTER_NAME
HETERONETWORK_DB_LEGACY_MEMBERS
HETERONETWORK_DB_MEMBERS
HETERONETWORK_DB_MEMBER_IDENTITIES
HETERONETWORK_DB_LEGACY_DCS_MEMBERS
HETERONETWORK_DB_DCS_MEMBERS
HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS
HETERONETWORK_DB_CLIENT_CIDRS
HETERONETWORK_DB_EXTRA_HBA_ENTRIES
HETERONETWORK_DB_SERVICE_NAME
HETERONETWORK_DB_STATE_DIR
HETERONETWORK_DB_DATA_DIR
HETERONETWORK_DB_DCS_DATA_DIR
HETERONETWORK_DB_CLIENT_CA_PATH
HETERONETWORK_DB_POSTGRES_PORT
HETERONETWORK_DB_REST_PORT
HETERONETWORK_DB_DCS_CLIENT_PORT
HETERONETWORK_DB_DCS_PEER_PORT
HETERONETWORK_DB_DCS_METRICS_PORT
HETERONETWORK_DB_PROXY_PORT
HETERONETWORK_DB_POSTGRES_MAJOR
HETERONETWORK_DB_TOPOLOGY_REVISION
HETERONETWORK_DB_NETWORK_PLANE
EOF
}

write_manifest() {
  local output="$1"
  cat >"$output/manifest.env" <<EOF
HETERONETWORK_DB_CLUSTER_NAME=${cluster_name}
HETERONETWORK_DB_LEGACY_MEMBERS=${legacy_members}
HETERONETWORK_DB_MEMBERS=${members}
HETERONETWORK_DB_MEMBER_IDENTITIES=${member_identities}
HETERONETWORK_DB_LEGACY_DCS_MEMBERS=${legacy_dcs_members}
HETERONETWORK_DB_DCS_MEMBERS=${dcs_members}
HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=${dcs_bootstrap_members}
HETERONETWORK_DB_CLIENT_CIDRS=${client_cidrs}
HETERONETWORK_DB_EXTRA_HBA_ENTRIES=${extra_hba_entries}
HETERONETWORK_DB_SERVICE_NAME=${service_name}
HETERONETWORK_DB_STATE_DIR=${state_dir}
HETERONETWORK_DB_DATA_DIR=${data_dir}
HETERONETWORK_DB_DCS_DATA_DIR=${dcs_data_dir}
HETERONETWORK_DB_CLIENT_CA_PATH=${client_ca_path}
HETERONETWORK_DB_POSTGRES_PORT=${postgres_port}
HETERONETWORK_DB_REST_PORT=${rest_port}
HETERONETWORK_DB_DCS_CLIENT_PORT=${dcs_client_port}
HETERONETWORK_DB_DCS_PEER_PORT=${dcs_peer_port}
HETERONETWORK_DB_DCS_METRICS_PORT=${dcs_metrics_port}
HETERONETWORK_DB_PROXY_PORT=${proxy_port}
HETERONETWORK_DB_POSTGRES_MAJOR=${postgres_major}
HETERONETWORK_DB_TOPOLOGY_REVISION=${topology_revision}
HETERONETWORK_DB_NETWORK_PLANE=${network_plane}
EOF
  chmod 0600 "$output/manifest.env"
}

write_cluster_id() {
  local output="$1"
  printf '%s\n' "$cluster_id" >"$output/cluster-id"
  chmod 0600 "$output/cluster-id"
}

read_cluster_id() {
  local directory="$1"
  local path="$directory/cluster-id"
  ensure_private_file "$path"
  [[ "$(stat -c '%s' "$path")" == "37" ]] \
    || die "migration bundle cluster-id has an invalid size"
  local value
  IFS= read -r value <"$path" \
    || die "migration bundle cluster-id is unreadable"
  validate_cluster_id "$value"
  printf '%s' "$value"
}

manifest_value() {
  local directory="$1"
  local key="$2"
  local allow_empty="${3:-false}"
  awk -v key="$key" -v allow_empty="$allow_empty" '
    index($0, key "=") == 1 {
      count += 1
      value = substr($0, length(key) + 2)
    }
    END {
      if (count != 1 || (allow_empty != "true" && value == "")) {
        exit 1
      }
      print value
    }
  ' "$directory/manifest.env"
}

validate_manifest_shape() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "migration bundle manifest is missing or unsafe"
  [[ "$(stat -c '%h' "$path")" == "1" ]] \
    || die "migration bundle manifest must not have hard links"
  (("$(stat -c '%s' "$path")" <= 65536)) \
    || die "migration bundle manifest is too large"

  local -A expected=()
  local key line line_key count=0
  while IFS= read -r key; do
    expected["$key"]=1
  done < <(manifest_keys)
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[A-Z0-9_]+=([^[:cntrl:]]*)$ ]] \
      || die "migration manifest contains an invalid line"
    line_key="${line%%=*}"
    [[ -n "${expected[$line_key]:-}" ]] \
      || die "migration manifest contains an unexpected key: $line_key"
    expected["$line_key"]=2
    count=$((count + 1))
  done <"$path"
  [[ "$count" == "$(manifest_keys | wc -l)" ]] \
    || die "migration manifest has missing or duplicate keys"
  for key in "${!expected[@]}"; do
    [[ "${expected[$key]}" == "2" ]] \
      || die "migration manifest is missing key: $key"
  done
}

load_manifest() {
  local directory="$1"
  validate_absolute_path "$directory"
  [[ -d "$directory" && ! -L "$directory" ]] \
    || die "migration bundle directory is missing or unsafe: $directory"
  validate_manifest_shape "$directory/manifest.env"

  cluster_id="$(read_cluster_id "$directory")"
  cluster_name="$(manifest_value "$directory" HETERONETWORK_DB_CLUSTER_NAME)"
  legacy_members="$(manifest_value "$directory" HETERONETWORK_DB_LEGACY_MEMBERS)"
  members="$(manifest_value "$directory" HETERONETWORK_DB_MEMBERS)"
  member_identities="$(
    manifest_value "$directory" HETERONETWORK_DB_MEMBER_IDENTITIES
  )"
  legacy_dcs_members="$(
    manifest_value "$directory" HETERONETWORK_DB_LEGACY_DCS_MEMBERS
  )"
  dcs_members="$(manifest_value "$directory" HETERONETWORK_DB_DCS_MEMBERS)"
  dcs_bootstrap_members="$(
    manifest_value "$directory" HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS
  )"
  client_cidrs="$(
    manifest_value "$directory" HETERONETWORK_DB_CLIENT_CIDRS true
  )"
  extra_hba_entries="$(
    manifest_value "$directory" HETERONETWORK_DB_EXTRA_HBA_ENTRIES true
  )"
  service_name="$(manifest_value "$directory" HETERONETWORK_DB_SERVICE_NAME)"
  state_dir="$(manifest_value "$directory" HETERONETWORK_DB_STATE_DIR)"
  data_dir="$(manifest_value "$directory" HETERONETWORK_DB_DATA_DIR)"
  dcs_data_dir="$(manifest_value "$directory" HETERONETWORK_DB_DCS_DATA_DIR)"
  client_ca_path="$(manifest_value "$directory" HETERONETWORK_DB_CLIENT_CA_PATH)"
  postgres_port="$(manifest_value "$directory" HETERONETWORK_DB_POSTGRES_PORT)"
  rest_port="$(manifest_value "$directory" HETERONETWORK_DB_REST_PORT)"
  dcs_client_port="$(
    manifest_value "$directory" HETERONETWORK_DB_DCS_CLIENT_PORT
  )"
  dcs_peer_port="$(manifest_value "$directory" HETERONETWORK_DB_DCS_PEER_PORT)"
  dcs_metrics_port="$(
    manifest_value "$directory" HETERONETWORK_DB_DCS_METRICS_PORT
  )"
  proxy_port="$(manifest_value "$directory" HETERONETWORK_DB_PROXY_PORT)"
  postgres_major="$(manifest_value "$directory" HETERONETWORK_DB_POSTGRES_MAJOR)"
  topology_revision="$(
    manifest_value "$directory" HETERONETWORK_DB_TOPOLOGY_REVISION
  )"
  network_plane="$(manifest_value "$directory" HETERONETWORK_DB_NETWORK_PLANE)"
  validate_topology
}

ensure_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "required regular file is missing or unsafe: $path"
  [[ "$(stat -c '%h' "$path")" == "1" ]] \
    || die "file must not have hard links: $path"
}

ensure_private_file() {
  local path="$1"
  ensure_regular_file "$path"
  local mode
  mode="$(stat -c '%a' "$path")"
  (((8#$mode & 0077) == 0)) \
    || die "private file has group or world permissions: $path"
}

ensure_node_private_key() {
  local path="$1"
  ensure_regular_file "$path"
  local mode
  mode="$(stat -c '%a' "$path")"
  (((8#$mode & 0037) == 0)) \
    || die "node private key has unsafe permissions: $path"
}

validate_secret_file() {
  local path="$1"
  ensure_private_file "$path"
  (("$(stat -c '%s' "$path")" <= 256)) || die "secret file is too large: $path"
  python3 - "$path" <<'PY'
import pathlib
import re
import sys

value = pathlib.Path(sys.argv[1]).read_bytes()
if not re.fullmatch(rb"[A-Za-z0-9]{32,128}\n?", value):
    raise SystemExit("invalid secret format")
PY
}

public_key_digest_for_certificate() {
  openssl x509 -in "$1" -pubkey -noout \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print $1}'
}

public_key_digest_for_private_key() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print $1}'
}

validate_ca() {
  local directory="$1"
  ensure_safe_directory "$directory"
  ensure_safe_directory "$directory/ca"
  ensure_private_file "$directory/ca/ca.key"
  ensure_regular_file "$directory/ca/ca.crt"
  openssl x509 -in "$directory/ca/ca.crt" -noout -checkend 86400 >/dev/null \
    || die "legacy CA certificate is invalid or expires within 24 hours"
  openssl verify -CAfile "$directory/ca/ca.crt" \
    "$directory/ca/ca.crt" >/dev/null \
    || die "legacy CA certificate is not self-verifiable"
  local certificate_text
  certificate_text="$(openssl x509 -in "$directory/ca/ca.crt" -noout -text)" \
    || die "failed to inspect the legacy CA certificate"
  grep -Fq 'CA:TRUE' <<<"$certificate_text" \
    || die "legacy CA certificate is not a certificate authority"
  local certificate_digest key_digest
  certificate_digest="$(public_key_digest_for_certificate "$directory/ca/ca.crt")"
  key_digest="$(public_key_digest_for_private_key "$directory/ca/ca.key")"
  [[ -n "$certificate_digest" && "$certificate_digest" == "$key_digest" ]] \
    || die "legacy CA private key does not match its certificate"
}

validate_certificate_files() {
  local ca_path="$1"
  local certificate_path="$2"
  local key_path="$3"
  local name="$4"
  local old_address="$5"
  local new_address="$6"
  ensure_regular_file "$ca_path"
  ensure_regular_file "$certificate_path"
  ensure_node_private_key "$key_path"
  openssl verify -CAfile "$ca_path" "$certificate_path" >/dev/null \
    || die "member certificate is not signed by the migration CA: $name"
  openssl x509 -in "$certificate_path" -noout -checkend 86400 >/dev/null \
    || die "member certificate is invalid or expires within 24 hours: $name"
  local subject_alt_names
  subject_alt_names="$(
    openssl x509 -in "$certificate_path" -noout -ext subjectAltName
  )" || die "member certificate has no subjectAltName extension: $name"
  grep -Fq "DNS:${service_name}" <<<"$subject_alt_names" \
    || die "member certificate lacks explicit service DNS SAN: $name"
  grep -Fq "DNS:${name}.${service_name}" <<<"$subject_alt_names" \
    || die "member certificate lacks explicit member DNS SAN: $name"
  grep -Fq "IP Address:${old_address}" <<<"$subject_alt_names" \
    || die "member certificate lacks explicit legacy IP SAN: $name"
  grep -Fq "IP Address:${new_address}" <<<"$subject_alt_names" \
    || die "member certificate lacks explicit underlay IP SAN: $name"
  openssl x509 -in "$certificate_path" -noout \
    -checkhost "$service_name" >/dev/null \
    || die "member certificate lacks service DNS SAN: $name"
  openssl x509 -in "$certificate_path" -noout \
    -checkhost "${name}.${service_name}" >/dev/null \
    || die "member certificate lacks member DNS SAN: $name"
  openssl x509 -in "$certificate_path" -noout \
    -checkip "$old_address" >/dev/null \
    || die "member certificate lacks legacy IP SAN: $name"
  openssl x509 -in "$certificate_path" -noout \
    -checkip "$new_address" >/dev/null \
    || die "member certificate lacks underlay IP SAN: $name"
  local certificate_digest key_digest
  certificate_digest="$(public_key_digest_for_certificate "$certificate_path")"
  key_digest="$(public_key_digest_for_private_key "$key_path")"
  [[ -n "$certificate_digest" && "$certificate_digest" == "$key_digest" ]] \
    || die "member certificate and private key do not match: $name"
}

validate_member_certificate() {
  local directory="$1"
  local name="$2"
  local old_address="$3"
  local new_address="$4"
  local node_dir="$directory/nodes/$name"
  ensure_safe_directory "$directory/nodes"
  ensure_safe_directory "$node_dir"
  ensure_regular_file "$node_dir/ca.crt"
  cmp -s "$directory/ca/ca.crt" "$node_dir/ca.crt" \
    || die "member CA copy differs from the bundle CA: $name"
  validate_certificate_files \
    "$directory/ca/ca.crt" "$node_dir/node.crt" "$node_dir/node.key" \
    "$name" "$old_address" "$new_address"
}

issue_member_certificate() {
  local output="$1"
  local name="$2"
  local old_address="$3"
  local new_address="$4"
  local node_dir="$output/nodes/$name"
  local csr="$node_dir/.node.csr.hn-migrate.$$"
  local extensions="$node_dir/.extensions.cnf.hn-migrate.$$"
  local serial
  install -d -m 0700 "$node_dir"
  register_cleanup_target "$csr"
  register_cleanup_target "$extensions"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$node_dir/node.key"
  openssl req -new -key "$node_dir/node.key" -out "$csr" \
    -subj "/CN=${name}.${service_name}"
  cat >"$extensions" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${service_name},DNS:${name}.${service_name},IP:${old_address},IP:${new_address},IP:127.0.0.1
EOF
  serial="$(openssl rand -hex 16)"
  openssl x509 -req -in "$csr" \
    -CA "$output/ca/ca.crt" -CAkey "$output/ca/ca.key" \
    -set_serial "0x${serial}" \
    -out "$node_dir/node.crt" -days 825 -sha256 \
    -extfile "$extensions" >/dev/null 2>&1 \
    || die "failed to issue dual-SAN certificate for $name"
  install -m 0644 "$output/ca/ca.crt" "$node_dir/ca.crt"
  rm -f -- "$csr" "$extensions"
  chmod 0600 "$node_dir/node.key"
  chmod 0644 "$node_dir/node.crt" "$node_dir/ca.crt"
  validate_member_certificate "$output" "$name" "$old_address" "$new_address"
}

legacy_manifest_optional_value() {
  local directory="$1"
  local key="$2"
  local path="$directory/manifest.env"
  [[ -f "$path" && ! -L "$path" ]] || return 1
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
  ' "$path"
}

validate_legacy_bundle() {
  local directory="$1"
  [[ -d "$directory" && ! -L "$directory" ]] \
    || die "legacy bundle directory is missing or unsafe: $directory"
  ensure_safe_directory "$directory/ca"
  ensure_safe_directory "$directory/secrets"
  validate_ca "$directory"
  local secret
  for secret in superuser replication rewind application rest-api; do
    validate_secret_file "$directory/secrets/${secret}.password"
  done

  local persisted
  if [[ -e "$directory/cluster-id" ]]; then
    persisted="$(read_cluster_id "$directory")"
    [[ "$persisted" == "$cluster_id" ]] \
      || die "legacy bundle cluster-id differs from HETERONETWORK_DB_CLUSTER_ID"
  fi
  if [[ -e "$directory/manifest.env" ]]; then
    ensure_regular_file "$directory/manifest.env"
    persisted="$(
      legacy_manifest_optional_value "$directory" HETERONETWORK_DB_MEMBERS
    )" || die "legacy bundle manifest has no unique member map"
    (
      validate_member_mapping "$persisted" legacy-bundle-database \
        "$MIN_DATABASE_MEMBER_COUNT" "$MAX_DATABASE_MEMBER_COUNT" false
    ) || die "legacy bundle manifest has an invalid member map"
    local entry name address persisted_address
    local -a entries
    IFS=, read -r -a entries <<<"$legacy_members"
    for entry in "${entries[@]}"; do
      name="${entry%%=*}"
      address="${entry#*=}"
      persisted_address="$(mapping_value_for_name "$persisted" "$name")" \
        || die "current legacy member is absent from the legacy bundle: $name"
      [[ "$persisted_address" == "$address" ]] \
        || die "legacy bundle rebinds $name from $address to $persisted_address"
    done
    if persisted="$(
      legacy_manifest_optional_value \
        "$directory" HETERONETWORK_DB_MEMBER_IDENTITIES
    )"; then
      for entry in "${entries[@]}"; do
        name="${entry%%=*}"
        address="$(mapping_value_for_name "$member_identities" "$name")"
        persisted_address="$(mapping_value_for_name "$persisted" "$name")" \
          || die "current legacy member has no persisted identity: $name"
        [[ "$persisted_address" == "$address" ]] \
          || die "legacy bundle rebinds the HeteroNetwork identity for $name"
      done
    fi
    persisted="$(
      legacy_manifest_optional_value "$directory" HETERONETWORK_DB_CLUSTER_NAME
    )" || die "legacy bundle manifest has no unique cluster name"
    [[ "$persisted" == "$cluster_name" ]] \
      || die "legacy bundle cluster name does not match the migration cluster"
    persisted="$(
      legacy_manifest_optional_value \
        "$directory" HETERONETWORK_DB_TOPOLOGY_REVISION
    )" || die "legacy bundle manifest has no unique topology revision"
    [[ "$persisted" =~ ^[1-9][0-9]*$ ]] \
      || die "legacy bundle topology revision is invalid"
    ((10#$topology_revision > 10#$persisted)) \
      || die "migration topology revision must exceed the legacy revision"
  fi
}

validate_bundle() {
  local directory="$1"
  load_manifest "$directory"
  ensure_safe_directory "$directory/ca"
  ensure_safe_directory "$directory/nodes"
  ensure_safe_directory "$directory/secrets"
  validate_ca "$directory"
  local secret
  for secret in superuser replication rewind application rest-api; do
    validate_secret_file "$directory/secrets/${secret}.password"
  done
  local entry name old_address new_address
  local -a entries
  IFS=, read -r -a entries <<<"$legacy_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    old_address="${entry#*=}"
    new_address="$(mapping_value_for_name "$members" "$name")"
    validate_member_certificate \
      "$directory" "$name" "$old_address" "$new_address"
  done
}

run_standard_helper() {
  local directory="$1"
  shift
  [[ -x "$helper" ]] \
    || die "standard PostgreSQL HA helper is not executable: $helper"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$cluster_name" \
    "HETERONETWORK_DB_INTERFACE=$interface" \
    "HETERONETWORK_DB_NODE_NAME=$node_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$node_address" \
    "HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS=$legacy_node_address" \
    "HETERONETWORK_DB_MEMBERS=$members" \
    "HETERONETWORK_DB_MEMBER_IDENTITIES=$member_identities" \
    "HETERONETWORK_DB_DCS_MEMBERS=$dcs_members" \
    "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=$dcs_bootstrap_members" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$members" \
    "HETERONETWORK_DB_CLIENT_CIDRS=$client_cidrs" \
    "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=$extra_hba_entries" \
    "HETERONETWORK_DB_STATE_DIR=$state_dir" \
    "HETERONETWORK_DB_DATA_DIR=$data_dir" \
    "HETERONETWORK_DB_DCS_DATA_DIR=$dcs_data_dir" \
    "HETERONETWORK_DB_CLIENT_CA_PATH=$client_ca_path" \
    "HETERONETWORK_DB_BUNDLE_DIR=$directory" \
    "HETERONETWORK_DB_SERVICE_NAME=$service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$rest_port" \
    "HETERONETWORK_DB_DCS_CLIENT_PORT=$dcs_client_port" \
    "HETERONETWORK_DB_DCS_PEER_PORT=$dcs_peer_port" \
    "HETERONETWORK_DB_DCS_METRICS_PORT=$dcs_metrics_port" \
    "HETERONETWORK_DB_PROXY_PORT=$proxy_port" \
    "HETERONETWORK_DB_POSTGRES_MAJOR=$postgres_major" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$topology_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$network_plane" \
    "$helper" "$@"
}

validate_standard_bundle() {
  local directory="$1"
  run_standard_helper "$directory" validate-bundle "$directory" >/dev/null \
    || die "migration bundle is incompatible with the standard PostgreSQL HA helper"
}

adopt_bundle() {
  local output="${1:-}"
  local legacy="${2:-}"
  [[ -n "$output" && -n "$legacy" ]] \
    || die "adopt-bundle requires OUTPUT_DIR and LEGACY_BUNDLE_DIR"
  validate_absolute_path "$output"
  validate_absolute_path "$legacy"
  [[ "$output" != "$legacy" ]] || die "output and legacy bundle paths must differ"
  validate_topology
  require_command install
  require_command openssl
  require_command python3
  require_command sha256sum
  validate_legacy_bundle "$legacy"
  [[ ! -e "$output" ]] || die "refusing to replace existing output path: $output"

  local parent base temporary
  parent="$(dirname -- "$output")"
  base="$(basename -- "$output")"
  [[ -d "$parent" && ! -L "$parent" ]] \
    || die "output parent directory is missing or unsafe: $parent"
  temporary="$(mktemp -d "${parent}/.${base}.hn-migrate.XXXXXX")"
  register_cleanup_target "$temporary"
  install -d -m 0700 \
    "$temporary/ca" "$temporary/nodes" "$temporary/secrets"
  install -m 0600 "$legacy/ca/ca.key" "$temporary/ca/ca.key"
  install -m 0644 "$legacy/ca/ca.crt" "$temporary/ca/ca.crt"

  local secret
  for secret in superuser replication rewind application rest-api; do
    install -m 0600 \
      "$legacy/secrets/${secret}.password" \
      "$temporary/secrets/${secret}.password"
    cmp -s \
      "$legacy/secrets/${secret}.password" \
      "$temporary/secrets/${secret}.password" \
      || die "failed to reuse legacy secret file: ${secret}.password"
  done
  cmp -s "$legacy/ca/ca.key" "$temporary/ca/ca.key" \
    || die "failed to reuse the legacy CA private key"
  cmp -s "$legacy/ca/ca.crt" "$temporary/ca/ca.crt" \
    || die "failed to reuse the legacy CA certificate"

  local entry name old_address new_address
  local -a entries
  IFS=, read -r -a entries <<<"$legacy_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    old_address="${entry#*=}"
    new_address="$(mapping_value_for_name "$members" "$name")"
    issue_member_certificate \
      "$temporary" "$name" "$old_address" "$new_address"
  done
  write_manifest "$temporary"
  write_cluster_id "$temporary"
  validate_bundle "$temporary"
  validate_standard_bundle "$temporary"
  mv -T -- "$temporary" "$output"
  log "created controlled underlay migration bundle at $output"
}

load_node_context() {
  local require_dcs="${1:-false}"
  [[ -n "$bundle_dir" ]] || die "HETERONETWORK_DB_BUNDLE_DIR is required"
  validate_absolute_path "$bundle_dir"
  [[ "$bundle_dir" == "$autopilot_bundle_dir" ]] \
    || die "migration bundle must be installed at $autopilot_bundle_dir"
  validate_runtime_controls
  validate_bundle "$bundle_dir"
  [[ -n "$node_name" ]] || die "HETERONETWORK_DB_NODE_NAME is required"
  validate_name "$node_name"
  node_address="$(mapping_value_for_name "$members" "$node_name")" \
    || die "local node is absent from the final database map: $node_name"
  legacy_node_address="$(
    mapping_value_for_name "$legacy_members" "$node_name"
  )" || die "local node is absent from the legacy database map: $node_name"

  if [[ -n "${HETERONETWORK_DB_NODE_ADDRESS:-}" ]]; then
    [[ "$HETERONETWORK_DB_NODE_ADDRESS" == "$node_address" ]] \
      || die "HETERONETWORK_DB_NODE_ADDRESS differs from the migration manifest"
  fi
  if [[ -n "${HETERONETWORK_DB_LEGACY_NODE_ADDRESS:-}" ]]; then
    [[ "$HETERONETWORK_DB_LEGACY_NODE_ADDRESS" == "$legacy_node_address" ]] \
      || die "HETERONETWORK_DB_LEGACY_NODE_ADDRESS differs from the migration manifest"
  fi
  [[ -n "$interface" ]] || die "HETERONETWORK_DB_INTERFACE is required"
  validate_interface_name "$interface"
  validate_interface_name "$legacy_interface"
  [[ "$interface" != "$DEFAULT_LEGACY_INTERFACE" ]] \
    || die "underlay interface must not be $DEFAULT_LEGACY_INTERFACE"
  [[ "$interface" != "$legacy_interface" ]] \
    || die "legacy and underlay interfaces must differ"

  if [[ "$require_dcs" == "true" ]]; then
    mapping_value_for_name "$dcs_members" "$node_name" >/dev/null \
      || die "local node is not a DCS voter: $node_name"
  fi
  validate_standard_bundle "$bundle_dir"
}

node_is_dcs_member() {
  mapping_value_for_name "$dcs_members" "$node_name" >/dev/null 2>&1
}

ip_action() {
  ip "$@"
}

systemctl_action() {
  systemctl "$@"
}

etcdctl_action() {
  ETCDCTL_API=3 "$etcdctl" "$@"
}

curl_action() {
  curl "$@"
}

list_unit_files_action() {
  systemctl_action list-unit-files --type=service --no-legend --no-pager
}

list_units_action() {
  systemctl_action \
    list-units --type=service --all --no-legend --no-pager --plain
}

verify_address_on_interface() {
  local address="$1"
  local expected_interface="$2"
  ip_action link show dev "$expected_interface" >/dev/null 2>&1 \
    || die "interface does not exist: $expected_interface"
  ip_action -o -4 address show dev "$expected_interface" scope global \
    | awk '{print $4}' \
    | cut -d/ -f1 \
    | grep -Fxq "$address" \
    || die "$address is not assigned to $expected_interface"
}

route_output_matches() {
  local output="$1"
  local expected_interface="$2"
  local expected_source="$3"
  awk \
    -v expected_interface="$expected_interface" \
    -v expected_source="$expected_source" '
    {
      for (i = 1; i <= NF; i += 1) {
        if ($i == "dev" && i < NF) {
          dev_count += 1
          dev = $(i + 1)
        } else if ($i == "src" && i < NF) {
          src_count += 1
          src = $(i + 1)
        }
      }
    }
    END {
      if (dev_count != 1 || src_count != 1 || dev != expected_interface || src != expected_source) {
        exit 1
      }
    }
  ' <<<"$output"
}

verify_routes_for_map() {
  local input="$1"
  local local_address="$2"
  local expected_interface="$3"
  local label="$4"
  local entry name address route
  local -a entries
  IFS=, read -r -a entries <<<"$input"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    address="${entry#*=}"
    [[ "$address" == "$local_address" ]] && continue
    route="$(ip_action -4 route get "$address" from "$local_address" 2>/dev/null)" \
      || die "no $label route from $local_address to $name=$address"
    route_output_matches "$route" "$expected_interface" "$local_address" \
      || die "$label route to $name=$address has the wrong interface or source"
  done
}

validate_local_network() {
  require_command ip
  verify_address_on_interface "$legacy_node_address" "$legacy_interface"
  verify_address_on_interface "$node_address" "$interface"
  verify_routes_for_map \
    "$legacy_members" "$legacy_node_address" "$legacy_interface" legacy-VPN
  verify_routes_for_map "$members" "$node_address" "$interface" underlay
}

ensure_safe_directory() {
  local path="$1"
  [[ -d "$path" && ! -L "$path" ]] \
    || die "required directory is missing or unsafe: $path"
}

validate_installed_identity_material() {
  ensure_regular_file "$state_dir/pki/ca.crt"
  ensure_regular_file "$state_dir/pki/node.crt"
  ensure_node_private_key "$state_dir/pki/node.key"
  ensure_regular_file "$client_ca_path"
  cmp -s "$bundle_dir/ca/ca.crt" "$state_dir/pki/ca.crt" \
    || die "installed database CA differs from the adopted legacy CA"
  cmp -s "$bundle_dir/ca/ca.crt" "$client_ca_path" \
    || die "installed client CA differs from the adopted legacy CA"

  local secret
  for secret in superuser replication rewind application rest-api; do
    ensure_regular_file "$state_dir/secrets/${secret}.password"
    cmp -s \
      "$bundle_dir/secrets/${secret}.password" \
      "$state_dir/secrets/${secret}.password" \
      || die "installed database secret differs from the adopted legacy value: $secret"
  done

  openssl verify -CAfile "$state_dir/pki/ca.crt" \
    "$state_dir/pki/node.crt" >/dev/null \
    || die "installed member certificate is not signed by the adopted legacy CA"
  openssl x509 -in "$state_dir/pki/node.crt" -noout \
    -checkip "$legacy_node_address" >/dev/null \
    || die "installed member certificate lacks the local legacy IP SAN"
  local certificate_digest key_digest
  certificate_digest="$(
    public_key_digest_for_certificate "$state_dir/pki/node.crt"
  )"
  key_digest="$(
    public_key_digest_for_private_key "$state_dir/pki/node.key"
  )"
  [[ -n "$certificate_digest" && "$certificate_digest" == "$key_digest" ]] \
    || die "installed member certificate and private key do not match"
}

require_existing_installation() {
  local require_dcs="${1:-false}"
  ensure_safe_directory "$state_dir"
  ensure_safe_directory "$state_dir/pki"
  ensure_safe_directory "$state_dir/secrets"
  ensure_safe_directory "$data_dir"
  ensure_safe_directory "$data_dir/postgres"
  ensure_regular_file "$data_dir/postgres/PG_VERSION"
  ensure_regular_file "$state_dir/patroni.yml"
  [[ -f "${systemd_unit_dir}/${patroni_service}" ]] \
    || die "existing Patroni unit is absent; refusing helper install fallback"
  [[ -x "$helper" ]] || die "PostgreSQL HA node helper is not executable: $helper"
  if [[ "$require_dcs" == "true" ]]; then
    ensure_safe_directory "$dcs_data_dir"
    ensure_regular_file "$state_dir/etcd.yml"
    [[ -f "${systemd_unit_dir}/${etcd_service}" ]] \
      || die "existing etcd unit is absent"
    [[ -x "$etcdctl" ]] || die "etcdctl is not executable: $etcdctl"
  fi
  validate_installed_identity_material
}

acquire_local_lock() {
  require_command flock
  exec {lock_fd}>/run/lock/heteronetwork-postgres-underlay-migrate.lock
  flock -n "$lock_fd" || die "another local PostgreSQL underlay migration is running"
}

atomic_install_file() {
  local source="$1"
  local destination="$2"
  local owner="$3"
  local group="$4"
  local mode="$5"
  local parent base temporary current_mode current_owner current_group
  ensure_regular_file "$source"
  parent="$(dirname -- "$destination")"
  base="$(basename -- "$destination")"
  ensure_safe_directory "$parent"
  if [[ -e "$destination" || -L "$destination" ]]; then
    ensure_regular_file "$destination"
    current_mode="$(stat -c '%a' "$destination")"
    current_owner="$(stat -c '%U' "$destination")"
    current_group="$(stat -c '%G' "$destination")"
    if cmp -s "$source" "$destination" \
      && [[ "$current_mode" == "$mode" \
        && "$current_owner" == "$owner" \
        && "$current_group" == "$group" ]]; then
      atomic_changed=0
      return 0
    fi
  fi
  temporary="$(mktemp "${parent}/.${base}.hn-migrate.XXXXXX")"
  register_cleanup_target "$temporary"
  install -o "$owner" -g "$group" -m "$mode" "$source" "$temporary"
  mv -fT -- "$temporary" "$destination"
  atomic_changed=1
}

atomic_replace_preserving_metadata() {
  local source="$1"
  local destination="$2"
  ensure_regular_file "$destination"
  local owner group mode
  owner="$(stat -c '%U' "$destination")"
  group="$(stat -c '%G' "$destination")"
  mode="$(stat -c '%a' "$destination")"
  atomic_install_file "$source" "$destination" "$owner" "$group" "$mode"
}

install_migration_material() {
  getent group heteronetwork-db-ha >/dev/null \
    || die "heteronetwork-db-ha group is missing"
  id -u postgres >/dev/null 2>&1 || die "postgres user is missing"
  local node_bundle="$bundle_dir/nodes/$node_name"
  local changed=0
  atomic_install_file \
    "$node_bundle/ca.crt" "$state_dir/pki/ca.crt" \
    root heteronetwork-db-ha 0644
  changed=$((changed | atomic_changed))
  atomic_install_file \
    "$node_bundle/node.crt" "$state_dir/pki/node.crt" \
    root heteronetwork-db-ha 0644
  changed=$((changed | atomic_changed))
  atomic_install_file \
    "$node_bundle/node.key" "$state_dir/pki/node.key" \
    root heteronetwork-db-ha 0640
  changed=$((changed | atomic_changed))
  atomic_install_file \
    "$node_bundle/ca.crt" "$client_ca_path" root root 0644
  changed=$((changed | atomic_changed))

  local secret
  for secret in superuser replication rewind application rest-api; do
    atomic_install_file \
      "$bundle_dir/secrets/${secret}.password" \
      "$state_dir/secrets/${secret}.password" \
      root postgres 0640
    changed=$((changed | atomic_changed))
  done
  validate_certificate_files \
    "$state_dir/pki/ca.crt" "$state_dir/pki/node.crt" \
    "$state_dir/pki/node.key" \
    "$node_name" "$legacy_node_address" "$node_address"
  atomic_changed="$changed"
}

initial_cluster_for_map() {
  local input="$1"
  local output="" entry name address
  local -a entries
  IFS=, read -r -a entries <<<"$input"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    address="${entry#*=}"
    [[ -z "$output" ]] || output+=","
    output+="${name}=https://${address}:${dcs_peer_port}"
  done
  printf '%s' "$output"
}

render_transition_etcd_config() {
  local initial_cluster
  initial_cluster="$(initial_cluster_for_map "$legacy_dcs_members")"
  cat <<EOF
# managed by postgres-ha-underlay-migrate.sh phase=transition revision=${topology_revision}
name: ${node_name}
data-dir: ${dcs_data_dir}
listen-peer-urls: https://${legacy_node_address}:${dcs_peer_port},https://${node_address}:${dcs_peer_port}
initial-advertise-peer-urls: https://${legacy_node_address}:${dcs_peer_port}
listen-client-urls: https://127.0.0.1:${dcs_client_port},https://${legacy_node_address}:${dcs_client_port},https://${node_address}:${dcs_client_port}
advertise-client-urls: https://${legacy_node_address}:${dcs_client_port}
listen-metrics-urls: http://127.0.0.1:${dcs_metrics_port}
initial-cluster: ${initial_cluster}
initial-cluster-token: ${cluster_name}-postgres-dcs-v1
initial-cluster-state: existing
auto-compaction-mode: periodic
auto-compaction-retention: 1h
quota-backend-bytes: 2147483648
snapshot-count: 10000
max-snapshots: 5
max-wals: 5
logger: zap
log-level: info
client-transport-security:
  cert-file: ${state_dir}/pki/node.crt
  key-file: ${state_dir}/pki/node.key
  client-cert-auth: true
  trusted-ca-file: ${state_dir}/pki/ca.crt
peer-transport-security:
  cert-file: ${state_dir}/pki/node.crt
  key-file: ${state_dir}/pki/node.key
  client-cert-auth: true
  trusted-ca-file: ${state_dir}/pki/ca.crt
EOF
}

render_final_etcd_config() {
  local initial_cluster
  initial_cluster="$(initial_cluster_for_map "$dcs_members")"
  cat <<EOF
# managed by postgres-ha-underlay-migrate.sh phase=final revision=${topology_revision}
name: ${node_name}
data-dir: ${dcs_data_dir}
listen-peer-urls: https://${node_address}:${dcs_peer_port}
initial-advertise-peer-urls: https://${node_address}:${dcs_peer_port}
listen-client-urls: https://127.0.0.1:${dcs_client_port},https://${node_address}:${dcs_client_port}
advertise-client-urls: https://${node_address}:${dcs_client_port}
listen-metrics-urls: http://127.0.0.1:${dcs_metrics_port}
initial-cluster: ${initial_cluster}
initial-cluster-token: ${cluster_name}-postgres-dcs-v1
initial-cluster-state: existing
auto-compaction-mode: periodic
auto-compaction-retention: 1h
quota-backend-bytes: 2147483648
snapshot-count: 10000
max-snapshots: 5
max-wals: 5
logger: zap
log-level: info
client-transport-security:
  cert-file: ${state_dir}/pki/node.crt
  key-file: ${state_dir}/pki/node.key
  client-cert-auth: true
  trusted-ca-file: ${state_dir}/pki/ca.crt
peer-transport-security:
  cert-file: ${state_dir}/pki/node.crt
  key-file: ${state_dir}/pki/node.key
  client-cert-auth: true
  trusted-ca-file: ${state_dir}/pki/ca.crt
EOF
}

render_to_temporary() {
  local renderer="$1"
  local destination="$2"
  local parent base temporary
  parent="$(dirname -- "$destination")"
  base="$(basename -- "$destination")"
  ensure_safe_directory "$parent"
  temporary="$(mktemp "${parent}/.${base}.hn-migrate.XXXXXX")"
  register_cleanup_target "$temporary"
  "$renderer" >"$temporary"
  chmod 0600 "$temporary"
  rendered_temporary="$temporary"
}

client_endpoints_for_map() {
  local input="$1"
  local output="" entry address
  local -a entries
  IFS=, read -r -a entries <<<"$input"
  for entry in "${entries[@]}"; do
    address="${entry#*=}"
    [[ -z "$output" ]] || output+=","
    output+="${address}:${dcs_client_port}"
  done
  printf '%s' "$output"
}

render_patroni_dual_hosts() {
  local input="$1"
  local output="$2"
  ensure_regular_file "$input"
  local old_endpoints new_endpoints
  old_endpoints="$(client_endpoints_for_map "$legacy_dcs_members")"
  new_endpoints="$(client_endpoints_for_map "$dcs_members")"
  python3 - "$input" "$output" "$old_endpoints" "$new_endpoints" <<'PY'
import os
import pathlib
import re
import sys

source_path, output_path = map(pathlib.Path, sys.argv[1:3])
old = tuple(sys.argv[3].split(","))
new = tuple(sys.argv[4].split(","))
dual = tuple(dict.fromkeys(old + new))
if not old or not new or len(old) != len(new):
    raise SystemExit("invalid expected Patroni DCS endpoint maps")

raw = source_path.read_bytes()
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit("Patroni config is not UTF-8") from error
if "\t" in text or "\r" in text:
    raise SystemExit("Patroni config has unsupported whitespace")
lines = text.splitlines(keepends=True)
if sum(line == "etcd3:\n" for line in lines) != 1:
    raise SystemExit("expected exactly one top-level etcd3 block")
etcd_index = lines.index("etcd3:\n")
if etcd_index + 2 >= len(lines) or lines[etcd_index + 1] != "  hosts:\n":
    raise SystemExit("etcd3.hosts does not match the expected renderer shape")

start = etcd_index + 2
end = start
current = []
host_pattern = re.compile(r"^    - ([0-9]+(?:\.[0-9]+){3}:[0-9]+)\n$")
while end < len(lines):
    match = host_pattern.fullmatch(lines[end])
    if match is None:
        break
    current.append(match.group(1))
    end += 1
if not current or end >= len(lines) or lines[end] != "  protocol: https\n":
    raise SystemExit("etcd3.hosts termination does not match the expected renderer shape")
if tuple(current) not in (old, new, dual):
    raise SystemExit("existing Patroni DCS hosts are not a managed legacy/final/dual list")

replacement = [f"    - {endpoint}\n" for endpoint in dual]
rendered = "".join(lines[:start] + replacement + lines[end:]).encode("utf-8")
with output_path.open("wb") as output_file:
    output_file.write(rendered)
    output_file.flush()
    os.fsync(output_file.fileno())
PY
}

install_patroni_dual_hosts() {
  local config="$state_dir/patroni.yml"
  ensure_regular_file "$config"
  local temporary validation
  temporary="$(mktemp "$(dirname -- "$config")/.patroni.yml.hn-migrate.XXXXXX")"
  register_cleanup_target "$temporary"
  render_patroni_dual_hosts "$config" "$temporary"
  atomic_replace_preserving_metadata "$temporary" "$config"

  validation="$(mktemp "$(dirname -- "$config")/.patroni.yml.hn-migrate.XXXXXX")"
  register_cleanup_target "$validation"
  render_patroni_dual_hosts "$config" "$validation"
  cmp -s "$config" "$validation" \
    || die "installed Patroni dual-host config failed strict validation"
}

validate_patroni_dual_hosts() {
  local config="$state_dir/patroni.yml"
  local validation
  ensure_regular_file "$config"
  validation="$(mktemp "$(dirname -- "$config")/.patroni.yml.hn-migrate.XXXXXX")"
  register_cleanup_target "$validation"
  render_patroni_dual_hosts "$config" "$validation"
  cmp -s "$config" "$validation" \
    || die "Patroni etcd3.hosts is not the required legacy+underlay list"
}

hup_patroni() {
  systemctl_action is-active --quiet "$patroni_service" \
    || die "Patroni is not active before HUP"
  systemctl_action kill \
    --kill-whom=main --signal=HUP "$patroni_service"
  systemctl_action is-active --quiet "$patroni_service" \
    || die "Patroni became inactive after HUP"
}

all_control_endpoints() {
  local old_endpoints new_endpoints combined="" endpoint
  local -A seen=()
  old_endpoints="$(client_endpoints_for_map "$legacy_dcs_members")"
  new_endpoints="$(client_endpoints_for_map "$dcs_members")"
  local -a entries
  IFS=, read -r -a entries <<<"${old_endpoints},${new_endpoints}"
  for endpoint in "${entries[@]}"; do
    [[ -z "${seen[$endpoint]:-}" ]] || continue
    seen["$endpoint"]=1
    [[ -z "$combined" ]] || combined+=","
    combined+="https://${endpoint}"
  done
  printf '%s' "$combined"
}

bundle_etcdctl_at() {
  local endpoints="$1"
  shift
  etcdctl_action \
    --endpoints="$endpoints" \
    --dial-timeout=2s \
    --command-timeout=8s \
    --cacert="$bundle_dir/ca/ca.crt" \
    --cert="$bundle_dir/nodes/$node_name/node.crt" \
    --key="$bundle_dir/nodes/$node_name/node.key" \
    "$@"
}

installed_etcdctl_at() {
  local endpoints="$1"
  shift
  etcdctl_action \
    --endpoints="$endpoints" \
    --dial-timeout=2s \
    --command-timeout=8s \
    --cacert="$state_dir/pki/ca.crt" \
    --cert="$state_dir/pki/node.crt" \
    --key="$state_dir/pki/node.key" \
    "$@"
}

find_control_endpoint() {
  local combined endpoint
  combined="$(all_control_endpoints)"
  local -a endpoints
  IFS=, read -r -a endpoints <<<"$combined"
  for endpoint in "${endpoints[@]}"; do
    if bundle_etcdctl_at "$endpoint" endpoint health >/dev/null 2>&1; then
      printf '%s' "$endpoint"
      return 0
    fi
  done
  return 1
}

read_dcs_snapshot() {
  local endpoint document
  endpoint="$(find_control_endpoint)" \
    || die "no managed legacy or underlay DCS endpoint is reachable"
  document="$(
    bundle_etcdctl_at "$endpoint" member list --write-out=json
  )" || die "failed to read DCS membership"
  python3 -c '
import json
import sys

document = json.load(sys.stdin)
members = document.get("members")
if not isinstance(members, list):
    raise SystemExit("invalid member list")
for member in members:
    member_id = member.get("ID")
    name = member.get("name")
    urls = member.get("peerURLs")
    learner = member.get("isLearner", False)
    if (
        not isinstance(member_id, int)
        or member_id <= 0
        or not isinstance(name, str)
        or not isinstance(urls, list)
        or len(urls) != 1
        or not isinstance(urls[0], str)
        or not isinstance(learner, bool)
    ):
        raise SystemExit("invalid member record")
    print(f"{member_id:x}\t{name}\t{urls[0]}\t{str(learner).lower()}")
' <<<"$document"
}

validate_dcs_snapshot() {
  local snapshot="$1"
  [[ -n "$snapshot" ]] || die "DCS membership is empty"
  local expected_count actual_count=0
  expected_count="$(mapping_count "$dcs_members")"
  local id actual_name peer_url learner old_address new_address expected_old expected_new
  local -A seen_names=()
  while IFS=$'\t' read -r id actual_name peer_url learner; do
    [[ "$id" =~ ^[0-9a-f]+$ && -n "$actual_name" ]] \
      || die "DCS membership contains an invalid member"
    [[ "$learner" == "false" ]] \
      || die "controlled migration supports voters only, not learners"
    old_address="$(mapping_value_for_name "$legacy_dcs_members" "$actual_name")" \
      || die "DCS contains unmanaged member: $actual_name"
    new_address="$(mapping_value_for_name "$dcs_members" "$actual_name")" \
      || die "DCS contains unmanaged member: $actual_name"
    expected_old="https://${old_address}:${dcs_peer_port}"
    expected_new="https://${new_address}:${dcs_peer_port}"
    [[ "$peer_url" == "$expected_old" || "$peer_url" == "$expected_new" ]] \
      || die "DCS member has an unmanaged peer URL: $actual_name"
    [[ -z "${seen_names[$actual_name]:-}" ]] \
      || die "DCS contains duplicate member name: $actual_name"
    seen_names["$actual_name"]=1
    actual_count=$((actual_count + 1))
  done <<<"$snapshot"
  ((actual_count == 10#$expected_count)) \
    || die "DCS voter count differs from the migration manifest"

  local entry name
  local -a entries
  IFS=, read -r -a entries <<<"$dcs_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    [[ -n "${seen_names[$name]:-}" ]] \
      || die "expected DCS voter is missing: $name"
  done
}

snapshot_member_phase() {
  local snapshot="$1"
  local expected_name="$2"
  local old_address new_address expected_old expected_new
  old_address="$(mapping_value_for_name "$legacy_dcs_members" "$expected_name")"
  new_address="$(mapping_value_for_name "$dcs_members" "$expected_name")"
  expected_old="https://${old_address}:${dcs_peer_port}"
  expected_new="https://${new_address}:${dcs_peer_port}"
  local id actual_name peer_url learner found=0 phase=""
  while IFS=$'\t' read -r id actual_name peer_url learner; do
    [[ "$actual_name" == "$expected_name" ]] || continue
    found=$((found + 1))
    if [[ "$peer_url" == "$expected_old" ]]; then
      phase="legacy"
    elif [[ "$peer_url" == "$expected_new" ]]; then
      phase="final"
    else
      return 1
    fi
  done <<<"$snapshot"
  ((found == 1)) || return 1
  printf '%s' "$phase"
}

snapshot_member_id() {
  local snapshot="$1"
  local expected_name="$2"
  local id actual_name peer_url learner found=0 result=""
  while IFS=$'\t' read -r id actual_name peer_url learner; do
    if [[ "$actual_name" == "$expected_name" ]]; then
      found=$((found + 1))
      result="$id"
    fi
  done <<<"$snapshot"
  ((found == 1)) || return 1
  printf '%s' "$result"
}

snapshot_is_all_final() {
  local snapshot="$1"
  local entry name
  local -a entries
  IFS=, read -r -a entries <<<"$dcs_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    [[ "$(snapshot_member_phase "$snapshot" "$name")" == "final" ]] \
      || return 1
  done
}

healthy_endpoint_count() {
  local snapshot="$1"
  local require_local="$2"
  local healthy=0 local_healthy=0 entry name phase address endpoint fallback
  local -a entries
  IFS=, read -r -a entries <<<"$dcs_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    phase="$(snapshot_member_phase "$snapshot" "$name")"
    address="$(mapping_value_for_name "$dcs_members" "$name")"
    endpoint="https://${address}:${dcs_client_port}"
    fallback=""
    if [[ "$phase" == "legacy" ]]; then
      address="$(mapping_value_for_name "$legacy_dcs_members" "$name")"
      fallback="https://${address}:${dcs_client_port}"
    fi
    if installed_etcdctl_at "$endpoint" endpoint health >/dev/null 2>&1 \
      || {
        [[ -n "$fallback" ]] \
          && installed_etcdctl_at "$fallback" endpoint health >/dev/null 2>&1
      }; then
      healthy=$((healthy + 1))
      [[ "$name" != "$node_name" ]] || local_healthy=1
    fi
  done
  if [[ "$require_local" == "true" && "$local_healthy" != "1" ]]; then
    return 1
  fi
  printf '%s' "$healthy"
}

verify_dcs_restart_budget() {
  local attempt snapshot healthy total minimum consecutive=0
  total="$(mapping_count "$dcs_members")"
  minimum="$((10#$total / 2 + 2))"
  for attempt in {1..60}; do
    if snapshot="$(read_dcs_snapshot 2>/dev/null)" \
      && validate_dcs_snapshot "$snapshot" >/dev/null 2>&1 \
      && healthy="$(healthy_endpoint_count "$snapshot" true 2>/dev/null)" \
      && ((10#$healthy >= minimum)); then
      consecutive=$((consecutive + 1))
      if ((consecutive >= 3)); then
        printf '%s' "$snapshot"
        return 0
      fi
    else
      consecutive=0
    fi
    sleep 1
  done
  return 1
}

verify_all_dcs_endpoints() {
  local attempt snapshot healthy total consecutive=0
  total="$(mapping_count "$dcs_members")"
  for attempt in {1..60}; do
    if snapshot="$(read_dcs_snapshot 2>/dev/null)" \
      && validate_dcs_snapshot "$snapshot" >/dev/null 2>&1 \
      && healthy="$(healthy_endpoint_count "$snapshot" true 2>/dev/null)" \
      && ((10#$healthy == 10#$total)); then
      consecutive=$((consecutive + 1))
      if ((consecutive >= 3)); then
        printf '%s' "$snapshot"
        return 0
      fi
    else
      consecutive=0
    fi
    sleep 1
  done
  return 1
}

install_rendered_etcd_config() {
  local renderer="$1"
  local temporary
  render_to_temporary "$renderer" "$state_dir/etcd.yml"
  temporary="$rendered_temporary"
  atomic_install_file \
    "$temporary" "$state_dir/etcd.yml" root heteronetwork-db-ha 0640
}

assert_etcd_config_matches() {
  local renderer="$1"
  local temporary
  render_to_temporary "$renderer" "$state_dir/etcd.yml"
  temporary="$rendered_temporary"
  cmp -s "$temporary" "$state_dir/etcd.yml" \
    || die "local etcd config does not match the required migration phase"
}

prepare_node() {
  require_root
  acquire_local_lock
  require_command install
  require_command curl
  require_command openssl
  require_command python3
  require_command ss
  require_command systemctl
  load_node_context false
  validate_local_network
  local local_is_dcs=false
  if node_is_dcs_member; then
    local_is_dcs=true
    require_existing_installation true
  else
    require_existing_installation false
  fi

  local snapshot phase=""
  snapshot="$(verify_dcs_restart_budget)" \
    || die "DCS lacks a stable local quorum plus one restart-safe endpoint"
  validate_dcs_snapshot "$snapshot"
  if [[ "$local_is_dcs" == "true" ]]; then
    phase="$(snapshot_member_phase "$snapshot" "$node_name")" \
      || die "could not determine the local DCS member phase"
  fi

  install_migration_material
  install_patroni_dual_hosts
  hup_patroni
  verify_patroni_role_at "$legacy_node_address"

  if [[ "$local_is_dcs" == "true" ]]; then
    if [[ "$phase" == "final" ]]; then
      install_rendered_etcd_config render_final_etcd_config
    else
      install_rendered_etcd_config render_transition_etcd_config
    fi
    stop_local_ingress_forwarders
    systemctl_action restart "$etcd_service"
    verify_local_etcd_listener_ownership
    installed_etcdctl_at \
      "https://${node_address}:${dcs_client_port}" \
      endpoint health >/dev/null \
      || die "native local underlay etcd listener is not healthy after prepare-node"
    verify_dcs_restart_budget >/dev/null \
      || die "DCS lost its stable restart-safe endpoint budget after prepare-node"
    log "prepared $node_name with dual Patroni DCS hosts and $phase-aware etcd listeners"
  else
    log "prepared non-voter $node_name with dual Patroni DCS hosts"
  fi
}

restore_fresh_transition_config() {
  local temporary
  render_to_temporary render_transition_etcd_config "$state_dir/etcd.yml"
  temporary="$rendered_temporary"
  atomic_install_file \
    "$temporary" "$state_dir/etcd.yml" root heteronetwork-db-ha 0640
}

migrate_dcs_node() {
  require_root
  acquire_local_lock
  require_command install
  require_command openssl
  require_command python3
  require_command ss
  require_command systemctl
  load_node_context true
  validate_local_network
  require_existing_installation true
  install_migration_material
  validate_patroni_dual_hosts

  local snapshot phase member_id before_snapshot
  before_snapshot="$(verify_all_dcs_endpoints)" \
    || die "all DCS endpoints must be healthy before changing a peer URL"
  snapshot="$before_snapshot"
  validate_dcs_snapshot "$snapshot"
  phase="$(snapshot_member_phase "$snapshot" "$node_name")" \
    || die "could not determine the local DCS member phase"
  member_id="$(snapshot_member_id "$snapshot" "$node_name")" \
    || die "could not determine the local DCS member ID"

  if [[ "$phase" == "final" ]]; then
    install_rendered_etcd_config render_final_etcd_config
    if ! systemctl_action is-active --quiet "$etcd_service" \
      || [[ "$atomic_changed" == "1" ]]; then
      systemctl_action restart "$etcd_service"
    fi
    snapshot="$(verify_all_dcs_endpoints)" \
      || die "not all DCS endpoints are healthy after idempotent finalization"
    [[ "$(snapshot_member_phase "$snapshot" "$node_name")" == "final" ]] \
      || die "local DCS member regressed from its final peer URL"
    log "DCS member $node_name already uses its final underlay peer URL"
    return
  fi

  assert_etcd_config_matches render_transition_etcd_config
  local final_config
  render_to_temporary render_final_etcd_config "$state_dir/etcd.yml"
  final_config="$rendered_temporary"
  local control_endpoint final_peer_url
  control_endpoint="$(find_control_endpoint)" \
    || {
      restore_fresh_transition_config
      die "no DCS endpoint is reachable before the member update"
    }
  final_peer_url="https://${node_address}:${dcs_peer_port}"
  if ! bundle_etcdctl_at "$control_endpoint" \
      member update "$member_id" --peer-urls="$final_peer_url" >/dev/null; then
    restore_fresh_transition_config
    die "local DCS member update failed; restored a freshly rendered transition config"
  fi

  atomic_install_file \
    "$final_config" "$state_dir/etcd.yml" root heteronetwork-db-ha 0640
  systemctl_action restart "$etcd_service"
  verify_local_etcd_listener_ownership
  snapshot="$(verify_all_dcs_endpoints)" \
    || die "not all DCS endpoints are healthy after the local member update"
  [[ "$(snapshot_member_phase "$snapshot" "$node_name")" == "final" ]] \
    || die "local DCS member did not retain its final underlay peer URL"
  log "migrated DCS member $node_name to its native underlay peer URL"
}

verify_patroni_role_at() {
  local address="$1"
  local attempt document
  for attempt in {1..45}; do
    if document="$(
      curl_action --fail --silent --show-error \
        --connect-timeout 2 --max-time 5 \
        --cacert "$state_dir/pki/ca.crt" \
        --connect-to \
          "${service_name}:${rest_port}:${address}:${rest_port}" \
        "https://${service_name}:${rest_port}/patroni" 2>/dev/null
    )" && python3 -c '
import json
import sys

document = json.load(sys.stdin)
if document.get("state") != "running":
    raise SystemExit(1)
if document.get("role") not in {
    "primary", "master", "replica", "standby_leader"
}:
    raise SystemExit(1)
' <<<"$document"; then
      return 0
    fi
    sleep 1
  done
  die "local Patroni role did not become healthy after restart"
}

verify_local_etcd_listener_ownership() {
  local main_pid sockets
  main_pid="$(
    systemctl_action show --property=MainPID --value "$etcd_service"
  )" || die "failed to inspect the local etcd main PID"
  [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] \
    || die "local etcd service has no valid main PID"
  sockets="$(ss -H -ltnp)" \
    || die "failed to inspect local etcd listening sockets"
  python3 - \
    "$node_address" "$dcs_client_port" "$dcs_peer_port" "$main_pid" \
    "$sockets" <<'PY' \
    || die "native underlay DCS listeners are not owned by the local etcd service"
import re
import sys

address, client_port, peer_port, expected_pid, sockets = sys.argv[1:]
for listener in (f"{address}:{client_port}", f"{address}:{peer_port}"):
    matches = []
    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[3] == listener:
            matches.append(line)
    if len(matches) != 1:
        raise SystemExit(1)
    pids = re.findall(r"pid=([0-9]+)", matches[0])
    if pids != [expected_pid]:
        raise SystemExit(1)
PY
}

apply_node() {
  require_root
  acquire_local_lock
  require_command curl
  require_command openssl
  require_command python3
  require_command systemctl
  load_node_context false
  validate_local_network
  require_existing_installation false

  local snapshot
  snapshot="$(verify_all_dcs_endpoints)" \
    || die "all DCS endpoints must be healthy before applying the final Patroni map"
  snapshot_is_all_final "$snapshot" \
    || die "all DCS voters must use final underlay peer URLs before apply-node"

  local postgres_data_identity dcs_data_identity=""
  postgres_data_identity="$(stat -c '%d:%i' "$data_dir/postgres")"
  if mapping_value_for_name "$dcs_members" "$node_name" >/dev/null 2>&1; then
    ensure_safe_directory "$dcs_data_dir"
    dcs_data_identity="$(stat -c '%d:%i' "$dcs_data_dir")"
  fi

  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$cluster_name" \
    "HETERONETWORK_DB_INTERFACE=$interface" \
    "HETERONETWORK_DB_NODE_NAME=$node_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$node_address" \
    "HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS=$legacy_node_address" \
    "HETERONETWORK_DB_MEMBERS=$members" \
    "HETERONETWORK_DB_MEMBER_IDENTITIES=$member_identities" \
    "HETERONETWORK_DB_DCS_MEMBERS=$dcs_members" \
    "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=$dcs_bootstrap_members" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$members" \
    "HETERONETWORK_DB_CLIENT_CIDRS=$client_cidrs" \
    "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=$extra_hba_entries" \
    "HETERONETWORK_DB_STATE_DIR=$state_dir" \
    "HETERONETWORK_DB_DATA_DIR=$data_dir" \
    "HETERONETWORK_DB_DCS_DATA_DIR=$dcs_data_dir" \
    "HETERONETWORK_DB_CLIENT_CA_PATH=$client_ca_path" \
    "HETERONETWORK_DB_BUNDLE_DIR=$bundle_dir" \
    "HETERONETWORK_DB_SERVICE_NAME=$service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$rest_port" \
    "HETERONETWORK_DB_DCS_CLIENT_PORT=$dcs_client_port" \
    "HETERONETWORK_DB_DCS_PEER_PORT=$dcs_peer_port" \
    "HETERONETWORK_DB_DCS_METRICS_PORT=$dcs_metrics_port" \
    "HETERONETWORK_DB_PROXY_PORT=$proxy_port" \
    "HETERONETWORK_DB_POSTGRES_MAJOR=$postgres_major" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$topology_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$network_plane" \
    "$helper" reconfigure-node

  [[ "$(stat -c '%d:%i' "$data_dir/postgres")" == "$postgres_data_identity" ]] \
    || die "PostgreSQL data directory identity changed during reconfiguration"
  if [[ -n "$dcs_data_identity" ]]; then
    [[ "$(stat -c '%d:%i' "$dcs_data_dir")" == "$dcs_data_identity" ]] \
      || die "etcd data directory identity changed during reconfiguration"
  fi
  systemctl_action restart "$patroni_service"
  systemctl_action is-active --quiet "$patroni_service" \
    || die "Patroni is inactive after explicit restart"
  verify_patroni_role_at "$node_address"
  run_standard_helper "$bundle_dir" verify \
    || die "full PostgreSQL HA verification failed after local underlay apply"
  log "applied underlay topology revision $topology_revision to $node_name"
}

validate_native_final_etcd_config() {
  local path="$state_dir/etcd.yml"
  ensure_regular_file "$path"
  python3 - \
    "$path" "$node_name" "$dcs_data_dir" "$node_address" \
    "$dcs_client_port" "$dcs_peer_port" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
name, data_dir, address, client_port, peer_port = sys.argv[2:]
expected = {
    "name": name,
    "data-dir": data_dir,
    "listen-peer-urls": f"https://{address}:{peer_port}",
    "initial-advertise-peer-urls": f"https://{address}:{peer_port}",
    "listen-client-urls": (
        f"https://127.0.0.1:{client_port},https://{address}:{client_port}"
    ),
    "advertise-client-urls": f"https://{address}:{client_port}",
    "initial-cluster-state": "existing",
}
values = {}
for raw_line in path.read_text(encoding="utf-8").splitlines():
    if not raw_line or raw_line.startswith((" ", "#")) or ":" not in raw_line:
        continue
    key, value = raw_line.split(":", 1)
    if key in expected:
        if key in values:
            raise SystemExit(f"duplicate etcd config key: {key}")
        values[key] = value.strip()
if values != expected:
    raise SystemExit("local etcd config is not the native final underlay shape")
PY
}

is_legacy_forwarder_unit() {
  local unit="$1"
  [[ "$unit" == "heteronetwork-dcs-ingress-79.service" \
    || "$unit" == "heteronetwork-dcs-ingress-80.service" \
    || "$unit" =~ ^heteronetwork-dcs-proxy-.+-(79|80)\.service$ ]]
}

require_legacy_forwarder_unit() {
  is_legacy_forwarder_unit "$1" \
    || die "refusing unrelated systemd unit: $1"
}

legacy_forwarder_fragment_kind() {
  local unit="$1"
  local fragment="$2"
  require_legacy_forwarder_unit "$unit"
  if [[ "$fragment" == "$systemd_unit_dir/$unit" ]]; then
    printf 'persistent'
    return 0
  fi
  if [[ "$fragment" == "/run/systemd/transient/$unit" ]]; then
    printf 'transient'
    return 0
  fi
  return 1
}

validated_forwarder_kind=""
validated_forwarder_listener=""

validate_legacy_forwarder_unit_runtime() {
  local unit="$1"
  local fragment kind transient unit_file_state exec_start listener
  require_legacy_forwarder_unit "$unit"
  fragment="$(
    systemctl_action show --property=FragmentPath --value "$unit"
  )" || die "failed to inspect legacy forwarder fragment: $unit"
  kind="$(legacy_forwarder_fragment_kind "$unit" "$fragment")" \
    || die "refusing legacy forwarder outside managed systemd paths: $unit"
  transient="$(
    systemctl_action show --property=Transient --value "$unit"
  )" || die "failed to inspect legacy forwarder transient state: $unit"
  unit_file_state="$(
    systemctl_action show --property=UnitFileState --value "$unit"
  )" || die "failed to inspect legacy forwarder unit-file state: $unit"
  if [[ "$kind" == "transient" ]]; then
    [[ "$transient" == "yes" && "$unit_file_state" == "transient" ]] \
      || die "legacy transient forwarder has inconsistent systemd state: $unit"
  else
    [[ "$transient" == "no" ]] \
      || die "legacy persistent forwarder is unexpectedly transient: $unit"
  fi

  exec_start="$(
    systemctl_action show --property=ExecStart --value "$unit"
  )" || die "failed to inspect legacy forwarder command: $unit"
  if ! listener="$(
    python3 - \
      "$unit" "$exec_start" "$node_address" "$legacy_node_address" \
      "$members" "$dcs_client_port" "$dcs_peer_port" <<'PY'
import ipaddress
import re
import sys

unit, rendered, node_address, legacy_address, members, client_port, peer_port = (
    sys.argv[1:]
)
if "path=/usr/bin/socat" not in rendered or "ignore_errors=no" not in rendered:
    raise SystemExit("forwarder does not execute the managed socat binary")
match = re.search(
    r"argv\[\]=/usr/bin/socat ([^ ]+) ([^ ;]+) ;",
    rendered,
)
if match is None:
    raise SystemExit("forwarder argv is not the managed two-socket shape")
listener, target = match.groups()
ingress = re.fullmatch(r"heteronetwork-dcs-ingress-(79|80)\.service", unit)
proxy = re.fullmatch(r"heteronetwork-dcs-proxy-.+-(79|80)\.service", unit)
if ingress is not None:
    port = client_port if ingress.group(1) == "79" else peer_port
    expected_listener = (
        f"TCP4-LISTEN:{port},bind={node_address},reuseaddr,fork"
    )
    expected_target = f"TCP4:{legacy_address}:{port},bind=127.0.0.1"
    if listener != expected_listener or target != expected_target:
        raise SystemExit("ingress forwarder endpoints do not match this member")
    print(f"{node_address}:{port}")
    raise SystemExit(0)
if proxy is None:
    raise SystemExit("forwarder unit name is outside the managed family")
port = client_port if proxy.group(1) == "79" else peer_port
listener_match = re.fullmatch(
    r"TCP4-LISTEN:([0-9]+),bind=127\.0\.0\.1,reuseaddr,fork",
    listener,
)
target_match = re.fullmatch(r"TCP4:([0-9]+(?:\.[0-9]+){3}):([0-9]+)", target)
if listener_match is None or target_match is None:
    raise SystemExit("proxy forwarder endpoints do not match the managed shape")
listen_port = int(listener_match.group(1))
if not 1024 <= listen_port <= 65535 or listen_port in {
    int(client_port),
    int(peer_port),
}:
    raise SystemExit("proxy forwarder listen port is unsafe")
if not str(listen_port).endswith(proxy.group(1)):
    raise SystemExit("proxy forwarder listen port does not match its unit suffix")
target_address, target_port = target_match.groups()
if target_port != port:
    raise SystemExit("proxy forwarder target port does not match its unit suffix")
managed_addresses = set()
for entry in members.split(","):
    name, address = entry.split("=", 1)
    if not name:
        raise SystemExit("invalid managed member map")
    managed_addresses.add(str(ipaddress.ip_address(address)))
if target_address not in managed_addresses:
    raise SystemExit("proxy forwarder target is not a managed underlay member")
print(f"127.0.0.1:{listen_port}")
PY
  )"; then
    die "refusing legacy forwarder with an unexpected command: $unit"
  fi

  if systemctl_action is-active --quiet "$unit"; then
    local main_pid sockets
    main_pid="$(
      systemctl_action show --property=MainPID --value "$unit"
    )" || die "failed to inspect legacy forwarder PID: $unit"
    [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] \
      || die "active legacy forwarder has no valid main PID: $unit"
    sockets="$(ss -H -ltnp)" \
      || die "failed to inspect listening sockets for $unit"
    python3 - "$listener" "$main_pid" "$sockets" <<'PY' \
      || die "legacy forwarder does not own its expected listening socket: $unit"
import re
import sys

listener, expected_pid, sockets = sys.argv[1:]
matches = []
for line in sockets.splitlines():
    fields = line.split()
    if len(fields) >= 6 and fields[3] == listener:
        matches.append(line)
if len(matches) != 1:
    raise SystemExit(1)
pids = re.findall(r"pid=([0-9]+)", matches[0])
if pids != [expected_pid]:
    raise SystemExit(1)
PY
  fi
  validated_forwarder_kind="$kind"
  validated_forwarder_listener="$listener"
}

stop_local_ingress_forwarders() {
  local suffix port unit load_state
  while read -r suffix port; do
    unit="heteronetwork-dcs-ingress-${suffix}.service"
    load_state="$(
      systemctl_action show --property=LoadState --value "$unit"
    )" || die "failed to inspect local DCS ingress unit: $unit"
    [[ "$load_state" != "not-found" ]] || continue
    validate_legacy_forwarder_unit_runtime "$unit"
    [[ "$validated_forwarder_listener" == "${node_address}:${port}" ]] \
      || die "local DCS ingress listener differs from the expected endpoint: $unit"
    if systemctl_action is-active --quiet "$unit"; then
      systemctl_action stop "$unit" \
        || die "failed to stop local DCS ingress unit: $unit"
    fi
    systemctl_action is-active --quiet "$unit" \
      && die "local DCS ingress unit remains active: $unit"
    if [[ "$validated_forwarder_kind" == "persistent" ]] \
      && systemctl_action is-enabled --quiet "$unit"; then
      die "persistent local DCS ingress must be disabled before migration: $unit"
    fi
  done <<EOF
79 ${dcs_client_port}
80 ${dcs_peer_port}
EOF
}

discover_legacy_forwarder_units() {
  local unit state path unit_files loaded_units
  local -A found=()
  unit_files="$(list_unit_files_action)" \
    || die "failed to list systemd service unit files"
  while read -r unit state _; do
    [[ -n "${unit:-}" ]] || continue
    if is_legacy_forwarder_unit "$unit"; then
      found["$unit"]=1
    fi
  done <<<"$unit_files"
  loaded_units="$(list_units_action)" \
    || die "failed to list loaded systemd service units"
  while read -r unit _; do
    [[ -n "${unit:-}" ]] || continue
    if is_legacy_forwarder_unit "$unit"; then
      found["$unit"]=1
    fi
  done <<<"$loaded_units"

  local -a paths=()
  shopt -s nullglob
  paths+=(
    "$systemd_unit_dir"/heteronetwork-dcs-ingress-79.service
    "$systemd_unit_dir"/heteronetwork-dcs-ingress-80.service
    "$systemd_unit_dir"/heteronetwork-dcs-proxy-*-79.service
    "$systemd_unit_dir"/heteronetwork-dcs-proxy-*-80.service
  )
  shopt -u nullglob
  for path in "${paths[@]}"; do
    [[ -e "$path" || -L "$path" ]] || continue
    unit="$(basename -- "$path")"
    require_legacy_forwarder_unit "$unit"
    found["$unit"]=1
  done
  if ((${#found[@]} > 0)); then
    printf '%s\n' "${!found[@]}" | sort
  fi
}

remove_legacy_forwarders() {
  local units unit path kind
  units="$(discover_legacy_forwarder_units)"
  if [[ -z "$units" ]]; then
    systemctl_action daemon-reload
    return 0
  fi
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    require_legacy_forwarder_unit "$unit"
    path="$systemd_unit_dir/$unit"
    validate_legacy_forwarder_unit_runtime "$unit"
    kind="$validated_forwarder_kind"
    if ! systemctl_action stop "$unit" >/dev/null 2>&1; then
      if systemctl_action is-active --quiet "$unit"; then
        die "failed to stop legacy forwarder unit: $unit"
      fi
    fi
    if [[ "$kind" == "persistent" ]]; then
      systemctl_action is-enabled --quiet "$unit" \
        && die "persistent legacy forwarder must be disabled before cleanup: $unit"
    fi
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -f "$path" || -L "$path" ]] \
        || die "refusing non-file legacy forwarder path: $path"
      rm -f -- "$path"
    fi
  done <<<"$units"
  systemctl_action daemon-reload

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    path="$systemd_unit_dir/$unit"
    [[ ! -e "$path" && ! -L "$path" ]] \
      || die "legacy forwarder unit file remains: $unit"
    if systemctl_action is-active --quiet "$unit"; then
      die "legacy forwarder unit remains active: $unit"
    fi
    if systemctl_action is-enabled --quiet "$unit"; then
      die "legacy forwarder unit remains enabled: $unit"
    fi
  done <<<"$units"
}

cleanup_legacy_forwarders() {
  require_root
  acquire_local_lock
  require_command openssl
  require_command python3
  require_command ss
  require_command systemctl
  load_node_context true
  validate_local_network
  require_existing_installation true
  local snapshot
  snapshot="$(verify_all_dcs_endpoints)" \
    || die "all DCS endpoints must be healthy before legacy forwarder cleanup"
  snapshot_is_all_final "$snapshot" \
    || die "all DCS voters must use final underlay peer URLs before cleanup"
  validate_native_final_etcd_config
  systemctl_action is-active --quiet "$etcd_service" \
    || die "native local etcd service is not active"
  verify_local_etcd_listener_ownership
  installed_etcdctl_at \
    "https://${node_address}:${dcs_client_port}" \
    endpoint health >/dev/null \
    || die "native local underlay etcd endpoint is not healthy"
  remove_legacy_forwarders
  log "removed obsolete local DCS socat forwarders after native underlay verification"
}

self_test() {
  require_non_root
  require_command install
  require_command openssl
  require_command python3
  require_command sha256sum
  local test_dir
  test_dir="$(mktemp -d /tmp/heteronetwork-postgres-ha-underlay-test.XXXXXX)"
  register_cleanup_target "$test_dir"

  local legacy="$test_dir/legacy"
  local adopted="$test_dir/adopted"
  install -d -m 0700 "$legacy/ca" "$legacy/secrets"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$legacy/ca/ca.key"
  openssl req -new -x509 -key "$legacy/ca/ca.key" \
    -out "$legacy/ca/ca.crt" -days 3650 -sha256 \
    -subj "/CN=HeteroNetwork migration self-test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  chmod 0600 "$legacy/ca/ca.key"
  chmod 0644 "$legacy/ca/ca.crt"
  local secret
  for secret in superuser replication rewind application rest-api; do
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n' \
      >"$legacy/secrets/${secret}.password"
    chmod 0600 "$legacy/secrets/${secret}.password"
  done

  cluster_name="heteronetwork"
  cluster_id="12345678-1234-4123-8123-123456789abc"
  legacy_members="db-a=10.250.0.2,db-b=10.250.0.3,db-c=10.250.0.4"
  members="db-a=100.64.10.1,db-b=100.64.10.2,db-c=100.64.10.3"
  member_identities="db-a=node-a,db-b=node-b,db-c=node-c"
  dcs_members="$members"
  legacy_dcs_members=""
  dcs_bootstrap_members="$members"
  client_cidrs="192.0.2.0/24,198.51.100.10/32"
  extra_hba_entries="keycloak:keycloak:10.250.0.10/32"
  service_name="postgres.heteronetwork.internal"
  state_dir="$DEFAULT_STATE_DIR"
  data_dir="$DEFAULT_DATA_DIR"
  dcs_data_dir="${DEFAULT_DATA_DIR}-dcs"
  client_ca_path="$DEFAULT_CLIENT_CA_PATH"
  postgres_port="55432"
  rest_port="18008"
  dcs_client_port="12379"
  dcs_peer_port="12380"
  dcs_metrics_port="12381"
  proxy_port="25432"
  postgres_major="17"
  topology_revision="9"
  network_plane="underlay-v1"
  helper="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/postgres-ha-node.sh"
  cat >"$legacy/manifest.env" <<'EOF'
HETERONETWORK_DB_CLUSTER_NAME=heteronetwork
HETERONETWORK_DB_MEMBERS=db-retired=10.250.0.1,db-a=10.250.0.2,db-b=10.250.0.3,db-c=10.250.0.4
HETERONETWORK_DB_DCS_MEMBERS=db-retired=10.250.0.1,db-a=10.250.0.2,db-b=10.250.0.3
HETERONETWORK_DB_SERVICE_NAME=postgres.heteronetwork.internal
HETERONETWORK_DB_POSTGRES_PORT=55432
HETERONETWORK_DB_REST_PORT=18008
HETERONETWORK_DB_TOPOLOGY_REVISION=8
EOF
  chmod 0600 "$legacy/manifest.env"
  adopt_bundle "$adopted" "$legacy" >/dev/null

  grep -Fxq "$cluster_id" "$adopted/cluster-id"
  [[ "$(stat -c '%a' "$adopted/cluster-id")" == "600" ]]
  grep -Fxq "HETERONETWORK_DB_LEGACY_MEMBERS=${legacy_members}" \
    "$adopted/manifest.env"
  grep -Fxq "HETERONETWORK_DB_MEMBERS=${members}" "$adopted/manifest.env"
  grep -Fxq \
    "HETERONETWORK_DB_MEMBER_IDENTITIES=${member_identities}" \
    "$adopted/manifest.env"
  grep -Fxq \
    "HETERONETWORK_DB_LEGACY_DCS_MEMBERS=${legacy_members}" \
    "$adopted/manifest.env"
  grep -Fxq "HETERONETWORK_DB_DCS_MEMBERS=${members}" \
    "$adopted/manifest.env"
  grep -Fxq \
    "HETERONETWORK_DB_CLIENT_CIDRS=${client_cidrs}" \
    "$adopted/manifest.env"
  grep -Fxq \
    "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=${extra_hba_entries}" \
    "$adopted/manifest.env"
  grep -Fxq 'HETERONETWORK_DB_TOPOLOGY_REVISION=9' \
    "$adopted/manifest.env"
  grep -Fxq 'HETERONETWORK_DB_NETWORK_PLANE=underlay-v1' \
    "$adopted/manifest.env"
  cmp -s "$legacy/ca/ca.key" "$adopted/ca/ca.key"
  for secret in superuser replication rewind application rest-api; do
    cmp -s \
      "$legacy/secrets/${secret}.password" \
      "$adopted/secrets/${secret}.password"
  done
  validate_bundle "$adopted"
  openssl x509 -in "$adopted/nodes/db-a/node.crt" -noout \
    -checkhost postgres.heteronetwork.internal >/dev/null
  openssl x509 -in "$adopted/nodes/db-a/node.crt" -noout \
    -checkhost db-a.postgres.heteronetwork.internal >/dev/null
  openssl x509 -in "$adopted/nodes/db-a/node.crt" -noout \
    -checkip 10.250.0.2 >/dev/null
  openssl x509 -in "$adopted/nodes/db-a/node.crt" -noout \
    -checkip 100.64.10.1 >/dev/null

  bundle_dir="$adopted"
  node_name="db-a"
  legacy_node_address="10.250.0.2"
  node_address="100.64.10.1"
  route_output_matches \
    '100.64.10.2 dev tailscale0 src 100.64.10.1 uid 0' \
    tailscale0 100.64.10.1
  if route_output_matches \
      '100.64.10.2 dev heteronetwork0 src 10.250.0.2 uid 0' \
      tailscale0 100.64.10.1; then
    die "route validator accepted the wrong interface and source"
  fi
  local transition="$test_dir/transition.yml"
  local final="$test_dir/final.yml"
  render_transition_etcd_config >"$transition"
  render_final_etcd_config >"$final"
  grep -Fxq \
    'listen-peer-urls: https://10.250.0.2:12380,https://100.64.10.1:12380' \
    "$transition"
  grep -Fxq \
    'initial-advertise-peer-urls: https://10.250.0.2:12380' \
    "$transition"
  grep -Fxq \
    'listen-client-urls: https://127.0.0.1:12379,https://10.250.0.2:12379,https://100.64.10.1:12379' \
    "$transition"
  grep -Fxq \
    'initial-advertise-peer-urls: https://100.64.10.1:12380' \
    "$final"
  if grep -Fq 'listen-peer-urls: https://10.250.0.2' "$final"; then
    die "final etcd renderer retained the legacy peer listener"
  fi

  local patroni_source="$test_dir/patroni.yml"
  local patroni_dual="$test_dir/patroni-dual.yml"
  cat >"$patroni_source" <<'EOF'
scope: heteronetwork
name: db-a

restapi:
  listen: 10.250.0.2:18008
  connect_address: 10.250.0.2:18008

etcd3:
  hosts:
    - 10.250.0.2:12379
    - 10.250.0.3:12379
    - 10.250.0.4:12379
  protocol: https
  cacert: /etc/heteronetwork/postgres-ha/pki/ca.crt

postgresql:
  listen: 10.250.0.2:55432
  connect_address: 10.250.0.2:55432
EOF
  render_patroni_dual_hosts "$patroni_source" "$patroni_dual"
  [[ "$(grep -c '^    - .*:12379$' "$patroni_dual")" == "6" ]]
  grep -Fxq '    - 100.64.10.3:12379' "$patroni_dual"
  grep -Fxq '  listen: 10.250.0.2:18008' "$patroni_dual"
  grep -Fxq '  connect_address: 10.250.0.2:18008' "$patroni_dual"
  grep -Fxq '  listen: 10.250.0.2:55432' "$patroni_dual"
  grep -Fxq '  connect_address: 10.250.0.2:55432' "$patroni_dual"
  local patroni_dual_again="$test_dir/patroni-dual-again.yml"
  render_patroni_dual_hosts "$patroni_dual" "$patroni_dual_again"
  cmp -s "$patroni_dual" "$patroni_dual_again"
  local malformed="$test_dir/patroni-malformed.yml"
  sed 's/10.250.0.3:12379/203.0.113.99:12379/' \
    "$patroni_source" >"$malformed"
  if (
    render_patroni_dual_hosts \
      "$malformed" "$test_dir/should-not-render.yml" >/dev/null 2>&1
  ); then
    die "Patroni renderer accepted an unmanaged DCS endpoint"
  fi

  local action_log="$test_dir/system-actions.log"
  patroni_service="heteronetwork-db.service"
  systemctl_action() {
    printf '%s\n' "$*" >>"$action_log"
    case "${1:-}" in
      is-active) return 0 ;;
      is-enabled) return 1 ;;
      *) return 0 ;;
    esac
  }
  hup_patroni
  grep -Fxq \
    'kill --kill-whom=main --signal=HUP heteronetwork-db.service' \
    "$action_log"

  node_address="100.64.10.1"
  legacy_node_address="10.250.0.2"
  systemd_unit_dir="$test_dir/systemd"
  local ingress_active=1
  systemctl_action() {
    printf '%s\n' "$*" >>"$action_log"
    local action="${1:-}" property="" unit="${*: -1}"
    if [[ "$action" == "show" ]]; then
      property="${2:-}"
      if [[ "$unit" == "heteronetwork-dcs-ingress-80.service" ]]; then
        [[ "$property" != "--property=LoadState" ]] || printf 'not-found\n'
        return 0
      fi
      case "$property" in
        --property=LoadState) printf 'loaded\n' ;;
        --property=FragmentPath)
          printf '/run/systemd/transient/%s\n' "$unit"
          ;;
        --property=Transient) printf 'yes\n' ;;
        --property=UnitFileState) printf 'transient\n' ;;
        --property=ExecStart)
          printf '{ path=/usr/bin/socat ; argv[]=/usr/bin/socat TCP4-LISTEN:12379,bind=100.64.10.1,reuseaddr,fork TCP4:10.250.0.2:12379,bind=127.0.0.1 ; ignore_errors=no ; }\n'
          ;;
        --property=MainPID) printf '4242\n' ;;
      esac
      return 0
    fi
    case "$action" in
      is-active) [[ "$ingress_active" == "1" ]] ;;
      is-enabled) return 1 ;;
      stop) ingress_active=0 ;;
      *) return 0 ;;
    esac
  }
  ss() {
    printf 'LISTEN 0 5 100.64.10.1:12379 0.0.0.0:* users:(("socat",pid=4242,fd=5))\n'
  }
  : >"$action_log"
  stop_local_ingress_forwarders
  [[ "$ingress_active" == "0" ]]
  grep -Fxq 'stop heteronetwork-dcs-ingress-79.service' "$action_log"

  is_legacy_forwarder_unit heteronetwork-dcs-ingress-79.service
  is_legacy_forwarder_unit heteronetwork-dcs-ingress-80.service
  is_legacy_forwarder_unit heteronetwork-dcs-proxy-db-a-79.service
  is_legacy_forwarder_unit heteronetwork-dcs-proxy-db-b-80.service
  if is_legacy_forwarder_unit heteronetwork-dcs-ingress-81.service; then
    die "legacy forwarder filter accepted ingress port 81"
  fi
  if is_legacy_forwarder_unit heteronetwork-db.service; then
    die "legacy forwarder filter accepted an unrelated unit"
  fi
  if (
    require_legacy_forwarder_unit heteronetwork-dcs-proxy-db-a-81.service
  ) >/dev/null 2>&1; then
    die "legacy forwarder guard did not refuse an unrelated unit"
  fi

  install -d -m 0700 "$systemd_unit_dir"
  touch \
    "$systemd_unit_dir/heteronetwork-dcs-ingress-79.service" \
    "$systemd_unit_dir/heteronetwork-dcs-ingress-80.service" \
    "$systemd_unit_dir/heteronetwork-dcs-proxy-db-a-79.service" \
    "$systemd_unit_dir/heteronetwork-dcs-proxy-db-b-80.service" \
    "$systemd_unit_dir/heteronetwork-db.service"
  list_unit_files_action() {
    printf '%s\n' \
      'heteronetwork-dcs-ingress-79.service enabled' \
      'heteronetwork-dcs-proxy-db-a-79.service enabled' \
      'heteronetwork-db.service enabled'
  }
  list_units_action() {
    printf '%s\n' \
      'heteronetwork-dcs-proxy-db-c-79.service loaded active running transient'
  }
  systemctl_action() {
    printf '%s\n' "$*" >>"$action_log"
    local action="${1:-}" property="" unit="${*: -1}"
    if [[ "$action" == "show" ]]; then
      property="${2:-}"
      case "$property" in
        --property=FragmentPath)
          if [[ "$unit" == "heteronetwork-dcs-proxy-db-c-79.service" ]]; then
            printf '/run/systemd/transient/%s\n' "$unit"
          else
            printf '%s/%s\n' "$systemd_unit_dir" "$unit"
          fi
          ;;
        --property=Transient)
          if [[ "$unit" == "heteronetwork-dcs-proxy-db-c-79.service" ]]; then
            printf 'yes\n'
          else
            printf 'no\n'
          fi
          ;;
        --property=UnitFileState)
          if [[ "$unit" == "heteronetwork-dcs-proxy-db-c-79.service" ]]; then
            printf 'transient\n'
          else
            printf 'disabled\n'
          fi
          ;;
        --property=ExecStart)
          case "$unit" in
            heteronetwork-dcs-ingress-79.service)
              printf '{ path=/usr/bin/socat ; argv[]=/usr/bin/socat TCP4-LISTEN:12379,bind=100.64.10.1,reuseaddr,fork TCP4:10.250.0.2:12379,bind=127.0.0.1 ; ignore_errors=no ; }\n'
              ;;
            heteronetwork-dcs-ingress-80.service)
              printf '{ path=/usr/bin/socat ; argv[]=/usr/bin/socat TCP4-LISTEN:12380,bind=100.64.10.1,reuseaddr,fork TCP4:10.250.0.2:12380,bind=127.0.0.1 ; ignore_errors=no ; }\n'
              ;;
            heteronetwork-dcs-proxy-db-a-79.service)
              printf '{ path=/usr/bin/socat ; argv[]=/usr/bin/socat TCP4-LISTEN:22079,bind=127.0.0.1,reuseaddr,fork TCP4:100.64.10.2:12379 ; ignore_errors=no ; }\n'
              ;;
            heteronetwork-dcs-proxy-db-b-80.service)
              printf '{ path=/usr/bin/socat ; argv[]=/usr/bin/socat TCP4-LISTEN:23080,bind=127.0.0.1,reuseaddr,fork TCP4:100.64.10.3:12380 ; ignore_errors=no ; }\n'
              ;;
            heteronetwork-dcs-proxy-db-c-79.service)
              printf '{ path=/usr/bin/socat ; argv[]=/usr/bin/socat TCP4-LISTEN:24079,bind=127.0.0.1,reuseaddr,fork TCP4:100.64.10.3:12379 ; ignore_errors=no ; }\n'
              ;;
          esac
          ;;
      esac
      return 0
    fi
    case "$action" in
      is-active|is-enabled) return 1 ;;
      *) return 0 ;;
    esac
  }
  : >"$action_log"
  remove_legacy_forwarders
  [[ ! -e "$systemd_unit_dir/heteronetwork-dcs-ingress-79.service" ]]
  [[ ! -e "$systemd_unit_dir/heteronetwork-dcs-ingress-80.service" ]]
  [[ ! -e "$systemd_unit_dir/heteronetwork-dcs-proxy-db-a-79.service" ]]
  [[ ! -e "$systemd_unit_dir/heteronetwork-dcs-proxy-db-b-80.service" ]]
  [[ -e "$systemd_unit_dir/heteronetwork-db.service" ]]
  grep -Fxq 'stop heteronetwork-dcs-proxy-db-c-79.service' "$action_log"
  if grep -Fq 'heteronetwork-db.service' "$action_log"; then
    die "legacy cleanup invoked a system action for an unrelated unit"
  fi
  grep -Fxq 'daemon-reload' "$action_log"

  rm -rf -- "$test_dir"
  printf 'postgres HA underlay migration self-test passed\n'
}

case "${1:-}" in
  adopt-bundle)
    (($# == 3)) \
      || die "adopt-bundle requires exactly OUTPUT_DIR and LEGACY_BUNDLE_DIR"
    shift
    adopt_bundle "${1:-}" "${2:-}"
    ;;
  prepare-node)
    (($# == 1)) || die "prepare-node does not accept positional arguments"
    prepare_node
    ;;
  migrate-dcs-node)
    (($# == 1)) || die "migrate-dcs-node does not accept positional arguments"
    migrate_dcs_node
    ;;
  apply-node)
    (($# == 1)) || die "apply-node does not accept positional arguments"
    apply_node
    ;;
  cleanup-legacy-forwarders)
    (($# == 1)) \
      || die "cleanup-legacy-forwarders does not accept positional arguments"
    cleanup_legacy_forwarders
    ;;
  self-test)
    (($# == 1)) || die "self-test does not accept positional arguments"
    self_test
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
