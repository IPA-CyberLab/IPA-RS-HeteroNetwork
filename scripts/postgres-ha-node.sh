#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_CLUSTER_NAME="heteronetwork"
readonly DEFAULT_INTERFACE="heteronetwork0"
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
readonly PATRONI_VERSION="4.1.4"
readonly ETCD_VERSION="v3.6.11"
readonly ETCD_LINUX_AMD64_SHA256="8756f7a4eaf921668a83de0bf13c0f65cae9186a165696e3ae8396afe6f557ed"
readonly MIN_DATABASE_MEMBER_COUNT="3"
readonly MAX_DATABASE_MEMBER_COUNT="32"
readonly MIN_DCS_MEMBER_COUNT="3"
readonly MAX_DCS_MEMBER_COUNT="9"

cluster_name="${HETERONETWORK_DB_CLUSTER_NAME:-$DEFAULT_CLUSTER_NAME}"
interface="${HETERONETWORK_DB_INTERFACE:-$DEFAULT_INTERFACE}"
node_name="${HETERONETWORK_DB_NODE_NAME:-}"
node_address="${HETERONETWORK_DB_NODE_ADDRESS:-}"
client_listen_address="${HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS:-}"
members="${HETERONETWORK_DB_MEMBERS:-}"
dcs_members="${HETERONETWORK_DB_DCS_MEMBERS:-$members}"
dcs_initial_cluster_state="${HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE:-new}"
proxy_backends="${HETERONETWORK_DB_PROXY_BACKENDS:-$members}"
client_cidrs="${HETERONETWORK_DB_CLIENT_CIDRS:-}"
extra_hba_entries="${HETERONETWORK_DB_EXTRA_HBA_ENTRIES:-}"
service_name="${HETERONETWORK_DB_SERVICE_NAME:-$DEFAULT_SERVICE_NAME}"
state_dir="${HETERONETWORK_DB_STATE_DIR:-$DEFAULT_STATE_DIR}"
data_dir="${HETERONETWORK_DB_DATA_DIR:-$DEFAULT_DATA_DIR}"
dcs_data_dir="${HETERONETWORK_DB_DCS_DATA_DIR:-${data_dir}-dcs}"
client_ca_path="${HETERONETWORK_DB_CLIENT_CA_PATH:-$DEFAULT_CLIENT_CA_PATH}"
bundle_dir="${HETERONETWORK_DB_BUNDLE_DIR:-}"
postgres_port="${HETERONETWORK_DB_POSTGRES_PORT:-$DEFAULT_POSTGRES_PORT}"
rest_port="${HETERONETWORK_DB_REST_PORT:-$DEFAULT_REST_PORT}"
dcs_client_port="${HETERONETWORK_DB_DCS_CLIENT_PORT:-$DEFAULT_DCS_CLIENT_PORT}"
dcs_peer_port="${HETERONETWORK_DB_DCS_PEER_PORT:-$DEFAULT_DCS_PEER_PORT}"
dcs_metrics_port="${HETERONETWORK_DB_DCS_METRICS_PORT:-$DEFAULT_DCS_METRICS_PORT}"
proxy_port="${HETERONETWORK_DB_PROXY_PORT:-$DEFAULT_PROXY_PORT}"
postgres_major="${HETERONETWORK_DB_POSTGRES_MAJOR:-$DEFAULT_POSTGRES_MAJOR}"
topology_revision="${HETERONETWORK_DB_TOPOLOGY_REVISION:-1}"

usage() {
  cat <<'EOF'
Usage: postgres-ha-node.sh COMMAND [OUTPUT_DIR]

Commands:
  init-bundle OUTPUT_DIR  Create an offline CA, per-node certificates, and cluster secrets
  extend-bundle DIR       Add certificates and update metadata in an existing private bundle
  install-node            Install this PostgreSQL/Patroni member and optional DCS voter
  reconfigure-node        Apply a new member map without replacing PostgreSQL data
  reconcile-dcs           Add or promote at most one DCS learner
  install-proxy           Install only the local primary-selecting database proxy
  verify                  Require DCS quorum, one primary, all replicas, and synchronous writes
  status                  Print bounded cluster health without printing credentials
  self-test               Run non-privileged config renderer and validation checks

Required environment for init-bundle:
  HETERONETWORK_DB_MEMBERS       3-32 name=private-ip entries, comma separated

Required environment for install-node:
  HETERONETWORK_DB_NODE_NAME
  HETERONETWORK_DB_NODE_ADDRESS
  HETERONETWORK_DB_MEMBERS
  HETERONETWORK_DB_BUNDLE_DIR

Required environment for install-proxy:
  HETERONETWORK_DB_PROXY_BACKENDS  3-32 name=private-ip entries
  HETERONETWORK_DB_BUNDLE_DIR

Optional environment:
  HETERONETWORK_DB_INTERFACE       Default: heteronetwork0
  HETERONETWORK_DB_DCS_MEMBERS     Odd 3-9 voter entries; defaults to DB members
  HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE
                                     new for a fresh quorum, existing when joining one
  HETERONETWORK_DB_TOPOLOGY_REVISION
                                     Monotonic positive integer, default: 1
  HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS
                                     Optional private management address used by remote proxies
  HETERONETWORK_DB_CLIENT_CIDRS    Additional comma-separated application source CIDRs
  HETERONETWORK_DB_EXTRA_HBA_ENTRIES
                                     Comma-separated database:user:CIDR access rules
  HETERONETWORK_DB_CLIENT_CA_PATH  Default: /etc/ssl/certs/heteronetwork-postgres-ha-ca.crt
  HETERONETWORK_DB_SERVICE_NAME    Default: postgres.heteronetwork.internal
  HETERONETWORK_DB_POSTGRES_PORT   Default: 55432
  HETERONETWORK_DB_REST_PORT       Default: 18008
  HETERONETWORK_DB_PROXY_PORT      Default: 25432

The replication addresses need only be mutually reachable private addresses.
They must remain available independently of this database's current primary.
The automatic coordinator replicates the private bundle only among enrolled
database members. Manual recovery bundles must remain root-only.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' is not available"
}

validate_name() {
  local value="$1"
  [[ ${#value} -le 63 && "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] \
    || die "invalid lowercase node or cluster name: $value"
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
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] \
    || die "invalid IPv4 address: $value"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || die "invalid IPv4 address: $value"
    ((10#$octet <= 255)) || die "invalid IPv4 address: $value"
  done
}

validate_port() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] || die "invalid TCP port: $value"
  ((10#$value >= 1024 && 10#$value <= 65535)) || die "port is outside 1024-65535: $value"
}

validate_absolute_path() {
  [[ "$1" == /* ]] || die "path must be absolute: $1"
}

member_rows_for() {
  local input="$1"
  local label="$2"
  local minimum="$3"
  local maximum="$4"
  local require_odd="$5"
  local -a entries
  local entry name address
  IFS=, read -r -a entries <<<"$input"
  ((${#entries[@]} >= minimum && ${#entries[@]} <= maximum)) \
    || die "$label member count must be between $minimum and $maximum"
  if [[ "$require_odd" == "true" ]]; then
    ((${#entries[@]} % 2 == 1)) || die "$label member count must be odd"
  fi

  local -A seen_names=()
  local -A seen_addresses=()
  for entry in "${entries[@]}"; do
    [[ "$entry" == "${entry//[[:space:]]/}" ]] || die "member entries must not contain whitespace"
    [[ "$entry" == *=* ]] || die "member entry must use name=private-ip: $entry"
    name="${entry%%=*}"
    address="${entry#*=}"
    validate_name "$name"
    validate_ipv4 "$address"
    [[ -z "${seen_names[$name]:-}" ]] || die "duplicate member name: $name"
    [[ -z "${seen_addresses[$address]:-}" ]] || die "duplicate member address: $address"
    seen_names[$name]=1
    seen_addresses[$address]=1
    printf '%s %s\n' "$name" "$address"
  done
}

member_rows() {
  member_rows_for "$members" database \
    "$MIN_DATABASE_MEMBER_COUNT" "$MAX_DATABASE_MEMBER_COUNT" false
}

dcs_member_rows() {
  member_rows_for "$dcs_members" DCS \
    "$MIN_DCS_MEMBER_COUNT" "$MAX_DCS_MEMBER_COUNT" false
}

proxy_backend_rows() {
  member_rows_for "$proxy_backends" proxy \
    "$MIN_DATABASE_MEMBER_COUNT" "$MAX_DATABASE_MEMBER_COUNT" false
}

database_member_count() {
  member_rows | wc -l | tr -d ' '
}

dcs_member_count() {
  dcs_member_rows | wc -l | tr -d ' '
}

synchronous_standby_count() {
  local count
  count="$(dcs_member_count)"
  printf '%s' "$(((10#$count - 1) / 2))"
}

validate_cidr() {
  local value="$1"
  local address prefix
  [[ "$value" == */* ]] || die "CIDR must include a prefix: $value"
  address="${value%/*}"
  prefix="${value#*/}"
  validate_ipv4 "$address"
  [[ "$prefix" =~ ^[0-9]{1,2}$ ]] || die "invalid IPv4 CIDR prefix: $value"
  ((10#$prefix <= 32)) || die "invalid IPv4 CIDR prefix: $value"
}

validate_sql_identifier() {
  local value="$1"
  [[ ${#value} -le 63 && "$value" =~ ^[a-z_][a-z0-9_]*$ ]] \
    || die "invalid lowercase PostgreSQL identifier: $value"
}

extra_hba_rows() {
  [[ -n "$extra_hba_entries" ]] || return 0
  local -a entries
  local entry database user cidr remainder
  local -A seen=()
  IFS=, read -r -a entries <<<"$extra_hba_entries"
  for entry in "${entries[@]}"; do
    [[ "$entry" == "${entry//[[:space:]]/}" ]] \
      || die "extra HBA entries must not contain whitespace"
    database="${entry%%:*}"
    remainder="${entry#*:}"
    [[ "$remainder" != "$entry" ]] \
      || die "extra HBA entry must use database:user:CIDR: $entry"
    user="${remainder%%:*}"
    cidr="${remainder#*:}"
    [[ "$cidr" != "$remainder" && "$cidr" != *:* ]] \
      || die "extra HBA entry must use database:user:CIDR: $entry"
    validate_sql_identifier "$database"
    validate_sql_identifier "$user"
    validate_cidr "$cidr"
    [[ -z "${seen[$entry]:-}" ]] || continue
    seen[$entry]=1
    printf '%s %s %s\n' "$database" "$user" "$cidr"
  done
}

application_cidrs() {
  local -A seen=()
  local name address cidr
  while read -r name address; do
    cidr="${address}/32"
    if [[ -z "${seen[$cidr]:-}" ]]; then
      seen[$cidr]=1
      printf '%s\n' "$cidr"
    fi
  done < <(member_rows)
  printf '127.0.0.1/32\n'
  seen["127.0.0.1/32"]=1

  [[ -n "$client_cidrs" ]] || return 0
  local -a values
  IFS=, read -r -a values <<<"$client_cidrs"
  for cidr in "${values[@]}"; do
    [[ "$cidr" == "${cidr//[[:space:]]/}" ]] || die "client CIDRs must not contain whitespace"
    validate_cidr "$cidr"
    if [[ -z "${seen[$cidr]:-}" ]]; then
      seen[$cidr]=1
      printf '%s\n' "$cidr"
    fi
  done
}

validate_common_config() {
  validate_name "$cluster_name"
  validate_dns_name "$service_name"
  validate_absolute_path "$state_dir"
  validate_absolute_path "$data_dir"
  validate_absolute_path "$dcs_data_dir"
  validate_absolute_path "$client_ca_path"
  [[ "$dcs_data_dir" != "$data_dir" ]] || die "PostgreSQL and DCS data paths must differ"
  validate_port "$postgres_port"
  validate_port "$rest_port"
  validate_port "$dcs_client_port"
  validate_port "$dcs_peer_port"
  validate_port "$dcs_metrics_port"
  validate_port "$proxy_port"
  [[ "$postgres_major" =~ ^[0-9]{2}$ ]] || die "PostgreSQL major must be a two-digit version"
  [[ "$topology_revision" =~ ^[1-9][0-9]*$ ]] || die "topology revision must be positive"
  member_rows >/dev/null
  dcs_member_rows >/dev/null
  [[ "$dcs_initial_cluster_state" == "new" || "$dcs_initial_cluster_state" == "existing" ]] \
    || die "DCS initial cluster state must be new or existing"
  if [[ "$dcs_initial_cluster_state" == "new" ]]; then
    local initial_dcs_count
    initial_dcs_count="$(dcs_member_count)"
    ((10#$initial_dcs_count % 2 == 1)) \
      || die "a fresh DCS member count must be odd"
  fi
  local -A database_members=()
  local name address
  while read -r name address; do
    database_members["$name"]="$address"
  done < <(member_rows)
  while read -r name address; do
    [[ "${database_members[$name]:-}" == "$address" ]] \
      || die "DCS member $name=$address is not present in HETERONETWORK_DB_MEMBERS"
  done < <(dcs_member_rows)
  application_cidrs >/dev/null
  extra_hba_rows >/dev/null
}

validate_node_config() {
  validate_common_config
  validate_name "$node_name"
  validate_ipv4 "$node_address"
  if [[ -n "$client_listen_address" ]]; then
    validate_ipv4 "$client_listen_address"
    [[ "$client_listen_address" != "$node_address" ]] \
      || die "client listen address must differ from the replication address"
  fi
  [[ -n "$bundle_dir" ]] || die "HETERONETWORK_DB_BUNDLE_DIR is required"
  validate_absolute_path "$bundle_dir"

  local found=0 name address
  while read -r name address; do
    if [[ "$name" == "$node_name" && "$address" == "$node_address" ]]; then
      found=1
    fi
  done < <(member_rows)
  ((found == 1)) || die "$node_name=$node_address is not present in HETERONETWORK_DB_MEMBERS"
}

validate_proxy_config() {
  validate_common_config
  [[ -n "$bundle_dir" ]] || die "HETERONETWORK_DB_BUNDLE_DIR is required"
  validate_absolute_path "$bundle_dir"
  proxy_backend_rows >/dev/null
}

node_is_dcs_member() {
  local name address found=1
  while read -r name address; do
    if [[ "$name" == "$node_name" && "$address" == "$node_address" ]]; then
      found=0
    fi
  done < <(dcs_member_rows)
  return "$found"
}

ensure_private_source_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "required private regular file is missing: $path"
  local links
  links="$(stat -c '%h' "$path")"
  [[ "$links" == "1" ]] || die "private file must not have hard links: $path"
}

validate_client_ca_parent() {
  local parent
  parent="$(dirname -- "$client_ca_path")"
  [[ -d "$parent" && ! -L "$parent" ]] \
    || die "client CA parent must be an existing non-symlink directory: $parent"
}

read_cluster_secret() {
  local name="$1"
  local path="${bundle_dir}/secrets/${name}.password"
  ensure_private_source_file "$path"
  local value
  value="$(tr -d '\r\n' <"$path")"
  [[ "$value" =~ ^[A-Za-z0-9]{32,128}$ ]] || die "invalid generated secret file: $path"
  printf '%s' "$value"
}

render_etcd_config() {
  local initial_cluster="" name address
  while read -r name address; do
    [[ -z "$initial_cluster" ]] || initial_cluster+=","
    initial_cluster+="${name}=https://${address}:${dcs_peer_port}"
  done < <(dcs_member_rows)

  cat <<EOF
name: ${node_name}
data-dir: ${dcs_data_dir}
listen-peer-urls: https://${node_address}:${dcs_peer_port}
initial-advertise-peer-urls: https://${node_address}:${dcs_peer_port}
listen-client-urls: https://127.0.0.1:${dcs_client_port},https://${node_address}:${dcs_client_port}
advertise-client-urls: https://${node_address}:${dcs_client_port}
listen-metrics-urls: http://127.0.0.1:${dcs_metrics_port}
initial-cluster: ${initial_cluster}
initial-cluster-token: ${cluster_name}-postgres-dcs-v1
initial-cluster-state: ${dcs_initial_cluster_state}
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

render_patroni_config() {
  local superuser_password replication_password rewind_password rest_password
  local synchronous_count replication_capacity
  superuser_password="$(read_cluster_secret superuser)"
  replication_password="$(read_cluster_secret replication)"
  rewind_password="$(read_cluster_secret rewind)"
  rest_password="$(read_cluster_secret rest-api)"
  synchronous_count="$(synchronous_standby_count)"
  replication_capacity="$((10#$MAX_DATABASE_MEMBER_COUNT + 4))"

  cat <<EOF
scope: ${cluster_name}
namespace: /heteronetwork/postgres/
name: ${node_name}

restapi:
  listen: ${node_address}:${rest_port}
  connect_address: ${node_address}:${rest_port}
  certfile: ${state_dir}/pki/node.crt
  keyfile: ${state_dir}/pki/node.key
  authentication:
    username: patroni
    password: ${rest_password}
  allowlist_include_members: true

ctl:
  cacert: ${state_dir}/pki/ca.crt

etcd3:
  hosts:
EOF
  local name address
  while read -r name address; do
    printf '    - %s:%s\n' "$address" "$dcs_client_port"
  done < <(dcs_member_rows)
  cat <<EOF
  protocol: https
  cacert: ${state_dir}/pki/ca.crt
  cert: ${state_dir}/pki/node.crt
  key: ${state_dir}/pki/node.key

bootstrap:
  dcs:
    ttl: 20
    loop_wait: 5
    retry_timeout: 5
    primary_start_timeout: 0
    maximum_lag_on_failover: 0
    maximum_lag_on_syncnode: 0
    check_timeline: true
    failsafe_mode: true
    synchronous_mode: true
    synchronous_mode_strict: true
    synchronous_node_count: ${synchronous_count}
    postgresql:
      use_pg_rewind: true
      use_slots: true
      parameters:
        password_encryption: scram-sha-256
        synchronous_commit: "on"
        wal_level: replica
        wal_log_hints: "on"
        max_wal_senders: ${replication_capacity}
        max_replication_slots: ${replication_capacity}
        max_connections: 200
        ssl: "on"
        ssl_min_protocol_version: TLSv1.2
        ssl_cert_file: ${state_dir}/pki/node.crt
        ssl_key_file: ${state_dir}/pki/node.key
        ssl_ca_file: ${state_dir}/pki/ca.crt
        shared_preload_libraries: ""
  initdb:
    - encoding: UTF8
    - locale: C.utf8
    - data-checksums
  post_bootstrap: /opt/heteronetwork/postgres-ha/bootstrap-database
  pg_hba:
EOF
  render_pg_hba_entries "    "
  cat <<EOF

postgresql:
  pg_hba:
EOF
  render_pg_hba_entries "    "
  cat <<EOF
  listen: ${node_address}${client_listen_address:+,${client_listen_address}}:${postgres_port}
  connect_address: ${node_address}:${postgres_port}
  data_dir: ${data_dir}/postgres
  bin_dir: /usr/lib/postgresql/${postgres_major}/bin
  pgpass: ${data_dir}/pgpass
  authentication:
    superuser:
      username: postgres
      password: ${superuser_password}
      sslmode: verify-full
      sslrootcert: ${state_dir}/pki/ca.crt
    replication:
      username: replicator
      password: ${replication_password}
      sslmode: verify-full
      sslrootcert: ${state_dir}/pki/ca.crt
    rewind:
      username: rewind
      password: ${rewind_password}
      sslmode: verify-full
      sslrootcert: ${state_dir}/pki/ca.crt
  parameters:
    unix_socket_directories: /run/postgresql

watchdog:
  mode: "off"

tags:
  clonefrom: true
  failover_priority: 1
EOF
}

render_pg_hba_entries() {
  local indent="$1"
  printf '%s- local all all peer\n' "$indent"
  local name address
  while read -r name address; do
    printf '%s- hostssl replication replicator %s/32 scram-sha-256\n' "$indent" "$address"
    printf '%s- hostssl all postgres %s/32 scram-sha-256\n' "$indent" "$address"
    printf '%s- hostssl all rewind %s/32 scram-sha-256\n' "$indent" "$address"
    printf '%s- hostssl all all %s/32 scram-sha-256\n' "$indent" "$address"
  done < <(member_rows)
  printf '%s- hostssl all all 127.0.0.1/32 scram-sha-256\n' "$indent"
  local cidr
  while read -r cidr; do
    printf '%s- hostssl heteronetwork heteronetwork %s scram-sha-256\n' "$indent" "$cidr"
  done < <(application_cidrs)
  local database user
  while read -r database user cidr; do
    printf '%s- hostssl %s %s %s scram-sha-256\n' \
      "$indent" "$database" "$user" "$cidr"
  done < <(extra_hba_rows)
}

render_haproxy_config() {
  cat <<EOF
global
    log stdout format raw local0
    maxconn 4096

defaults
    log global
    mode tcp
    option tcplog
    option dontlog-normal
    option redispatch
    retries 2
    timeout connect 1s
    timeout check 1s
    timeout client 5m
    timeout server 5m

frontend heteronetwork_postgres
    bind 127.0.0.1:${proxy_port}
    default_backend heteronetwork_postgres_primary

backend heteronetwork_postgres_primary
    option httpchk GET /primary
    http-check expect status 200
    default-server inter 2s fastinter 500ms downinter 1s fall 2 rise 2 on-marked-down shutdown-sessions
EOF
  local name address
  while read -r name address; do
    printf '    server %s %s:%s check port %s check-ssl verify required ca-file %s/pki/ca.crt verifyhost %s\n' \
      "$name" "$address" "$postgres_port" "$rest_port" "$state_dir" "$service_name"
  done < <(proxy_backend_rows)
  if [[ -n "$client_listen_address" ]]; then
    cat <<EOF

frontend heteronetwork_patroni_health
    bind ${client_listen_address}:${rest_port}
    default_backend heteronetwork_patroni_local

backend heteronetwork_patroni_local
    server local ${node_address}:${rest_port}
EOF
  fi
}

render_dcs_service() {
  cat <<EOF
[Unit]
Description=HeteroNetwork PostgreSQL HA consensus member
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
User=heteronetwork-dcs
Group=heteronetwork-db-ha
ExecStart=/opt/heteronetwork/postgres-ha/etcd --config-file ${state_dir}/etcd.yml
Restart=always
RestartSec=3s
TimeoutStartSec=0
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${dcs_data_dir}

[Install]
WantedBy=multi-user.target
EOF
}

render_patroni_service() {
  local dcs_dependencies=""
  if node_is_dcs_member; then
    dcs_dependencies="Wants=network-online.target heteronetwork-db-dcs.service
After=network-online.target heteronetwork-db-dcs.service"
  else
    dcs_dependencies="Wants=network-online.target
After=network-online.target"
  fi
  cat <<EOF
[Unit]
Description=HeteroNetwork synchronous PostgreSQL member
${dcs_dependencies}

[Service]
Type=simple
User=postgres
Group=postgres
Environment=MALLOC_ARENA_MAX=1
Environment=PG_MALLOC_ARENA_MAX=
ExecStart=/opt/heteronetwork/postgres-ha/patroni/bin/patroni ${state_dir}/patroni.yml
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
TimeoutStartSec=0
TimeoutStopSec=60
Restart=always
RestartSec=3s
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${data_dir} /run/postgresql

[Install]
WantedBy=multi-user.target
EOF
}

render_proxy_service() {
  cat <<EOF
[Unit]
Description=HeteroNetwork PostgreSQL primary proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
User=haproxy
Group=haproxy
RuntimeDirectory=heteronetwork-db-proxy
ExecStart=/usr/sbin/haproxy -Ws -f ${state_dir}/haproxy.cfg -p /run/heteronetwork-db-proxy/haproxy.pid
ExecReload=/usr/sbin/haproxy -Ws -f ${state_dir}/haproxy.cfg -p /run/heteronetwork-db-proxy/haproxy.pid -sf \$MAINPID
KillMode=mixed
Restart=always
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
}

ensure_service_hosts_entry() {
  local marker="# heteronetwork-postgres-ha"
  local temporary
  temporary="$(mktemp /etc/hosts.heteronetwork.XXXXXX)"
  awk -v marker="$marker" 'index($0, marker) == 0 { print }' /etc/hosts >"$temporary"
  printf '127.0.0.1 %s %s\n' "$service_name" "$marker" >>"$temporary"
  chmod --reference=/etc/hosts "$temporary"
  chown --reference=/etc/hosts "$temporary"
  mv "$temporary" /etc/hosts
}

validate_bundle_authority() {
  local output="$1"
  [[ -d "$output" && ! -L "$output" ]] || die "bundle directory is missing or unsafe: $output"
  ensure_private_source_file "$output/ca/ca.key"
  [[ -f "$output/ca/ca.crt" && ! -L "$output/ca/ca.crt" ]] \
    || die "bundle CA certificate is missing: $output/ca/ca.crt"
  openssl x509 -in "$output/ca/ca.crt" -noout >/dev/null
  local certificate_public_key private_public_key
  certificate_public_key="$(
    openssl x509 -in "$output/ca/ca.crt" -pubkey -noout \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print $1}'
  )"
  private_public_key="$(
    openssl pkey -in "$output/ca/ca.key" -pubout -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print $1}'
  )"
  [[ -n "$certificate_public_key" && "$certificate_public_key" == "$private_public_key" ]] \
    || die "bundle CA private key does not match its certificate"
}

validate_node_certificate() {
  local output="$1"
  local name="$2"
  local address="$3"
  local node_dir="$output/nodes/$name"
  ensure_private_source_file "$node_dir/node.key"
  [[ -f "$node_dir/node.crt" && ! -L "$node_dir/node.crt" ]] \
    || die "incomplete certificate bundle for $name"
  openssl verify -CAfile "$output/ca/ca.crt" "$node_dir/node.crt" >/dev/null
  openssl x509 -in "$node_dir/node.crt" -noout -ext subjectAltName \
    | grep -Fq "IP Address:${address}" \
    || die "existing certificate for $name does not contain $address"
  local certificate_public_key private_public_key
  certificate_public_key="$(
    openssl x509 -in "$node_dir/node.crt" -pubkey -noout \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print $1}'
  )"
  private_public_key="$(
    openssl pkey -in "$node_dir/node.key" -pubout -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print $1}'
  )"
  [[ -n "$certificate_public_key" && "$certificate_public_key" == "$private_public_key" ]] \
    || die "certificate and private key do not match for $name"
}

issue_node_certificate() {
  local output="$1"
  local name="$2"
  local address="$3"
  local node_dir="$output/nodes/$name"
  local extension_file="$node_dir/extensions.cnf"
  if [[ -e "$node_dir/node.key" || -e "$node_dir/node.crt" ]]; then
    validate_node_certificate "$output" "$name" "$address"
    return
  fi

  install -d -m 0700 "$node_dir"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$node_dir/node.key"
  openssl req -new -key "$node_dir/node.key" -out "$node_dir/node.csr" \
    -subj "/CN=${name}.${service_name}"
  cat >"$extension_file" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${service_name},DNS:${name}.${service_name},IP:${address},IP:127.0.0.1
EOF
  openssl x509 -req -in "$node_dir/node.csr" \
    -CA "$output/ca/ca.crt" -CAkey "$output/ca/ca.key" -CAcreateserial \
    -out "$node_dir/node.crt" -days 825 -sha256 -extfile "$extension_file"
  install -m 0644 "$output/ca/ca.crt" "$node_dir/ca.crt"
  rm -f "$node_dir/node.csr" "$extension_file"
  chmod 0600 "$node_dir/node.key"
  chmod 0644 "$node_dir/node.crt" "$node_dir/ca.crt"
}

write_bundle_manifest() {
  local output="$1"
  cat >"$output/manifest.env" <<EOF
HETERONETWORK_DB_CLUSTER_NAME=${cluster_name}
HETERONETWORK_DB_MEMBERS=${members}
HETERONETWORK_DB_DCS_MEMBERS=${dcs_members}
HETERONETWORK_DB_SERVICE_NAME=${service_name}
HETERONETWORK_DB_POSTGRES_PORT=${postgres_port}
HETERONETWORK_DB_REST_PORT=${rest_port}
HETERONETWORK_DB_TOPOLOGY_REVISION=${topology_revision}
EOF
  chmod 0600 "$output/manifest.env"
}

init_bundle() {
  local output="${1:-}"
  [[ -n "$output" ]] || die "init-bundle requires OUTPUT_DIR"
  [[ "$output" == /* ]] || die "OUTPUT_DIR must be absolute"
  validate_common_config
  require_command openssl
  require_command install
  [[ ! -e "$output" ]] || die "refusing to replace existing bundle path: $output"

  umask 077
  install -d -m 0700 "$output" "$output/ca" "$output/nodes" "$output/secrets"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$output/ca/ca.key"
  openssl req -new -x509 -key "$output/ca/ca.key" \
    -out "$output/ca/ca.crt" -days 3650 -sha256 \
    -subj "/CN=HeteroNetwork PostgreSQL HA CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

  local secret
  for secret in superuser replication rewind application rest-api; do
    openssl rand -hex 32 >"$output/secrets/${secret}.password"
    chmod 0600 "$output/secrets/${secret}.password"
  done

  local name address
  while read -r name address; do
    issue_node_certificate "$output" "$name" "$address"
  done < <(member_rows)

  write_bundle_manifest "$output"
  printf 'Created private HA bundle at %s.\n' "$output"
}

extend_bundle() {
  local output="${1:-}"
  [[ -n "$output" ]] || die "extend-bundle requires DIR"
  [[ "$output" == /* ]] || die "DIR must be absolute"
  validate_common_config
  require_command openssl
  require_command install
  validate_bundle_authority "$output"

  local original_bundle_dir="$bundle_dir"
  bundle_dir="$output"
  local secret
  for secret in superuser replication rewind application rest-api; do
    read_cluster_secret "$secret" >/dev/null
  done
  local name address
  while read -r name address; do
    issue_node_certificate "$output" "$name" "$address"
  done < <(member_rows)
  write_bundle_manifest "$output"
  bundle_dir="$original_bundle_dir"
  printf 'Extended private HA bundle at %s to topology revision %s.\n' \
    "$output" "$topology_revision"
}

validate_bundle() {
  local output="${1:-$bundle_dir}"
  [[ -n "$output" ]] || die "validate-bundle requires HETERONETWORK_DB_BUNDLE_DIR or DIR"
  [[ "$output" == /* ]] || die "bundle DIR must be absolute"
  validate_common_config
  require_command openssl
  validate_bundle_authority "$output"
  local original_bundle_dir="$bundle_dir"
  bundle_dir="$output"
  local secret
  for secret in superuser replication rewind application rest-api; do
    read_cluster_secret "$secret" >/dev/null
  done
  local name address
  while read -r name address; do
    validate_node_certificate "$output" "$name" "$address"
  done < <(member_rows)
  bundle_dir="$original_bundle_dir"
}

install_postgresql_packages() {
  export DEBIAN_FRONTEND=noninteractive
  local -a apt=(apt-get -o DPkg::Lock::Timeout=300)
  "${apt[@]}" update
  "${apt[@]}" install --yes --no-install-recommends ca-certificates curl gnupg haproxy python3-venv

  if ! apt-cache show "postgresql-${postgres_major}" >/dev/null 2>&1; then
    local codename VERSION_CODENAME
    # shellcheck disable=SC1091
    # shellcheck source=/etc/os-release
    . /etc/os-release
    codename="$VERSION_CODENAME"
    install -d -m 0755 /usr/share/postgresql-common/pgdg
    curl --fail --location --retry 3 --retry-all-errors \
      --connect-timeout 15 --max-time 300 \
      https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor --yes -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg
    printf 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg] https://apt.postgresql.org/pub/repos/apt %s-pgdg main\n' \
      "$codename" >/etc/apt/sources.list.d/pgdg.list
    "${apt[@]}" update
  fi

  local postgres_was_installed=0
  dpkg-query -W -f='${Status}' "postgresql-${postgres_major}" 2>/dev/null \
    | grep -Fq 'install ok installed' && postgres_was_installed=1
  "${apt[@]}" install --yes --no-install-recommends \
    "postgresql-${postgres_major}" "postgresql-client-${postgres_major}"
  if ((postgres_was_installed == 0)) && command -v pg_lsclusters >/dev/null 2>&1; then
    local version cluster
    while read -r version cluster _; do
      [[ "$version" == "$postgres_major" ]] || continue
      pg_ctlcluster "$version" "$cluster" stop || true
      systemctl disable "postgresql@${version}-${cluster}.service" >/dev/null 2>&1 || true
    done < <(pg_lsclusters --no-header)
  fi
}

install_etcd() {
  if [[ -x /opt/heteronetwork/postgres-ha/etcd ]] \
    && /opt/heteronetwork/postgres-ha/etcd --version 2>/dev/null \
      | grep -Fq "etcd Version: ${ETCD_VERSION#v}"; then
    return 0
  fi
  local architecture
  architecture="$(dpkg --print-architecture)"
  [[ "$architecture" == "amd64" ]] || die "pinned etcd artifact supports amd64 only"
  local work_dir archive
  work_dir="$(mktemp -d /tmp/heteronetwork-etcd.XXXXXX)"
  archive="$work_dir/etcd.tar.gz"
  trap '[[ -z "${work_dir:-}" || "$work_dir" != /tmp/heteronetwork-etcd.* ]] || rm -rf "$work_dir"' RETURN
  curl --fail --location --retry 3 --retry-all-errors \
    --connect-timeout 15 --max-time 300 \
    --output "$archive" \
    "https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-amd64.tar.gz"
  printf '%s  %s\n' "$ETCD_LINUX_AMD64_SHA256" "$archive" | sha256sum --check
  tar --extract --gzip --file "$archive" --directory "$work_dir"
  install -m 0755 "$work_dir/etcd-${ETCD_VERSION}-linux-amd64/etcd" \
    /opt/heteronetwork/postgres-ha/etcd
  install -m 0755 "$work_dir/etcd-${ETCD_VERSION}-linux-amd64/etcdctl" \
    /opt/heteronetwork/postgres-ha/etcdctl
  rm -rf "$work_dir"
  trap - RETURN
}

install_patroni() {
  if [[ -x /opt/heteronetwork/postgres-ha/patroni/bin/patroni ]] \
    && [[ "$(/opt/heteronetwork/postgres-ha/patroni/bin/patroni --version 2>/dev/null)" == *"${PATRONI_VERSION}"* ]]; then
    return 0
  fi
  python3 -m venv /opt/heteronetwork/postgres-ha/patroni
  /opt/heteronetwork/postgres-ha/patroni/bin/pip install \
    --disable-pip-version-check \
    "patroni[etcd3,psycopg3]==${PATRONI_VERSION}"
}

install_pki_and_secrets() {
  validate_client_ca_parent
  local node_bundle="${bundle_dir}/nodes/${node_name}"
  ensure_private_source_file "$node_bundle/node.key"
  [[ -f "$node_bundle/node.crt" && ! -L "$node_bundle/node.crt" ]] \
    || die "node certificate is missing: $node_bundle/node.crt"
  [[ -f "$node_bundle/ca.crt" && ! -L "$node_bundle/ca.crt" ]] \
    || die "CA certificate is missing: $node_bundle/ca.crt"
  openssl verify -CAfile "$node_bundle/ca.crt" "$node_bundle/node.crt" >/dev/null

  install -o root -g heteronetwork-db-ha -m 0644 "$node_bundle/ca.crt" "$state_dir/pki/ca.crt"
  install -o root -g root -m 0644 "$node_bundle/ca.crt" "$client_ca_path"
  install -o root -g heteronetwork-db-ha -m 0644 "$node_bundle/node.crt" "$state_dir/pki/node.crt"
  install -o root -g heteronetwork-db-ha -m 0640 "$node_bundle/node.key" "$state_dir/pki/node.key"

  local secret
  for secret in superuser replication rewind application rest-api; do
    read_cluster_secret "$secret" >/dev/null
    install -o root -g postgres -m 0640 \
      "$bundle_dir/secrets/${secret}.password" "$state_dir/secrets/${secret}.password"
  done
}

install_bootstrap_script() {
  install -o root -g postgres -m 0750 /dev/stdin /opt/heteronetwork/postgres-ha/bootstrap-database <<EOF
#!/bin/sh
set -eu
application_password="\$(tr -d '\\r\\n' <${state_dir}/secrets/application.password)"
{
  printf "\\\\set application_password '%s'\\n" "\$application_password"
  cat <<'SQL'
SELECT format('CREATE ROLE heteronetwork LOGIN PASSWORD %L', :'application_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'heteronetwork') \gexec
SELECT 'CREATE DATABASE heteronetwork OWNER heteronetwork'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'heteronetwork') \gexec
SQL
} | exec /usr/bin/psql "\$1" --set=ON_ERROR_STOP=1
EOF
}

verify_interface_address() {
  require_command ip
  ip link show dev "$interface" >/dev/null 2>&1 \
    || die "private replication interface does not exist: $interface"
  ip -o -4 address show dev "$interface" \
    | awk '{print $4}' \
    | cut -d/ -f1 \
    | grep -Fxq "$node_address" \
    || die "$node_address is not assigned to $interface"
  if [[ -n "$client_listen_address" ]]; then
    ip -o -4 address show \
      | awk '{print $4}' \
      | cut -d/ -f1 \
      | grep -Fxq "$client_listen_address" \
      || die "$client_listen_address is not assigned to this node"
  fi
}

install_node() {
  require_root
  validate_node_config
  verify_interface_address
  require_command apt-get
  require_command openssl

  getent group heteronetwork-db-ha >/dev/null \
    || groupadd --system heteronetwork-db-ha
  if node_is_dcs_member; then
    id -u heteronetwork-dcs >/dev/null 2>&1 \
      || useradd --system --home "$dcs_data_dir" --shell /usr/sbin/nologin \
        --gid heteronetwork-db-ha heteronetwork-dcs
    usermod --home "$dcs_data_dir" heteronetwork-dcs
  fi

  install_postgresql_packages
  usermod --append --groups heteronetwork-db-ha postgres
  usermod --append --groups heteronetwork-db-ha haproxy
  install -d -o root -g root -m 0755 /opt/heteronetwork/postgres-ha
  install -d -o root -g heteronetwork-db-ha -m 0750 "$state_dir" "$state_dir/pki"
  install -d -o root -g postgres -m 0750 "$state_dir/secrets"
  install -d -o postgres -g postgres -m 0700 "$data_dir" "$data_dir/postgres"
  if node_is_dcs_member; then
    install -d -o heteronetwork-dcs -g heteronetwork-db-ha -m 0700 "$dcs_data_dir"
  fi
  install -d -o postgres -g postgres -m 0755 /run/postgresql

  if node_is_dcs_member; then
    install_etcd
  fi
  install_patroni
  install_pki_and_secrets
  install_bootstrap_script

  if node_is_dcs_member; then
    render_etcd_config \
      | install -o root -g heteronetwork-db-ha -m 0640 /dev/stdin "$state_dir/etcd.yml"
  fi
  render_patroni_config | install -o root -g postgres -m 0640 /dev/stdin "$state_dir/patroni.yml"
  render_haproxy_config | install -o root -g haproxy -m 0640 /dev/stdin "$state_dir/haproxy.cfg"
  if node_is_dcs_member; then
    render_dcs_service \
      | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db-dcs.service
  fi
  render_patroni_service | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db.service
  render_proxy_service | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db-proxy.service

  ensure_service_hosts_entry
  /usr/sbin/haproxy -c -f "$state_dir/haproxy.cfg"
  systemctl daemon-reload
  if node_is_dcs_member; then
    systemctl enable --now heteronetwork-db-dcs.service
  fi
  systemctl enable --now heteronetwork-db.service
  systemctl enable --now heteronetwork-db-proxy.service
}

install_proxy() {
  require_root
  validate_proxy_config
  require_command apt-get
  export DEBIAN_FRONTEND=noninteractive
  local -a apt=(apt-get -o DPkg::Lock::Timeout=300)
  "${apt[@]}" update
  "${apt[@]}" install --yes --no-install-recommends ca-certificates haproxy
  validate_client_ca_parent
  install -d -o root -g haproxy -m 0755 "$state_dir" "$state_dir/pki"
  install -o root -g haproxy -m 0644 "$bundle_dir/ca/ca.crt" "$state_dir/pki/ca.crt"
  install -o root -g root -m 0644 "$bundle_dir/ca/ca.crt" "$client_ca_path"
  render_haproxy_config | install -o root -g haproxy -m 0640 /dev/stdin "$state_dir/haproxy.cfg"
  render_proxy_service | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db-proxy.service
  ensure_service_hosts_entry
  /usr/sbin/haproxy -c -f "$state_dir/haproxy.cfg"
  systemctl daemon-reload
  systemctl enable --now heteronetwork-db-proxy.service
}

reconfigure_node() {
  require_root
  validate_node_config
  verify_interface_address
  require_command openssl
  require_command systemctl
  if [[ ! -f /etc/systemd/system/heteronetwork-db.service ]]; then
    install_node
    return
  fi
  [[ -x /opt/heteronetwork/postgres-ha/patroni/bin/patroni ]] \
    || die "Patroni is not installed on this database member"
  [[ -x /usr/sbin/haproxy ]] || die "HAProxy is not installed on this database member"

  getent group heteronetwork-db-ha >/dev/null \
    || groupadd --system heteronetwork-db-ha
  usermod --append --groups heteronetwork-db-ha postgres
  usermod --append --groups heteronetwork-db-ha haproxy
  install -d -o root -g heteronetwork-db-ha -m 0750 "$state_dir" "$state_dir/pki"
  install -d -o root -g postgres -m 0750 "$state_dir/secrets"
  install_pki_and_secrets
  install_bootstrap_script

  if node_is_dcs_member; then
    id -u heteronetwork-dcs >/dev/null 2>&1 \
      || useradd --system --home "$dcs_data_dir" --shell /usr/sbin/nologin \
        --gid heteronetwork-db-ha heteronetwork-dcs
    usermod --home "$dcs_data_dir" heteronetwork-dcs
    install -d -o heteronetwork-dcs -g heteronetwork-db-ha -m 0700 "$dcs_data_dir"
    install_etcd
    render_etcd_config \
      | install -o root -g heteronetwork-db-ha -m 0640 /dev/stdin "$state_dir/etcd.yml"
    render_dcs_service \
      | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db-dcs.service
  elif [[ -f /etc/systemd/system/heteronetwork-db-dcs.service ]]; then
    die "automatic DCS voter removal is intentionally refused"
  fi

  render_patroni_config | install -o root -g postgres -m 0640 /dev/stdin "$state_dir/patroni.yml"
  render_haproxy_config | install -o root -g haproxy -m 0640 /dev/stdin "$state_dir/haproxy.cfg"
  render_patroni_service \
    | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db.service
  render_proxy_service \
    | install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/heteronetwork-db-proxy.service
  ensure_service_hosts_entry
  /usr/sbin/haproxy -c -f "$state_dir/haproxy.cfg"
  systemctl daemon-reload
  if node_is_dcs_member; then
    systemctl enable --now heteronetwork-db-dcs.service
  fi
  systemctl reload-or-restart heteronetwork-db.service
  systemctl reload-or-restart heteronetwork-db-proxy.service
}

etcd_endpoints() {
  local output="" name address
  while read -r name address; do
    [[ -z "$output" ]] || output+=","
    output+="https://${address}:${dcs_client_port}"
  done < <(dcs_member_rows)
  printf '%s' "$output"
}

dcs_etcdctl() {
  /opt/heteronetwork/postgres-ha/etcdctl \
    --endpoints="$(etcd_endpoints)" \
    --dial-timeout=3s \
    --command-timeout=10s \
    --cacert="$bundle_dir/ca/ca.crt" \
    --cert="$bundle_dir/nodes/$node_name/node.crt" \
    --key="$bundle_dir/nodes/$node_name/node.key" \
    "$@"
}

dcs_member_snapshot() {
  dcs_etcdctl member list --write-out=json \
    | python3 -c '
import json
import sys

document = json.load(sys.stdin)
for member in document.get("members", []):
    member_id = member.get("ID")
    if not isinstance(member_id, int):
        raise SystemExit("invalid etcd member ID")
    name = member.get("name", "")
    urls = member.get("peerURLs", [])
    learner = member.get("isLearner", False)
    if not isinstance(name, str) or not isinstance(urls, list) or len(urls) != 1:
        raise SystemExit("invalid etcd member record")
    print(f"{member_id:x}\t{name}\t{urls[0]}\t{str(bool(learner)).lower()}")
'
}

reconcile_dcs() {
  require_root
  validate_node_config
  require_command python3
  [[ -x /opt/heteronetwork/postgres-ha/etcdctl ]] || die "etcdctl is not installed"
  validate_bundle_authority "$bundle_dir"

  local snapshot
  snapshot="$(dcs_member_snapshot)"
  [[ -n "$snapshot" ]] || die "DCS membership is empty"
  local id actual_name peer_url learner
  local desired_name desired_address desired_url found
  while IFS=$'\t' read -r id actual_name peer_url learner; do
    found=0
    while read -r desired_name desired_address; do
      desired_url="https://${desired_address}:${dcs_peer_port}"
      if [[ "$peer_url" == "$desired_url" ]]; then
        [[ -z "$actual_name" || "$actual_name" == "$desired_name" ]] \
          || die "DCS peer $peer_url is registered as unexpected name $actual_name"
        found=1
      fi
    done < <(dcs_member_rows)
    ((found == 1)) || die "DCS contains an unmanaged peer URL: $peer_url"
  done <<<"$snapshot"

  while IFS=$'\t' read -r id actual_name peer_url learner; do
    [[ "$learner" == "true" ]] || continue
    if dcs_etcdctl member promote "$id" >/dev/null 2>&1; then
      printf 'Promoted DCS learner %s.\n' "${actual_name:-$peer_url}"
    else
      printf 'DCS learner %s is not caught up yet.\n' "${actual_name:-$peer_url}"
    fi
    return
  done <<<"$snapshot"

  local added=0
  while read -r desired_name desired_address; do
    desired_url="https://${desired_address}:${dcs_peer_port}"
    found=0
    while IFS=$'\t' read -r id actual_name peer_url learner; do
      if [[ "$peer_url" == "$desired_url" ]]; then
        found=1
        break
      fi
    done <<<"$snapshot"
    if ((found == 0 && added == 0)); then
      dcs_etcdctl member add "$desired_name" \
        --peer-urls="$desired_url" \
        --learner >/dev/null
      printf 'Added DCS learner %s at %s.\n' "$desired_name" "$desired_address"
      added=1
    fi
  done < <(dcs_member_rows)
  ((added == 0)) || return
  printf 'DCS membership already matches the requested topology.\n'
}

reconcile_patroni_config() {
  require_root
  validate_node_config
  local synchronous_count
  synchronous_count="$(synchronous_standby_count)"
  [[ -x /opt/heteronetwork/postgres-ha/patroni/bin/patronictl ]] \
    || die "patronictl is not installed"
  env PAGER=cat /opt/heteronetwork/postgres-ha/patroni/bin/patronictl \
    -c "$state_dir/patroni.yml" \
    edit-config "$cluster_name" \
    --set "synchronous_node_count=${synchronous_count}" \
    --force >/dev/null
  printf 'Patroni requires %s synchronous standbys for this topology.\n' \
    "$synchronous_count"
}

status_cluster() {
  validate_node_config
  require_command curl
  require_command python3
  printf 'DCS\n'
  /opt/heteronetwork/postgres-ha/etcdctl \
    --endpoints="$(etcd_endpoints)" \
    --cacert="$state_dir/pki/ca.crt" \
    --cert="$state_dir/pki/node.crt" \
    --key="$state_dir/pki/node.key" \
    endpoint status --cluster --write-out=table
  printf 'POSTGRESQL\n'
  /opt/heteronetwork/postgres-ha/patroni/bin/patronictl \
    -c "$state_dir/patroni.yml" list
}

verify_cluster() {
  validate_node_config
  local expected_members expected_replicas expected_sync expected_dcs
  expected_members="$(database_member_count)"
  expected_replicas="$((10#$expected_members - 1))"
  expected_sync="$(synchronous_standby_count)"
  expected_dcs="$(dcs_member_count)"
  ((10#$expected_dcs % 2 == 1)) || die "steady-state DCS member count must be odd"
  local healthy=0 primaries=0 name address status
  while read -r name address; do
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
      --cacert "$state_dir/pki/ca.crt" \
      --connect-to "${service_name}:${rest_port}:${address}:${rest_port}" \
      "https://${service_name}:${rest_port}/health")"
    [[ "$status" == "200" ]] || die "Patroni health failed for $name: HTTP $status"
    healthy=$((healthy + 1))
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
      --cacert "$state_dir/pki/ca.crt" \
      --connect-to "${service_name}:${rest_port}:${address}:${rest_port}" \
      "https://${service_name}:${rest_port}/primary")"
    [[ "$status" == "200" ]] && primaries=$((primaries + 1))
  done < <(member_rows)
  ((healthy == 10#$expected_members)) \
    || die "expected $expected_members healthy PostgreSQL members"
  ((primaries == 1)) || die "expected exactly one PostgreSQL primary, found $primaries"

  local superuser_password
  superuser_password="$(read_cluster_secret superuser)"
  local replication streaming_count sync_count
  replication="$(PGPASSWORD="$superuser_password" \
    /usr/lib/postgresql/"$postgres_major"/bin/psql \
      "host=${service_name} hostaddr=127.0.0.1 port=${proxy_port} dbname=postgres user=postgres sslmode=verify-full sslrootcert=${state_dir}/pki/ca.crt connect_timeout=3" \
      --no-psqlrc --tuples-only --no-align \
      --command="SELECT count(*) FILTER (WHERE state = 'streaming'), count(*) FILTER (WHERE sync_state IN ('sync', 'quorum')) FROM pg_stat_replication")"
  IFS='|' read -r streaming_count sync_count <<<"$replication"
  [[ "$streaming_count" =~ ^[0-9]+$ && "$sync_count" =~ ^[0-9]+$ ]] \
    || die "invalid PostgreSQL replication status: $replication"
  ((10#$streaming_count == 10#$expected_replicas)) \
    || die "expected $expected_replicas streaming replicas, got: $replication"
  ((10#$sync_count >= 10#$expected_sync)) \
    || die "expected at least $expected_sync synchronous replicas, got: $replication"

  local dcs_health
  dcs_health="$(/opt/heteronetwork/postgres-ha/etcdctl \
    --endpoints="$(etcd_endpoints)" \
    --cacert="$state_dir/pki/ca.crt" \
    --cert="$state_dir/pki/node.crt" \
    --key="$state_dir/pki/node.key" \
    endpoint health --cluster 2>&1)"
  [[ "$(grep -c 'is healthy' <<<"$dcs_health")" == "$expected_dcs" ]] \
    || die "expected $expected_dcs healthy DCS members"
  printf 'HA verification passed: %s DCS members, 1 primary, %s streaming replicas, %s synchronous replicas required.\n' \
    "$expected_dcs" "$expected_replicas" "$expected_sync"
}

self_test() {
  local original_members="$members"
  local original_dcs_members="$dcs_members"
  local original_dcs_initial_cluster_state="$dcs_initial_cluster_state"
  local original_topology_revision="$topology_revision"
  local original_proxy_backends="$proxy_backends"
  local original_node_name="$node_name"
  local original_node_address="$node_address"
  local original_client_listen_address="$client_listen_address"
  local original_extra_hba_entries="$extra_hba_entries"
  local original_bundle_dir="$bundle_dir"
  local test_dir
  test_dir="$(mktemp -d /tmp/heteronetwork-postgres-ha-test.XXXXXX)"
  trap '[[ -z "${test_dir:-}" || "$test_dir" != /tmp/heteronetwork-postgres-ha-test.* ]] || rm -rf "$test_dir"' RETURN

  members="db-a=10.250.0.1,db-b=10.250.0.2,db-c=10.250.0.3,db-d=10.250.0.4,db-e=10.250.0.5,db-f=10.250.0.6"
  dcs_members="db-a=10.250.0.1,db-b=10.250.0.2,db-c=10.250.0.3,db-d=10.250.0.4,db-e=10.250.0.5"
  dcs_initial_cluster_state="new"
  topology_revision="7"
  proxy_backends="$members"
  node_name="db-a"
  node_address="10.250.0.1"
  client_listen_address="100.64.0.1"
  extra_hba_entries="keycloak:keycloak:10.250.0.4/32,keycloak:keycloak:10.250.0.5/32"
  bundle_dir="$test_dir/bundle"
  install -d -m 0700 "$bundle_dir/secrets"
  local secret
  for secret in superuser replication rewind application rest-api; do
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n' \
      >"$bundle_dir/secrets/${secret}.password"
    chmod 0600 "$bundle_dir/secrets/${secret}.password"
  done

  validate_node_config
  render_etcd_config >"$test_dir/etcd.yml"
  render_patroni_config >"$test_dir/patroni.yml"
  render_haproxy_config >"$test_dir/haproxy.cfg"
  grep -Fq 'synchronous_mode_strict: true' "$test_dir/patroni.yml"
  grep -Fq 'synchronous_node_count: 2' "$test_dir/patroni.yml"
  grep -Fq 'max_wal_senders: 36' "$test_dir/patroni.yml"
  grep -Fq 'max_replication_slots: 36' "$test_dir/patroni.yml"
  grep -Fq 'listen: 10.250.0.1,100.64.0.1:55432' "$test_dir/patroni.yml"
  [[ "$(grep -c 'hostssl keycloak keycloak 10.250.0.[45]/32 scram-sha-256' \
    "$test_dir/patroni.yml")" == "4" ]]
  grep -Fq '10.250.0.5:12380' "$test_dir/etcd.yml"
  if grep -Fq '10.250.0.6:12380' "$test_dir/etcd.yml"; then
    die "non-voter unexpectedly appeared in the DCS configuration"
  fi
  grep -Fq 'bind 100.64.0.1:18008' "$test_dir/haproxy.cfg"
  [[ "$(grep -c '^    server db-' "$test_dir/haproxy.cfg")" == "6" ]]
  init_bundle "$test_dir/generated-bundle" >/dev/null 2>&1
  openssl x509 -in "$test_dir/generated-bundle/ca/ca.crt" -noout -text \
    | grep -F 'Certificate Sign, CRL Sign' >/dev/null
  openssl x509 -in "$test_dir/generated-bundle/nodes/db-a/node.crt" -noout -text \
    | grep -F 'Signature Algorithm: ecdsa-with-SHA256' >/dev/null
  openssl verify \
    -CAfile "$test_dir/generated-bundle/ca/ca.crt" \
    "$test_dir/generated-bundle/nodes/db-a/node.crt" \
    "$test_dir/generated-bundle/nodes/db-f/node.crt" >/dev/null
  grep -Fq 'HETERONETWORK_DB_TOPOLOGY_REVISION=7' \
    "$test_dir/generated-bundle/manifest.env"
  members="${members},db-g=10.250.0.7"
  proxy_backends="$members"
  topology_revision="8"
  extend_bundle "$test_dir/generated-bundle" >/dev/null 2>&1
  openssl verify \
    -CAfile "$test_dir/generated-bundle/ca/ca.crt" \
    "$test_dir/generated-bundle/nodes/db-g/node.crt" >/dev/null
  grep -Fq 'HETERONETWORK_DB_TOPOLOGY_REVISION=8' \
    "$test_dir/generated-bundle/manifest.env"
  members="${members%,db-g=10.250.0.7}"
  proxy_backends="$members"
  topology_revision="7"
  if (
    members="db-a=10.250.0.1,db-a=10.250.0.2,db-c=10.250.0.3"
    member_rows >/dev/null 2>&1
  ); then
    die "duplicate member self-test unexpectedly succeeded"
  fi
  if (
    dcs_members="db-a=10.250.0.1,db-b=10.250.0.2,db-c=10.250.0.3,db-d=10.250.0.4"
    dcs_initial_cluster_state="new"
    validate_common_config >/dev/null 2>&1
  ); then
    die "even DCS member count self-test unexpectedly succeeded"
  fi
  if (
    dcs_members="db-a=10.250.0.1,db-b=10.250.0.2,db-z=10.250.0.99"
    validate_common_config >/dev/null 2>&1
  ); then
    die "DCS member outside the database set self-test unexpectedly succeeded"
  fi
  node_name="db-f"
  node_address="10.250.0.6"
  render_patroni_service >"$test_dir/non-voter.service"
  if grep -Fq 'heteronetwork-db-dcs.service' "$test_dir/non-voter.service"; then
    die "non-voter Patroni service unexpectedly depends on the local DCS service"
  fi

  members="$original_members"
  dcs_members="$original_dcs_members"
  dcs_initial_cluster_state="$original_dcs_initial_cluster_state"
  topology_revision="$original_topology_revision"
  proxy_backends="$original_proxy_backends"
  node_name="$original_node_name"
  node_address="$original_node_address"
  client_listen_address="$original_client_listen_address"
  extra_hba_entries="$original_extra_hba_entries"
  bundle_dir="$original_bundle_dir"
  rm -rf "$test_dir"
  trap - RETURN
  printf 'postgres HA renderer self-test passed\n'
}

case "${1:-}" in
  init-bundle)
    shift
    init_bundle "${1:-}"
    ;;
  extend-bundle)
    shift
    extend_bundle "${1:-}"
    ;;
  validate-bundle)
    shift
    validate_bundle "${1:-}"
    ;;
  install-node)
    install_node
    ;;
  reconfigure-node)
    reconfigure_node
    ;;
  reconcile-dcs)
    reconcile_dcs
    ;;
  reconcile-patroni)
    reconcile_patroni_config
    ;;
  install-proxy)
    install_proxy
    ;;
  verify)
    verify_cluster
    ;;
  status)
    status_cluster
    ;;
  self-test)
    self_test
    ;;
  help | --help | -h)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
