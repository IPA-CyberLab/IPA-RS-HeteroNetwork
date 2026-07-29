#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly KEYCLOAK_VERSION="26.6.4"
readonly KEYCLOAK_ARCHIVE_SHA256="386b566bbea05527226e275c43e5cf6f218896ad2441ac4be5c39f1226772e8f"
readonly DEFAULT_KEYCLOAK_ARCHIVE_URL="https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz"
readonly DEFAULT_HTTP_PORT="18080"
readonly DEFAULT_MANAGEMENT_PORT="19000"
readonly DEFAULT_BACKCHANNEL_PORT="18080"
readonly DEFAULT_EDGE_PORT="18079"
readonly DEFAULT_DB_URL="jdbc:postgresql://postgres.heteronetwork.internal:25432/keycloak?sslmode=verify-full&sslrootcert=/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt"
readonly MAX_SECRET_BYTES="4096"
readonly MAX_ARCHIVE_BYTES="1073741824"
readonly ACTIVATION_READY_ATTEMPTS="3"
readonly ACTIVATION_READY_INTERVAL_SECONDS="3"
readonly ACTIVATION_READY_REQUEST_TIMEOUT_SECONDS="2"

archive="${HETERONETWORK_KEYCLOAK_ARCHIVE:-}"
archive_url="${HETERONETWORK_KEYCLOAK_ARCHIVE_URL:-$DEFAULT_KEYCLOAK_ARCHIVE_URL}"
cluster_bind_address="${HETERONETWORK_KEYCLOAK_CLUSTER_BIND_ADDRESS:-}"
db_url="${HETERONETWORK_KEYCLOAK_DB_URL:-$DEFAULT_DB_URL}"
db_password_file="${HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE:-}"
bootstrap_admin_password_file="${HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE:-}"
import_dir="${HETERONETWORK_KEYCLOAK_IMPORT_DIR:-}"
http_port="${HETERONETWORK_KEYCLOAK_HTTP_PORT:-$DEFAULT_HTTP_PORT}"
management_port="${HETERONETWORK_KEYCLOAK_MANAGEMENT_PORT:-$DEFAULT_MANAGEMENT_PORT}"
backchannel_port="${HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT:-$DEFAULT_BACKCHANNEL_PORT}"
backchannel_listen_addresses="${HETERONETWORK_KEYCLOAK_BACKCHANNEL_LISTEN_ADDRESSES:-$cluster_bind_address}"
edge_upstreams="${HETERONETWORK_KEYCLOAK_EDGE_UPSTREAMS:-}"
edge_listen_port="${HETERONETWORK_KEYCLOAK_EDGE_LISTEN_PORT:-$DEFAULT_EDGE_PORT}"
edge_health_path="${HETERONETWORK_KEYCLOAK_EDGE_HEALTH_PATH:-/realms/kakurizai/.well-known/openid-configuration}"

readonly install_dir="/opt/heteronetwork/keycloak-${KEYCLOAK_VERSION}"
readonly current_link="/opt/heteronetwork/keycloak"
readonly prepared_marker="${install_dir}/.heteronetwork-prepared"
readonly keycloak_config_dir="/etc/heteronetwork/keycloak"
readonly keycloak_data_dir="/var/lib/heteronetwork-keycloak"
readonly backchannel_config_dir="/etc/heteronetwork/keycloak-backchannel"
readonly edge_config_dir="/etc/heteronetwork/keycloak-edge-proxy"

usage() {
  cat <<'EOF'
Usage: keycloak-ha-node.sh COMMAND

Commands:
  prepare-edge          Install only the lightweight edge-proxy dependencies
  prepare               Install the pinned Keycloak release and dormant units
  prepared              Exit successfully when the pinned release is prepared
  configure              Install validated secrets and node-specific configuration
  activate               Start the configured replica and private backchannel
  deactivate             Stop the replica and private backchannel
  configure-edge-proxy   Configure/start the loopback proxy for selected replicas
  deactivate-edge-proxy  Stop the loopback proxy

Required environment for configure:
  HETERONETWORK_KEYCLOAK_CLUSTER_BIND_ADDRESS
  HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE
  HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE

Optional environment:
  HETERONETWORK_KEYCLOAK_ARCHIVE
  HETERONETWORK_KEYCLOAK_ARCHIVE_URL
  HETERONETWORK_KEYCLOAK_IMPORT_DIR
  HETERONETWORK_KEYCLOAK_DB_URL
  HETERONETWORK_KEYCLOAK_HTTP_PORT
  HETERONETWORK_KEYCLOAK_MANAGEMENT_PORT
  HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT
  HETERONETWORK_KEYCLOAK_BACKCHANNEL_LISTEN_ADDRESSES
  HETERONETWORK_KEYCLOAK_EDGE_UPSTREAMS
  HETERONETWORK_KEYCLOAK_EDGE_LISTEN_PORT
  HETERONETWORK_KEYCLOAK_EDGE_HEALTH_PATH

prepare always verifies Keycloak 26.6.4 against the compiled-in SHA-256.
Supplying a local archive changes only the source, never the accepted digest.
EOF
}

die() {
  printf 'keycloak-ha-node: error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

validate_port() {
  local value="$1" name="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a TCP port"
  ((10#$value >= 1024 && 10#$value <= 65535)) \
    || die "$name is outside 1024-65535"
}

validate_ipv4() {
  local value="$1" a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" \
    && -n "${c:-}" && -n "${d:-}" ]] \
    || die "invalid IPv4 address"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || die "invalid IPv4 address"
    ((10#$octet <= 255)) || die "invalid IPv4 address"
  done
}

validate_private_ipv4() {
  local value="$1" a b c d
  validate_ipv4 "$value"
  IFS=. read -r a b c d <<<"$value"
  if ((10#$a == 10)) \
    || ((10#$a == 172 && 10#$b >= 16 && 10#$b <= 31)) \
    || ((10#$a == 192 && 10#$b == 168)) \
    || ((10#$a == 100 && 10#$b >= 64 && 10#$b <= 127)); then
    return
  fi
  die "address must be private IPv4 or CGNAT"
}

validate_backchannel_listen_addresses() {
  local address
  local -A seen=()
  local -a addresses=()
  IFS=, read -r -a addresses <<<"$backchannel_listen_addresses"
  ((${#addresses[@]} > 0)) || die "backchannel listen addresses must not be empty"
  for address in "${addresses[@]}"; do
    [[ -n "$address" && "$address" != *[[:space:]]* ]] \
      || die "backchannel listen addresses must be comma-separated IPv4 addresses"
    validate_private_ipv4 "$address"
    [[ -z "${seen[$address]:-}" ]] || die "duplicate backchannel listen address"
    seen["$address"]=1
  done
}

validate_edge_upstreams() {
  local endpoint address port
  local -A seen=()
  local -a endpoints=()
  IFS=, read -r -a endpoints <<<"$edge_upstreams"
  ((${#endpoints[@]} >= 1 && ${#endpoints[@]} <= 3)) \
    || die "edge proxy requires one to three private upstreams"
  for endpoint in "${endpoints[@]}"; do
    [[ -n "$endpoint" && "$endpoint" != *[[:space:]]* && "$endpoint" == *:* ]] \
      || die "edge upstreams must be comma-separated IPv4:port values"
    address="${endpoint%:*}"
    port="${endpoint##*:}"
    validate_private_ipv4 "$address"
    validate_port "$port" "edge upstream port"
    [[ -z "${seen[$endpoint]:-}" ]] || die "duplicate edge upstream"
    seen["$endpoint"]=1
  done
}

validate_edge_health_path() {
  [[ "$edge_health_path" == /realms/*/.well-known/openid-configuration \
    && ${#edge_health_path} -le 1024 \
    && "$edge_health_path" != *\?* \
    && "$edge_health_path" != *\#* \
    && "$edge_health_path" != *[[:space:]]* ]] \
    || die "edge health path must be a bounded Keycloak realm discovery path"
  [[ ! "$edge_health_path" =~ [[:cntrl:]] ]] \
    || die "edge health path must not contain control characters"
}

validate_archive_url() {
  [[ -n "$archive_url" \
    && ${#archive_url} -le 2048 \
    && "$archive_url" =~ ^https://[][A-Za-z0-9._~:/?#%+@,\&=-]+$ \
    && "$archive_url" != *[[:space:]]* ]] \
    || die "Keycloak archive URL must be a bounded HTTPS URL"
}

validate_archive_file() {
  local path="$1"
  [[ "$path" == /* ]] || die "Keycloak archive path must be absolute"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "Keycloak archive must be a non-symlink regular file"
  local size
  size="$(stat -c '%s' -- "$path")" \
    || die "unable to inspect Keycloak archive"
  ((10#$size > 0 && 10#$size <= MAX_ARCHIVE_BYTES)) \
    || die "Keycloak archive size is invalid"
}

validate_secret_file() {
  local path="$1" name="$2"
  [[ "$path" == /* ]] || die "$name must be an absolute path"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "$name must be a non-symlink regular file"

  local uid links mode size
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$path") \
    || die "unable to inspect $name"
  [[ "$uid" == "0" ]] || die "$name must be owned by root"
  [[ "$links" == "1" ]] || die "$name must have exactly one hard link"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "$name has an invalid mode"
  (( (8#$mode & 0400) != 0 )) || die "$name must be owner-readable"
  (( (8#$mode & 0077) == 0 )) \
    || die "$name must not grant group or world permissions"
  ((10#$size > 0 && 10#$size <= MAX_SECRET_BYTES)) \
    || die "$name size must be between 1 and $MAX_SECRET_BYTES bytes"
}

prepared_release_is_valid() {
  [[ -x "$install_dir/bin/kc.sh" \
    && -f "$prepared_marker" \
    && ! -L "$prepared_marker" ]] || return 1
  grep -Fqx "version=$KEYCLOAK_VERSION" "$prepared_marker" \
    && grep -Fqx "sha256=$KEYCLOAK_ARCHIVE_SHA256" "$prepared_marker"
}

install_debian_packages() {
  command -v apt-get >/dev/null 2>&1 \
    || die "automatic Keycloak preparation currently requires apt-get"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update
  apt-get -o DPkg::Lock::Timeout=300 install --yes --no-install-recommends \
    "$@"
}

install_edge_dependencies() {
  if command -v haproxy >/dev/null 2>&1 \
    && command -v curl >/dev/null 2>&1; then
    return
  fi
  install_debian_packages ca-certificates curl haproxy
}

install_replica_dependencies() {
  if command -v java >/dev/null 2>&1 \
    && command -v haproxy >/dev/null 2>&1 \
    && command -v curl >/dev/null 2>&1; then
    return
  fi
  install_debian_packages \
    ca-certificates curl haproxy openjdk-21-jre-headless
}

ensure_service_account() {
  if ! getent group keycloak >/dev/null; then
    groupadd --system keycloak
  fi
  if ! id keycloak >/dev/null 2>&1; then
    useradd --system --gid keycloak --home-dir "$keycloak_data_dir" \
      --shell /usr/sbin/nologin keycloak
  fi
}

render_keycloak_start() {
  cat <<'EOF'
#!/bin/sh
set -eu
export KC_DB_PASSWORD
KC_DB_PASSWORD="$(cat /etc/heteronetwork/keycloak/db.password)"
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /etc/heteronetwork/keycloak/bootstrap-admin.password)"
exec /opt/heteronetwork/keycloak/bin/kc.sh start --optimized
EOF
}

render_keycloak_service() {
  cat <<'EOF'
[Unit]
Description=HeteroNetwork Keycloak HA replica
Wants=network-online.target heteronetwork-agent.service
After=network-online.target heteronetwork-agent.service heteronetwork-db-proxy.service
Requires=heteronetwork-db-proxy.service

[Service]
Type=simple
User=keycloak
Group=keycloak
ExecStart=/opt/heteronetwork/libexec/keycloak-start
Restart=on-failure
RestartSec=5s
TimeoutStartSec=180s
TimeoutStopSec=45s
LimitNOFILE=65536
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths=/var/lib/heteronetwork-keycloak
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
EOF
}

prepare_edge() {
  require_root
  install_edge_dependencies
  install -d -o root -g root -m 0755 /etc/heteronetwork
  install -d -o root -g haproxy -m 0750 "$edge_config_dir"
}

prepare_release() {
  require_root
  install_replica_dependencies
  ensure_service_account

  install -d -o root -g root -m 0755 /opt/heteronetwork /opt/heteronetwork/libexec
  install -d -o root -g root -m 0755 /etc/heteronetwork
  install -d -o keycloak -g keycloak -m 0750 \
    "$keycloak_data_dir" "$keycloak_data_dir/import"
  install -d -o root -g keycloak -m 0750 "$keycloak_config_dir"
  install -d -o root -g haproxy -m 0750 \
    "$backchannel_config_dir" "$edge_config_dir"

  if ! prepared_release_is_valid; then
    if [[ -e "$install_dir" || -L "$install_dir" ]]; then
      [[ -d "$install_dir" && ! -L "$install_dir" ]] \
        || die "unverified Keycloak install path is not a regular directory"
      if systemctl is-active --quiet heteronetwork-keycloak.service \
        || systemctl is-active --quiet heteronetwork-keycloak-backchannel.service; then
        die "stop the active unverified Keycloak release before replacing it"
      fi
    fi

    local archive_path="$archive" downloaded_archive="" extract_dir staged_dir
    if [[ -z "$archive_path" ]]; then
      validate_archive_url
      downloaded_archive="$(mktemp /tmp/heteronetwork-keycloak.XXXXXX.tar.gz)"
      archive_path="$downloaded_archive"
      curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 600 \
        --output "$archive_path" "$archive_url" \
        || {
          rm -f "$downloaded_archive"
          die "unable to download the pinned Keycloak archive"
        }
    fi
    validate_archive_file "$archive_path"
    printf '%s  %s\n' "$KEYCLOAK_ARCHIVE_SHA256" "$archive_path" \
      | sha256sum --check --status \
      || {
        [[ -z "$downloaded_archive" ]] || rm -f "$downloaded_archive"
        die "Keycloak archive SHA-256 mismatch"
      }

    extract_dir="$(mktemp -d /opt/heteronetwork/keycloak-extract.XXXXXX)"
    if ! tar -xzf "$archive_path" -C "$extract_dir"; then
      rm -rf "$extract_dir"
      [[ -z "$downloaded_archive" ]] || rm -f "$downloaded_archive"
      die "unable to extract Keycloak archive"
    fi
    [[ -d "$extract_dir/keycloak-${KEYCLOAK_VERSION}" ]] || {
      rm -rf "$extract_dir"
      [[ -z "$downloaded_archive" ]] || rm -f "$downloaded_archive"
      die "archive omitted the expected Keycloak directory"
    }
    staged_dir="$extract_dir/keycloak-${KEYCLOAK_VERSION}"
    [[ -z "$downloaded_archive" ]] || rm -f "$downloaded_archive"

    if ! "$staged_dir/bin/kc.sh" build \
      --db=postgres \
      --health-enabled=true \
      --metrics-enabled=true; then
      rm -rf "$extract_dir"
      die "unable to build the pinned Keycloak release"
    fi
    chown -R root:root "$staged_dir"
    find "$staged_dir" -type d -exec chmod 0755 {} +
    {
      printf 'version=%s\n' "$KEYCLOAK_VERSION"
      printf 'sha256=%s\n' "$KEYCLOAK_ARCHIVE_SHA256"
    } >"$staged_dir/.heteronetwork-prepared"
    chown root:root "$staged_dir/.heteronetwork-prepared"
    chmod 0444 "$staged_dir/.heteronetwork-prepared"

    if [[ -e "$install_dir" ]]; then
      rm -rf --one-file-system "$install_dir"
    fi
    mv "$staged_dir" "$install_dir"
    rmdir "$extract_dir"
  fi

  chown root:root "$install_dir"
  chmod 0755 "$install_dir"
  find "$install_dir" -type d -exec chmod 0755 {} +
  ln -sfn "$install_dir" "$current_link"
  if [[ -d "$install_dir/data" && ! -L "$install_dir/data" ]]; then
    rmdir "$install_dir/data"
  fi
  [[ -e "$install_dir/data" ]] || ln -s "$keycloak_data_dir" "$install_dir/data"

  render_keycloak_start \
    | install -o root -g root -m 0755 /dev/stdin \
      /opt/heteronetwork/libexec/keycloak-start
  render_keycloak_service \
    | install -o root -g root -m 0644 /dev/stdin \
      /etc/systemd/system/heteronetwork-keycloak.service
  systemctl daemon-reload
}

render_backchannel_haproxy_config() {
  local address
  cat <<'EOF'
global
    log stdout format raw local0
    maxconn 2048

defaults
    log global
    mode http
    option httplog
    option dontlog-normal
    timeout connect 2s
    timeout client 2m
    timeout server 2m

frontend heteronetwork_keycloak_backchannel
EOF
  local -a addresses=()
  IFS=, read -r -a addresses <<<"$backchannel_listen_addresses"
  for address in "${addresses[@]}"; do
    printf '    bind %s:%s\n' "$address" "$backchannel_port"
  done
  cat <<EOF
    http-request set-header X-Forwarded-Host %[req.hdr(Host)]
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Port 443
    default_backend heteronetwork_keycloak_local

backend heteronetwork_keycloak_local
    server local 127.0.0.1:${http_port} check inter 2s fall 2 rise 2
EOF
}

render_backchannel_service() {
  cat <<'EOF'
[Unit]
Description=HeteroNetwork Keycloak private backchannel
Wants=heteronetwork-agent.service
After=network-online.target heteronetwork-agent.service heteronetwork-keycloak.service
Requires=heteronetwork-keycloak.service
BindsTo=heteronetwork-keycloak.service

[Service]
Type=notify
User=haproxy
Group=haproxy
RuntimeDirectory=heteronetwork-keycloak-backchannel
ExecStart=/usr/sbin/haproxy -Ws -f /etc/heteronetwork/keycloak-backchannel/haproxy.cfg -p /run/heteronetwork-keycloak-backchannel/haproxy.pid
ExecReload=/bin/kill -USR2 $MAINPID
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
EOF
}

install_backchannel_configuration() {
  validate_private_ipv4 "$cluster_bind_address"
  validate_backchannel_listen_addresses
  validate_port "$http_port" "HETERONETWORK_KEYCLOAK_HTTP_PORT"
  validate_port "$backchannel_port" "HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT"
  command -v haproxy >/dev/null 2>&1 || die "haproxy is not installed"

  install -d -o root -g haproxy -m 0750 "$backchannel_config_dir"
  local temporary
  temporary="$(mktemp "$backchannel_config_dir/.haproxy.cfg.XXXXXX")"
  render_backchannel_haproxy_config >"$temporary"
  chown root:haproxy "$temporary"
  chmod 0640 "$temporary"
  /usr/sbin/haproxy -c -f "$temporary" >/dev/null
  mv -f "$temporary" "$backchannel_config_dir/haproxy.cfg"
  render_backchannel_service \
    | install -o root -g root -m 0644 /dev/stdin \
      /etc/systemd/system/heteronetwork-keycloak-backchannel.service
}

configure_replica() {
  require_root
  prepared_release_is_valid || die "pinned Keycloak release is not prepared"
  systemctl is-active --quiet heteronetwork-db.service \
    || die "heteronetwork-db.service is not active"
  systemctl is-active --quiet heteronetwork-db-proxy.service \
    || die "heteronetwork-db-proxy.service is not active"
  validate_secret_file "$db_password_file" \
    "HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE"
  validate_secret_file "$bootstrap_admin_password_file" \
    "HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE"
  validate_private_ipv4 "$cluster_bind_address"
  validate_port "$http_port" "HETERONETWORK_KEYCLOAK_HTTP_PORT"
  validate_port "$management_port" "HETERONETWORK_KEYCLOAK_MANAGEMENT_PORT"
  [[ "$http_port" != "$management_port" ]] \
    || die "HTTP and management ports must differ"
  [[ "$db_url" == jdbc:postgresql://* ]] \
    || die "database URL must use PostgreSQL JDBC"

  install -d -o root -g keycloak -m 0750 "$keycloak_config_dir"
  install -o root -g keycloak -m 0640 \
    "$db_password_file" "$keycloak_config_dir/db.password"
  install -o root -g keycloak -m 0640 \
    "$bootstrap_admin_password_file" "$keycloak_config_dir/bootstrap-admin.password"

  if [[ -n "$import_dir" ]]; then
    [[ "$import_dir" == /* && -d "$import_dir" && ! -L "$import_dir" ]] \
      || die "HETERONETWORK_KEYCLOAK_IMPORT_DIR must be an absolute directory"
    local imported=0 file
    shopt -s nullglob
    for file in "$import_dir"/*.json; do
      [[ -f "$file" && ! -L "$file" ]] || die "realm import must be a regular file"
      install -o keycloak -g keycloak -m 0640 \
        "$file" "$keycloak_data_dir/import/$(basename "$file")"
      imported=1
    done
    ((imported == 1)) || die "Keycloak import directory contains no JSON exports"
  fi

  local temporary
  temporary="$(mktemp "$install_dir/conf/.keycloak.conf.XXXXXX")"
  cat >"$temporary" <<EOF
db=postgres
db-url=${db_url}
db-username=keycloak
http-enabled=true
http-host=127.0.0.1
http-port=${http_port}
http-management-port=${management_port}
hostname-strict=false
proxy-headers=xforwarded
proxy-trusted-addresses=127.0.0.1/32
health-enabled=true
metrics-enabled=true
cache=ispn
cache-stack=jdbc-ping
cache-embedded-network-bind-address=${cluster_bind_address}
cache-embedded-network-bind-port=7800
EOF
  chown root:keycloak "$temporary"
  chmod 0640 "$temporary"
  mv -f "$temporary" "$install_dir/conf/keycloak.conf"

  install_backchannel_configuration
  systemctl daemon-reload
}

activate_replica() {
  require_root
  prepared_release_is_valid || die "pinned Keycloak release is not prepared"
  [[ -f "$install_dir/conf/keycloak.conf" \
    && -f "$keycloak_config_dir/db.password" \
    && -f "$keycloak_config_dir/bootstrap-admin.password" \
    && -f "$backchannel_config_dir/haproxy.cfg" ]] \
    || die "Keycloak replica is not configured"

  if ! systemctl is-active --quiet heteronetwork-keycloak.service; then
    systemctl start heteronetwork-keycloak.service
  fi
  systemctl is-active --quiet heteronetwork-keycloak.service \
    || die "Keycloak replica did not become active"

  if systemctl is-active --quiet heteronetwork-keycloak-backchannel.service; then
    systemctl reload-or-restart heteronetwork-keycloak-backchannel.service
  else
    systemctl start heteronetwork-keycloak-backchannel.service
  fi
  systemctl is-active --quiet heteronetwork-keycloak-backchannel.service \
    || die "Keycloak backchannel did not become active"

  local attempt
  for ((attempt = 1; attempt <= ACTIVATION_READY_ATTEMPTS; attempt++)); do
    if curl --fail --silent --show-error \
      --connect-timeout 1 --max-time "$ACTIVATION_READY_REQUEST_TIMEOUT_SECONDS" \
      "http://127.0.0.1:${management_port}/health/ready" >/dev/null 2>&1; then
      return
    fi
    ((attempt == ACTIVATION_READY_ATTEMPTS)) \
      || sleep "$ACTIVATION_READY_INTERVAL_SECONDS"
  done
  die "Keycloak replica did not become ready after activation"
}

deactivate_replica() {
  require_root
  local failed=0
  if ! systemctl stop heteronetwork-keycloak-backchannel.service; then
    failed=1
  fi
  if ! systemctl stop heteronetwork-keycloak.service; then
    failed=1
  fi
  if ((failed == 0)); then
    systemctl reset-failed \
      heteronetwork-keycloak-backchannel.service \
      heteronetwork-keycloak.service
  fi
  ((failed == 0))
}

render_edge_haproxy_config() {
  local endpoint index=0
  cat <<EOF
global
    log stdout format raw local0
    maxconn 2048

defaults
    log global
    mode http
    option httplog
    option dontlog-normal
    timeout connect 2s
    timeout client 2m
    timeout server 2m

frontend heteronetwork_keycloak_edge
    bind 127.0.0.1:${edge_listen_port}
    default_backend heteronetwork_keycloak_replicas

backend heteronetwork_keycloak_replicas
    balance roundrobin
    option httpchk
    http-check send meth GET uri ${edge_health_path} hdr Host localhost
    http-check expect status 200
EOF
  local -a endpoints=()
  IFS=, read -r -a endpoints <<<"$edge_upstreams"
  for endpoint in "${endpoints[@]}"; do
    index=$((index + 1))
    printf '    server replica_%s %s check inter 2s fall 2 rise 2\n' \
      "$index" "$endpoint"
  done
}

render_edge_service() {
  cat <<'EOF'
[Unit]
Description=HeteroNetwork Keycloak edge proxy
Wants=heteronetwork-agent.service
After=network-online.target heteronetwork-agent.service

[Service]
Type=notify
User=haproxy
Group=haproxy
RuntimeDirectory=heteronetwork-keycloak-edge-proxy
ExecStart=/usr/sbin/haproxy -Ws -f /etc/heteronetwork/keycloak-edge-proxy/haproxy.cfg -p /run/heteronetwork-keycloak-edge-proxy/haproxy.pid
ExecReload=/bin/kill -USR2 $MAINPID
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
EOF
}

configure_edge_proxy() {
  require_root
  validate_port "$edge_listen_port" "HETERONETWORK_KEYCLOAK_EDGE_LISTEN_PORT"
  validate_edge_upstreams
  validate_edge_health_path
  command -v haproxy >/dev/null 2>&1 || die "haproxy is not installed"
  systemctl is-active --quiet heteronetwork-agent.service \
    || die "heteronetwork-agent.service is not active"

  install -d -o root -g haproxy -m 0750 "$edge_config_dir"
  local temporary unit_temporary config_changed=0 unit_changed=0
  temporary="$(mktemp "$edge_config_dir/.haproxy.cfg.XXXXXX")"
  render_edge_haproxy_config >"$temporary"
  chown root:haproxy "$temporary"
  chmod 0640 "$temporary"
  /usr/sbin/haproxy -c -f "$temporary" >/dev/null
  if [[ -f "$edge_config_dir/haproxy.cfg" \
    && ! -L "$edge_config_dir/haproxy.cfg" ]] \
    && cmp -s "$temporary" "$edge_config_dir/haproxy.cfg"; then
    rm -f "$temporary"
  else
    mv -f "$temporary" "$edge_config_dir/haproxy.cfg"
    config_changed=1
  fi
  unit_temporary="$(mktemp \
    /etc/systemd/system/.heteronetwork-keycloak-edge-proxy.service.XXXXXX)"
  render_edge_service >"$unit_temporary"
  chown root:root "$unit_temporary"
  chmod 0644 "$unit_temporary"
  if [[ -f /etc/systemd/system/heteronetwork-keycloak-edge-proxy.service \
    && ! -L /etc/systemd/system/heteronetwork-keycloak-edge-proxy.service ]] \
    && cmp -s "$unit_temporary" \
      /etc/systemd/system/heteronetwork-keycloak-edge-proxy.service; then
    rm -f "$unit_temporary"
  else
    mv -f "$unit_temporary" \
      /etc/systemd/system/heteronetwork-keycloak-edge-proxy.service
    unit_changed=1
  fi
  if ((unit_changed == 1)); then
    systemctl daemon-reload
  fi
  if systemctl is-active --quiet heteronetwork-keycloak-edge-proxy.service; then
    if ((config_changed == 1 || unit_changed == 1)); then
      systemctl reload-or-restart heteronetwork-keycloak-edge-proxy.service
    fi
  else
    systemctl start heteronetwork-keycloak-edge-proxy.service
  fi
  systemctl is-active --quiet heteronetwork-keycloak-edge-proxy.service \
    || die "Keycloak edge proxy did not become active"
}

deactivate_edge_proxy() {
  require_root
  systemctl stop heteronetwork-keycloak-edge-proxy.service
  systemctl reset-failed heteronetwork-keycloak-edge-proxy.service
}

case "${1:-}" in
  prepare-edge)
    prepare_edge
    ;;
  prepare)
    prepare_release
    ;;
  prepared)
    prepared_release_is_valid
    ;;
  configure)
    configure_replica
    ;;
  activate)
    activate_replica
    ;;
  deactivate)
    deactivate_replica
    ;;
  configure-edge-proxy)
    configure_edge_proxy
    ;;
  deactivate-edge-proxy)
    deactivate_edge_proxy
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
