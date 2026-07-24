#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_VERSION="26.6.4"
readonly DEFAULT_ARCHIVE_SHA256="386b566bbea05527226e275c43e5cf6f218896ad2441ac4be5c39f1226772e8f"
readonly DEFAULT_HTTP_PORT="18080"
readonly DEFAULT_MANAGEMENT_PORT="19000"
readonly DEFAULT_BACKCHANNEL_PORT="18080"
readonly DEFAULT_DB_URL="jdbc:postgresql://postgres.heteronetwork.internal:25432/keycloak?sslmode=verify-full&sslrootcert=/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt"

version="${HETERONETWORK_KEYCLOAK_VERSION:-$DEFAULT_VERSION}"
archive="${HETERONETWORK_KEYCLOAK_ARCHIVE:-}"
archive_sha256="${HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256:-$DEFAULT_ARCHIVE_SHA256}"
cluster_bind_address="${HETERONETWORK_KEYCLOAK_CLUSTER_BIND_ADDRESS:-}"
db_url="${HETERONETWORK_KEYCLOAK_DB_URL:-$DEFAULT_DB_URL}"
db_password_file="${HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE:-}"
bootstrap_admin_password_file="${HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE:-}"
import_dir="${HETERONETWORK_KEYCLOAK_IMPORT_DIR:-}"
http_port="${HETERONETWORK_KEYCLOAK_HTTP_PORT:-$DEFAULT_HTTP_PORT}"
management_port="${HETERONETWORK_KEYCLOAK_MANAGEMENT_PORT:-$DEFAULT_MANAGEMENT_PORT}"
backchannel_port="${HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT:-$DEFAULT_BACKCHANNEL_PORT}"
backchannel_listen_addresses="${HETERONETWORK_KEYCLOAK_BACKCHANNEL_LISTEN_ADDRESSES:-$cluster_bind_address}"

usage() {
  cat <<'EOF'
Usage: keycloak-ha-node.sh COMMAND

Commands:
  install              Install Keycloak and its private HA backchannel
  install-backchannel  Reconcile only the private HA backchannel proxy

Required environment:
  HETERONETWORK_KEYCLOAK_ARCHIVE
  HETERONETWORK_KEYCLOAK_CLUSTER_BIND_ADDRESS
  HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE
  HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE

Optional environment:
  HETERONETWORK_KEYCLOAK_IMPORT_DIR
  HETERONETWORK_KEYCLOAK_DB_URL
  HETERONETWORK_KEYCLOAK_VERSION
  HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256
  HETERONETWORK_KEYCLOAK_HTTP_PORT
  HETERONETWORK_KEYCLOAK_MANAGEMENT_PORT
  HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT
  HETERONETWORK_KEYCLOAK_BACKCHANNEL_LISTEN_ADDRESSES

The node must already have heteronetwork-db-proxy.service installed. Keycloak
listens on loopback for HTTP and uses the HeteroNetwork VPN address for its
encrypted embedded-cache transport. The private backchannel defaults to that
address and can additionally bind trusted RFC1918 or CGNAT management paths.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

validate_absolute_regular_file() {
  local path="$1" name="$2"
  [[ "$path" == /* ]] || die "$name must be an absolute path"
  [[ -f "$path" && ! -L "$path" ]] || die "$name must be a non-symlink regular file"
}

validate_ipv4() {
  local value="$1" a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] \
    || die "invalid cluster bind IPv4 address: $value"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || die "invalid cluster bind IPv4 address: $value"
    ((10#$octet <= 255)) || die "invalid cluster bind IPv4 address: $value"
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
  die "backchannel listen address must be private IPv4 or CGNAT: $value"
}

validate_backchannel_listen_addresses() {
  local address
  local -A seen=()
  local -a addresses=()
  IFS=, read -r -a addresses <<<"$backchannel_listen_addresses"
  ((${#addresses[@]} > 0)) || die "backchannel listen addresses must not be empty"
  for address in "${addresses[@]}"; do
    [[ -n "$address" && "$address" != *[[:space:]]* ]] \
      || die "backchannel listen addresses must be comma-separated IPv4 addresses without spaces"
    validate_private_ipv4 "$address"
    [[ -z "${seen[$address]:-}" ]] || die "duplicate backchannel listen address: $address"
    seen["$address"]=1
  done
}

validate_port() {
  local value="$1" name="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a TCP port"
  ((10#$value >= 1024 && 10#$value <= 65535)) || die "$name is outside 1024-65535"
}

validate_config() {
  validate_absolute_regular_file "$archive" "HETERONETWORK_KEYCLOAK_ARCHIVE"
  validate_absolute_regular_file \
    "$db_password_file" "HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE"
  validate_absolute_regular_file \
    "$bootstrap_admin_password_file" \
    "HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE"
  validate_ipv4 "$cluster_bind_address"
  validate_port "$http_port" "HETERONETWORK_KEYCLOAK_HTTP_PORT"
  validate_port "$management_port" "HETERONETWORK_KEYCLOAK_MANAGEMENT_PORT"
  validate_port "$backchannel_port" "HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT"
  [[ "$http_port" != "$management_port" ]] || die "HTTP and management ports must differ"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid Keycloak version"
  [[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid archive SHA-256"
  [[ "$db_url" == jdbc:postgresql://* ]] || die "database URL must use PostgreSQL JDBC"
  if [[ -n "$import_dir" ]]; then
    [[ "$import_dir" == /* && -d "$import_dir" && ! -L "$import_dir" ]] \
      || die "HETERONETWORK_KEYCLOAK_IMPORT_DIR must be an absolute non-symlink directory"
  fi
  systemctl is-active --quiet heteronetwork-db-proxy.service \
    || die "heteronetwork-db-proxy.service is not active"
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
  cat <<EOF
[Unit]
Description=HeteroNetwork Keycloak private backchannel
Wants=network-online.target heteronetwork-keycloak.service
After=network-online.target heteronetwork-agent.service heteronetwork-keycloak.service
Requires=heteronetwork-agent.service
PartOf=heteronetwork-agent.service

[Service]
Type=notify
User=haproxy
Group=haproxy
RuntimeDirectory=heteronetwork-keycloak-backchannel
ExecStart=/usr/sbin/haproxy -Ws -f /etc/heteronetwork/keycloak-backchannel/haproxy.cfg -p /run/heteronetwork-keycloak-backchannel/haproxy.pid
ExecReload=/bin/kill -USR2 \$MAINPID
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
WantedBy=multi-user.target heteronetwork-agent.service
EOF
}

install_backchannel() {
  require_root
  validate_ipv4 "$cluster_bind_address"
  validate_backchannel_listen_addresses
  validate_port "$http_port" "HETERONETWORK_KEYCLOAK_HTTP_PORT"
  validate_port "$backchannel_port" "HETERONETWORK_KEYCLOAK_BACKCHANNEL_PORT"
  command -v haproxy >/dev/null 2>&1 || die "haproxy is not installed"
  systemctl is-active --quiet heteronetwork-keycloak.service \
    || die "heteronetwork-keycloak.service is not active"

  install -d -o root -g haproxy -m 0750 /etc/heteronetwork/keycloak-backchannel
  render_backchannel_haproxy_config \
    | install -o root -g haproxy -m 0640 /dev/stdin \
      /etc/heteronetwork/keycloak-backchannel/haproxy.cfg
  render_backchannel_service \
    | install -o root -g root -m 0644 /dev/stdin \
      /etc/systemd/system/heteronetwork-keycloak-backchannel.service
  /usr/sbin/haproxy -c -f /etc/heteronetwork/keycloak-backchannel/haproxy.cfg
  systemctl daemon-reload
  systemctl enable heteronetwork-keycloak-backchannel.service
  if systemctl is-active --quiet heteronetwork-keycloak-backchannel.service; then
    systemctl reload-or-restart heteronetwork-keycloak-backchannel.service
  else
    systemctl start heteronetwork-keycloak-backchannel.service
  fi
}

install_keycloak() {
  require_root
  validate_config
  printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check --status \
    || die "Keycloak archive SHA-256 mismatch"

  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update
  apt-get -o DPkg::Lock::Timeout=300 install --yes --no-install-recommends \
    ca-certificates haproxy openjdk-21-jre-headless

  if ! getent group keycloak >/dev/null; then
    groupadd --system keycloak
  fi
  if ! id keycloak >/dev/null 2>&1; then
    useradd --system --gid keycloak --home-dir /var/lib/heteronetwork-keycloak \
      --shell /usr/sbin/nologin keycloak
  fi

  local install_dir="/opt/heteronetwork/keycloak-${version}"
  local current_link="/opt/heteronetwork/keycloak"
  install -d -o root -g root -m 0755 /opt/heteronetwork
  if [[ ! -d "$install_dir" ]]; then
    local extract_dir
    extract_dir="$(mktemp -d /opt/heteronetwork/keycloak-extract.XXXXXX)"
    trap 'rm -rf "$extract_dir"' EXIT
    tar -xzf "$archive" -C "$extract_dir"
    [[ -d "$extract_dir/keycloak-${version}" ]] || die "archive omitted expected Keycloak directory"
    mv "$extract_dir/keycloak-${version}" "$install_dir"
    rmdir "$extract_dir"
    trap - EXIT
  fi
  ln -sfn "$install_dir" "$current_link"

  install -d -o keycloak -g keycloak -m 0750 \
    /var/lib/heteronetwork-keycloak \
    /var/lib/heteronetwork-keycloak/import
  if [[ -d "$install_dir/data" && ! -L "$install_dir/data" ]]; then
    rmdir "$install_dir/data"
  fi
  [[ -e "$install_dir/data" ]] || ln -s /var/lib/heteronetwork-keycloak "$install_dir/data"

  if [[ -n "$import_dir" ]]; then
    local imported=0 file
    shopt -s nullglob
    for file in "$import_dir"/*.json; do
      install -o keycloak -g keycloak -m 0640 \
        "$file" "/var/lib/heteronetwork-keycloak/import/$(basename "$file")"
      imported=1
    done
    ((imported == 1)) || die "Keycloak import directory contains no JSON exports"
  fi

  install -d -o root -g keycloak -m 0750 /etc/heteronetwork/keycloak
  install -o root -g keycloak -m 0640 \
    "$db_password_file" /etc/heteronetwork/keycloak/db.password
  install -o root -g keycloak -m 0640 \
    "$bootstrap_admin_password_file" /etc/heteronetwork/keycloak/bootstrap-admin.password

  cat >"$install_dir/conf/keycloak.conf" <<EOF
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
  chown root:keycloak "$install_dir/conf/keycloak.conf"
  chmod 0640 "$install_dir/conf/keycloak.conf"

  "$install_dir/bin/kc.sh" build \
    --db=postgres \
    --health-enabled=true \
    --metrics-enabled=true

  install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
  cat >/opt/heteronetwork/libexec/keycloak-start <<'EOF'
#!/bin/sh
set -eu
export KC_DB_PASSWORD
KC_DB_PASSWORD="$(cat /etc/heteronetwork/keycloak/db.password)"
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /etc/heteronetwork/keycloak/bootstrap-admin.password)"
exec /opt/heteronetwork/keycloak/bin/kc.sh start --optimized --import-realm
EOF
  chmod 0755 /opt/heteronetwork/libexec/keycloak-start

  cat >/etc/systemd/system/heteronetwork-keycloak.service <<EOF
[Unit]
Description=HeteroNetwork Keycloak HA replica
Wants=network-online.target
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

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now heteronetwork-keycloak.service
  install_backchannel
}

case "${1:-}" in
  install)
    install_keycloak
    ;;
  install-backchannel)
    install_backchannel
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
