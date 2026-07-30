#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly KEYCLOAK_VERSION="26.6.4"
readonly KEYCLOAK_ARCHIVE_SHA256="386b566bbea05527226e275c43e5cf6f218896ad2441ac4be5c39f1226772e8f"
readonly DEFAULT_ARCHIVE_URL="https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz"
readonly REALM="heteronetwork-customers"
readonly DATABASE_NAME="heteronetwork_customer_identity"
readonly DATABASE_ROLE="heteronetwork_customer_identity"
readonly DATABASE_SCHEMA="customer_identity"
readonly DATABASE_HOST="postgres.heteronetwork.internal"
readonly DATABASE_PROXY_PORT="25432"
readonly HTTP_PORT="28080"
readonly MANAGEMENT_PORT="29000"
readonly CACHE_PORT="27800"
readonly ADMIN_USERNAME="customer-bootstrap-admin"
readonly MAX_SECRET_BYTES="4096"
readonly MAX_CONFIG_BYTES="65536"
readonly MAX_ARCHIVE_BYTES="1073741824"

readonly install_dir="/opt/heteronetwork/customer-keycloak-${KEYCLOAK_VERSION}"
readonly current_link="/opt/heteronetwork/customer-keycloak"
readonly prepared_marker="${install_dir}/.heteronetwork-customer-prepared"
readonly config_dir="/etc/heteronetwork/customer-keycloak"
readonly config_path="${config_dir}/customer-keycloak.env"
readonly secret_dir="${config_dir}/secrets"
readonly data_dir="/var/lib/heteronetwork-customer-keycloak"
readonly libexec_dir="/opt/heteronetwork/libexec"
readonly postgres_ca_path="/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt"
readonly default_db_admin_password_file="/etc/heteronetwork/postgres-autopilot/bundle/secrets/superuser.password"

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
systemd_source_dir="${HETERONETWORK_CUSTOMER_KEYCLOAK_SYSTEMD_DIR:-$script_dir/../deploy/systemd}"
archive="${HETERONETWORK_CUSTOMER_KEYCLOAK_ARCHIVE:-}"
archive_url="${HETERONETWORK_CUSTOMER_KEYCLOAK_ARCHIVE_URL:-$DEFAULT_ARCHIVE_URL}"
secret_bundle="${HETERONETWORK_CUSTOMER_KEYCLOAK_SECRET_BUNDLE:-}"
issuer_url="${HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL:-}"
public_origin=""
cluster_bind_address="${HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS:-}"
redirect_uris_csv="${HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS:-}"
web_origins_csv="${HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS:-}"
trusted_proxy_cidrs="${HETERONETWORK_CUSTOMER_KEYCLOAK_TRUSTED_PROXY_CIDRS:-127.0.0.1/32}"
db_admin_password_file="${HETERONETWORK_CUSTOMER_KEYCLOAK_DB_ADMIN_PASSWORD_FILE:-$default_db_admin_password_file}"

usage() {
  cat <<'EOF'
Usage: customer-keycloak-node.sh COMMAND [OUTPUT_DIR]

Commands:
  init-secrets OUTPUT_DIR
      Idempotently create the customer-only database and bootstrap secrets.
  validate-config
      Validate environment input without mutating the host.
  plan
      Print the validated, non-secret deployment plan without mutating the host.
  install
      Idempotently install, configure, start, and bootstrap one customer replica.
  provision-database
      Reconcile the dedicated PostgreSQL role, database, and schema.
  validate-live
      Verify database login, local services, realm state, and public TLS discovery.
  status
      Print bounded service and local issuer status.

Required environment for validate-config, plan, and install:
  HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL
      Exact public issuer, for example:
      https://identity.example.com/realms/heteronetwork-customers
  HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS
      Private/CGNAT address used only for Keycloak cache clustering.
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS
      Comma-separated exact HTTPS callback URIs; wildcards are refused.
  HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS
      Comma-separated exact HTTPS origins.

Required environment for install:
  HETERONETWORK_CUSTOMER_KEYCLOAK_SECRET_BUNDLE
      Root-only directory created by init-secrets and shared securely with every
      customer Keycloak replica.

Optional environment for install:
  HETERONETWORK_CUSTOMER_KEYCLOAK_DB_ADMIN_PASSWORD_FILE
  HETERONETWORK_CUSTOMER_KEYCLOAK_TRUSTED_PROXY_CIDRS
  HETERONETWORK_CUSTOMER_KEYCLOAK_ARCHIVE
  HETERONETWORK_CUSTOMER_KEYCLOAK_ARCHIVE_URL
  HETERONETWORK_CUSTOMER_KEYCLOAK_SYSTEMD_DIR

Keycloak listens only on 127.0.0.1:28080. A public TLS reverse proxy or load
balancer must publish the exact configured issuer and forward to that port.
EOF
}

die() {
  printf 'customer-keycloak-node: error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'customer-keycloak-node: %s\n' "$*" >&2
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 \
    || die "required command is unavailable: $1"
}

validate_ipv4() {
  local value="$1" a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" \
    && -n "${c:-}" && -n "${d:-}" ]] \
    || die "invalid IPv4 address: $value"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] \
      || die "invalid IPv4 address: $value"
    ((10#$octet <= 255)) || die "invalid IPv4 address: $value"
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
  die "cluster bind address must be private IPv4 or CGNAT"
}

validate_safe_absolute_path() {
  local value="$1" label="$2"
  [[ "$value" =~ ^/[A-Za-z0-9_./-]+$ && "$value" != *"//"* ]] \
    || die "$label must be a simple absolute path"
}

validate_public_urls() {
  require_command python3
  public_origin="$(
    python3 - \
      "$issuer_url" \
      "$REALM" \
      "$redirect_uris_csv" \
      "$web_origins_csv" \
      "$trusted_proxy_cidrs" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit

issuer, realm, redirect_csv, origin_csv, proxy_csv = sys.argv[1:]

def fail(message):
    print(f"customer-keycloak-node: error: {message}", file=sys.stderr)
    raise SystemExit(1)

def validate_host(host, label):
    if not host:
        fail(f"{label} has no host")
    lowered = host.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith((".internal", ".local", ".localhost")):
        fail(f"{label} must use a public DNS name or globally routable IP")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = lowered.split(".")
        if len(labels) < 2 or any(
            not part
            or len(part) > 63
            or part[0] == "-"
            or part[-1] == "-"
            or not all(char.isalnum() or char == "-" for char in part)
            for part in labels
        ):
            fail(f"{label} has an invalid DNS name")
    else:
        if not address.is_global:
            fail(f"{label} IP address is not globally routable")

def parse_https(value, label, exact_origin=False):
    if not value or any(char.isspace() for char in value) or "*" in value:
        fail(f"{label} must be a non-wildcard HTTPS URL without whitespace")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(f"{label} is malformed")
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        fail(f"{label} must be an absolute HTTPS URL without credentials or fragment")
    validate_host(parsed.hostname, label)
    if exact_origin and (
        parsed.path not in ("", "/")
        or parsed.query
    ):
        fail(f"{label} must be an HTTPS origin without path or query")
    return parsed, port

parsed_issuer, issuer_port = parse_https(issuer, "customer issuer")
if parsed_issuer.path != f"/realms/{realm}" or parsed_issuer.query:
    fail(f"customer issuer path must be exactly /realms/{realm}")
if issuer_port is not None:
    fail("customer issuer must use implicit public TLS port 443")

redirects = redirect_csv.split(",") if redirect_csv else []
origins = origin_csv.split(",") if origin_csv else []
if not redirects or any(not item for item in redirects):
    fail("at least one exact console redirect URI is required")
if not origins or any(not item for item in origins):
    fail("at least one exact console web origin is required")
if len(set(redirects)) != len(redirects):
    fail("console redirect URIs contain a duplicate")
if len(set(origins)) != len(origins):
    fail("console web origins contain a duplicate")
for index, value in enumerate(redirects, 1):
    parse_https(value, f"console redirect URI {index}")
for index, value in enumerate(origins, 1):
    parse_https(value, f"console web origin {index}", exact_origin=True)

proxies = proxy_csv.split(",") if proxy_csv else []
if not proxies or any(not item for item in proxies):
    fail("at least one trusted reverse-proxy CIDR is required")
for value in proxies:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        fail(f"invalid trusted reverse-proxy CIDR: {value}")
    if network.is_global:
        fail(f"trusted reverse-proxy CIDR must not be globally routable: {value}")

host = parsed_issuer.hostname
if ":" in host:
    host = f"[{host}]"
print(f"https://{host}")
PY
  )" || exit 1
}

validate_configuration_values() {
  [[ -n "$issuer_url" ]] \
    || die "HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL is required"
  [[ -n "$cluster_bind_address" ]] \
    || die "HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS is required"
  [[ -n "$redirect_uris_csv" ]] \
    || die "HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS is required"
  [[ -n "$web_origins_csv" ]] \
    || die "HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS is required"
  [[ "$redirect_uris_csv" != *[[:space:]]* \
    && "$web_origins_csv" != *[[:space:]]* \
    && "$trusted_proxy_cidrs" != *[[:space:]]* ]] \
    || die "URI and CIDR lists must not contain whitespace"
  validate_private_ipv4 "$cluster_bind_address"
  validate_safe_absolute_path "$db_admin_password_file" \
    "database admin password file"
  validate_public_urls
}

secure_secret_file() {
  local path="$1" label="$2"
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] \
    || die "$label must be an absolute non-symlink regular file"
  local uid links mode size
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$path") \
    || die "unable to inspect $label"
  [[ "$uid" == "0" && "$links" == "1" && "$mode" =~ ^[0-7]{3,4}$ ]] \
    || die "$label must be root-owned and have one hard link"
  (( (8#$mode & 0400) != 0 && (8#$mode & 0077) == 0 )) \
    || die "$label must be owner-readable and inaccessible to group/world"
  ((10#$size > 0 && 10#$size <= MAX_SECRET_BYTES)) \
    || die "$label has an invalid size"
  local value
  value="$(<"$path")"
  [[ "$value" =~ ^[a-f0-9]{64}$ ]] \
    || die "$label must contain one 64-character lowercase hex secret"
}

read_secret_file() {
  local path="$1" label="$2"
  secure_secret_file "$path" "$label"
  printf '%s' "$(<"$path")"
}

secure_config_file() {
  [[ -f "$config_path" && ! -L "$config_path" ]] || return 1
  local uid links mode size
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$config_path") \
    || return 1
  [[ "$uid" == "0" && "$links" == "1" && "$mode" =~ ^[0-7]{3,4}$ ]] \
    || return 1
  (( (8#$mode & 0400) != 0 && (8#$mode & 0077) == 0 )) || return 1
  ((10#$size > 0 && 10#$size <= MAX_CONFIG_BYTES))
}

load_installed_config() {
  secure_config_file \
    || die "installed customer Keycloak configuration is missing or unsafe"
  unset \
    HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL \
    HETERONETWORK_CUSTOMER_KEYCLOAK_PUBLIC_ORIGIN \
    HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS \
    HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS \
    HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS \
    HETERONETWORK_CUSTOMER_KEYCLOAK_TRUSTED_PROXY_CIDRS \
    HETERONETWORK_CUSTOMER_KEYCLOAK_DB_ADMIN_PASSWORD_FILE
  # This file is generated below and is root-owned and root-only.
  # shellcheck disable=SC1090
  source "$config_path"
  issuer_url="${HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL:-}"
  public_origin="${HETERONETWORK_CUSTOMER_KEYCLOAK_PUBLIC_ORIGIN:-}"
  cluster_bind_address="${HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS:-}"
  redirect_uris_csv="${HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS:-}"
  web_origins_csv="${HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS:-}"
  trusted_proxy_cidrs="${HETERONETWORK_CUSTOMER_KEYCLOAK_TRUSTED_PROXY_CIDRS:-}"
  db_admin_password_file="${HETERONETWORK_CUSTOMER_KEYCLOAK_DB_ADMIN_PASSWORD_FILE:-}"
  local configured_origin="$public_origin"
  validate_configuration_values
  [[ "$configured_origin" == "$public_origin" ]] \
    || die "installed public origin does not match the issuer"
}

write_installed_config() {
  install -d -o root -g root -m 0755 /etc/heteronetwork
  install -d -o root -g root -m 0700 "$config_dir"
  local temporary
  temporary="$(mktemp "$config_dir/.customer-keycloak.env.XXXXXX")"
  {
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=%q\n' "$issuer_url"
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_PUBLIC_ORIGIN=%q\n' "$public_origin"
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS=%q\n' \
      "$cluster_bind_address"
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=%q\n' \
      "$redirect_uris_csv"
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=%q\n' \
      "$web_origins_csv"
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_TRUSTED_PROXY_CIDRS=%q\n' \
      "$trusted_proxy_cidrs"
    printf 'HETERONETWORK_CUSTOMER_KEYCLOAK_DB_ADMIN_PASSWORD_FILE=%q\n' \
      "$db_admin_password_file"
  } >"$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$config_path"
}

create_secret() {
  local path="$1" temporary
  [[ ! -e "$path" && ! -L "$path" ]] || return
  temporary="$(mktemp "$(dirname -- "$path")/.secret.XXXXXX")"
  openssl rand -hex 32 >"$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -n "$temporary" "$path"
  rm -f -- "$temporary"
}

init_secrets() {
  require_root
  require_command openssl
  local output="${1:-}"
  [[ -n "$output" ]] || die "init-secrets requires OUTPUT_DIR"
  validate_safe_absolute_path "$output" "secret output directory"
  if [[ -e "$output" || -L "$output" ]]; then
    [[ -d "$output" && ! -L "$output" ]] \
      || die "secret output path must be a non-symlink directory"
    [[ "$(stat -c '%u' "$output")" == "0" ]] \
      || die "secret output directory must be root-owned"
    chmod 0700 "$output"
  else
    install -d -o root -g root -m 0700 "$output"
  fi
  create_secret "$output/db.password"
  create_secret "$output/bootstrap-admin.password"
  secure_secret_file "$output/db.password" "customer database secret"
  secure_secret_file "$output/bootstrap-admin.password" \
    "customer bootstrap admin secret"
  printf 'Customer Keycloak secrets are ready at %s.\n' "$output"
}

validate_secret_bundle() {
  [[ -n "$secret_bundle" ]] \
    || die "HETERONETWORK_CUSTOMER_KEYCLOAK_SECRET_BUNDLE is required"
  validate_safe_absolute_path "$secret_bundle" "customer secret bundle"
  [[ -d "$secret_bundle" && ! -L "$secret_bundle" ]] \
    || die "customer secret bundle must be a non-symlink directory"
  secure_secret_file "$secret_bundle/db.password" "customer database secret"
  secure_secret_file "$secret_bundle/bootstrap-admin.password" \
    "customer bootstrap admin secret"
}

install_secrets() {
  validate_secret_bundle
  install -d -o root -g root -m 0700 "$secret_dir"
  local name source destination
  for name in db.password bootstrap-admin.password; do
    source="$secret_bundle/$name"
    destination="$secret_dir/$name"
    if [[ -e "$destination" || -L "$destination" ]]; then
      secure_secret_file "$destination" "installed customer secret $name"
      cmp -s -- "$source" "$destination" \
        || die "refusing to replace installed customer secret $name"
    else
      install -o root -g root -m 0600 "$source" "$destination"
    fi
    secure_secret_file "$destination" "installed customer secret $name"
  done
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
  validate_safe_absolute_path "$path" "Keycloak archive path"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "Keycloak archive must be a non-symlink regular file"
  local size
  size="$(stat -c '%s' -- "$path")" \
    || die "unable to inspect Keycloak archive"
  ((10#$size > 0 && 10#$size <= MAX_ARCHIVE_BYTES)) \
    || die "Keycloak archive size is invalid"
}

prepared_release_is_valid() {
  [[ -x "$install_dir/bin/kc.sh" \
    && -f "$prepared_marker" \
    && ! -L "$prepared_marker" ]] || return 1
  grep -Fqx "version=$KEYCLOAK_VERSION" "$prepared_marker" \
    && grep -Fqx "sha256=$KEYCLOAK_ARCHIVE_SHA256" "$prepared_marker" \
    && grep -Fqx "plane=customer" "$prepared_marker"
}

install_dependencies() {
  if command -v java >/dev/null 2>&1 \
    && command -v psql >/dev/null 2>&1 \
    && command -v curl >/dev/null 2>&1 \
    && command -v jq >/dev/null 2>&1 \
    && command -v python3 >/dev/null 2>&1; then
    return
  fi
  command -v apt-get >/dev/null 2>&1 \
    || die "automatic installation currently requires apt-get"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update
  apt-get -o DPkg::Lock::Timeout=300 install --yes --no-install-recommends \
    ca-certificates curl jq openjdk-21-jre-headless postgresql-client python3
}

ensure_service_account() {
  if ! getent group heteronetwork-customer-keycloak >/dev/null; then
    groupadd --system heteronetwork-customer-keycloak
  fi
  if ! id heteronetwork-customer-keycloak >/dev/null 2>&1; then
    useradd --system \
      --gid heteronetwork-customer-keycloak \
      --home-dir "$data_dir" \
      --shell /usr/sbin/nologin \
      heteronetwork-customer-keycloak
  fi
}

prepare_release() {
  install -d -o root -g root -m 0755 /opt/heteronetwork "$libexec_dir"
  install -d \
    -o heteronetwork-customer-keycloak \
    -g heteronetwork-customer-keycloak \
    -m 0750 \
    "$data_dir" "$data_dir/import"

  if ! prepared_release_is_valid; then
    if [[ -e "$install_dir" || -L "$install_dir" ]]; then
      [[ -d "$install_dir" && ! -L "$install_dir" ]] \
        || die "customer Keycloak install path is not a regular directory"
      if systemctl is-active --quiet heteronetwork-customer-keycloak.service; then
        die "stop the active unverified customer Keycloak release before replacing it"
      fi
    fi

    local archive_path="$archive" downloaded_archive="" extract_dir staged_dir
    if [[ -z "$archive_path" ]]; then
      validate_archive_url
      downloaded_archive="$(mktemp /tmp/heteronetwork-customer-keycloak.XXXXXX.tar.gz)"
      archive_path="$downloaded_archive"
      if ! curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 600 \
        --output "$archive_path" "$archive_url"; then
        rm -f -- "$downloaded_archive"
        die "unable to download the pinned Keycloak archive"
      fi
    fi
    validate_archive_file "$archive_path"
    printf '%s  %s\n' "$KEYCLOAK_ARCHIVE_SHA256" "$archive_path" \
      | sha256sum --check --status \
      || {
        [[ -z "$downloaded_archive" ]] || rm -f -- "$downloaded_archive"
        die "Keycloak archive SHA-256 mismatch"
      }

    extract_dir="$(mktemp -d /opt/heteronetwork/customer-keycloak-extract.XXXXXX)"
    if ! tar -xzf "$archive_path" -C "$extract_dir"; then
      rm -rf -- "$extract_dir"
      [[ -z "$downloaded_archive" ]] || rm -f -- "$downloaded_archive"
      die "unable to extract the Keycloak archive"
    fi
    staged_dir="$extract_dir/keycloak-${KEYCLOAK_VERSION}"
    [[ -d "$staged_dir" && ! -L "$staged_dir" ]] \
      || {
        rm -rf -- "$extract_dir"
        [[ -z "$downloaded_archive" ]] || rm -f -- "$downloaded_archive"
        die "archive omitted the expected Keycloak release directory"
      }
    [[ -z "$downloaded_archive" ]] || rm -f -- "$downloaded_archive"

    if ! "$staged_dir/bin/kc.sh" build \
      --db=postgres \
      --health-enabled=true \
      --metrics-enabled=true; then
      rm -rf -- "$extract_dir"
      die "unable to build the pinned customer Keycloak release"
    fi
    {
      printf 'version=%s\n' "$KEYCLOAK_VERSION"
      printf 'sha256=%s\n' "$KEYCLOAK_ARCHIVE_SHA256"
      printf 'plane=customer\n'
    } >"$staged_dir/.heteronetwork-customer-prepared"
    chown -R root:root "$staged_dir"
    chmod 0444 "$staged_dir/.heteronetwork-customer-prepared"
    find "$staged_dir" -type d -exec chmod 0755 {} +

    if [[ -e "$install_dir" ]]; then
      rm -rf --one-file-system -- "$install_dir"
    fi
    mv "$staged_dir" "$install_dir"
    rmdir "$extract_dir"
  fi

  chown -R root:root "$install_dir"
  chmod 0755 "$install_dir"
  find "$install_dir" -type d -exec chmod 0755 {} +
  ln -sfn "$install_dir" "$current_link"
  if [[ -d "$install_dir/data" && ! -L "$install_dir/data" ]]; then
    rmdir "$install_dir/data"
  fi
  [[ -e "$install_dir/data" ]] \
    || ln -s "$data_dir" "$install_dir/data"
}

render_keycloak_start() {
  cat <<'EOF'
#!/bin/sh
set -eu
: "${CREDENTIALS_DIRECTORY:?systemd credentials are required}"
export KC_DB_PASSWORD
KC_DB_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/db-password")"
export KC_BOOTSTRAP_ADMIN_USERNAME=customer-bootstrap-admin
export KC_BOOTSTRAP_ADMIN_PASSWORD
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/bootstrap-admin-password")"
exec /opt/heteronetwork/customer-keycloak/bin/kc.sh start --optimized
EOF
}

render_keycloak_config() {
  cat <<EOF
db=postgres
db-url=jdbc:postgresql://${DATABASE_HOST}:${DATABASE_PROXY_PORT}/${DATABASE_NAME}?sslmode=verify-full&sslrootcert=${postgres_ca_path}
db-username=${DATABASE_ROLE}
db-schema=${DATABASE_SCHEMA}
http-enabled=true
http-host=127.0.0.1
http-port=${HTTP_PORT}
http-management-port=${MANAGEMENT_PORT}
hostname=${public_origin}
hostname-strict=true
hostname-backchannel-dynamic=true
proxy-headers=xforwarded
proxy-trusted-addresses=${trusted_proxy_cidrs}
health-enabled=true
metrics-enabled=true
cache=ispn
cache-stack=jdbc-ping
cache-embedded-network-bind-address=${cluster_bind_address}
cache-embedded-network-bind-port=${CACHE_PORT}
EOF
}

install_runtime_files() {
  local bootstrap_source="$script_dir/customer-keycloak-bootstrap.sh"
  [[ -f "$bootstrap_source" && ! -L "$bootstrap_source" ]] \
    || die "customer Keycloak bootstrap helper is missing beside this script"
  [[ -d "$systemd_source_dir" && ! -L "$systemd_source_dir" ]] \
    || die "customer Keycloak systemd source directory is missing"

  local unit
  for unit in \
    heteronetwork-customer-keycloak-database.service \
    heteronetwork-customer-keycloak.service \
    heteronetwork-customer-keycloak-bootstrap.service; do
    [[ -f "$systemd_source_dir/$unit" && ! -L "$systemd_source_dir/$unit" ]] \
      || die "required customer Keycloak unit is missing: $unit"
    install -o root -g root -m 0644 \
      "$systemd_source_dir/$unit" "/etc/systemd/system/$unit"
  done

  if [[ "$(readlink -f -- "$0")" != "$libexec_dir/customer-keycloak-node.sh" ]]; then
    install -o root -g root -m 0755 \
      "$0" "$libexec_dir/customer-keycloak-node.sh"
  fi
  install -o root -g root -m 0755 \
    "$bootstrap_source" "$libexec_dir/customer-keycloak-bootstrap.sh"
  render_keycloak_start \
    | install -o root -g root -m 0755 /dev/stdin \
      "$libexec_dir/customer-keycloak-start"

  local temporary
  temporary="$(mktemp "$install_dir/conf/.customer-keycloak.conf.XXXXXX")"
  render_keycloak_config >"$temporary"
  chown root:heteronetwork-customer-keycloak "$temporary"
  chmod 0640 "$temporary"
  mv -f "$temporary" "$install_dir/conf/keycloak.conf"
}

postgres_admin_connection() {
  printf 'host=%s hostaddr=127.0.0.1 port=%s dbname=%s user=postgres sslmode=verify-full sslrootcert=%s connect_timeout=5' \
    "$DATABASE_HOST" "$DATABASE_PROXY_PORT" "${1:-postgres}" "$postgres_ca_path"
}

postgres_customer_connection() {
  printf 'host=%s hostaddr=127.0.0.1 port=%s dbname=%s user=%s sslmode=verify-full sslrootcert=%s connect_timeout=5' \
    "$DATABASE_HOST" "$DATABASE_PROXY_PORT" "$DATABASE_NAME" \
    "$DATABASE_ROLE" "$postgres_ca_path"
}

provision_database() {
  require_root
  load_installed_config
  require_command psql
  systemctl is-active --quiet heteronetwork-db-proxy.service \
    || die "heteronetwork-db-proxy.service is not active"
  [[ -f "$postgres_ca_path" && ! -L "$postgres_ca_path" ]] \
    || die "PostgreSQL HA client CA is missing"

  local admin_password database_password admin_connection customer_admin_connection
  admin_password="$(read_secret_file "$db_admin_password_file" \
    "PostgreSQL admin password")"
  database_password="$(read_secret_file "$secret_dir/db.password" \
    "customer database password")"
  admin_connection="$(postgres_admin_connection postgres)"

  {
    printf "\\set customer_password '%s'\n" "$database_password"
    cat <<'SQL'
SELECT pg_advisory_lock(hashtextextended('heteronetwork-customer-keycloak-database-v1', 0));
SELECT format(
  'CREATE ROLE heteronetwork_customer_identity LOGIN PASSWORD %L',
  :'customer_password'
)
WHERE NOT EXISTS (
  SELECT 1 FROM pg_roles WHERE rolname = 'heteronetwork_customer_identity'
) \gexec
ALTER ROLE heteronetwork_customer_identity
  WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
DO $body$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_database database
    JOIN pg_roles owner ON owner.oid = database.datdba
    WHERE database.datname = 'heteronetwork_customer_identity'
      AND owner.rolname <> 'heteronetwork_customer_identity'
  ) THEN
    RAISE EXCEPTION 'customer identity database has an unexpected owner';
  END IF;
END
$body$;
SELECT 'CREATE DATABASE heteronetwork_customer_identity OWNER heteronetwork_customer_identity'
WHERE NOT EXISTS (
  SELECT 1 FROM pg_database
  WHERE datname = 'heteronetwork_customer_identity'
) \gexec
SELECT pg_advisory_unlock(hashtextextended('heteronetwork-customer-keycloak-database-v1', 0));
SQL
  } | PGPASSWORD="$admin_password" psql "$admin_connection" \
    --no-psqlrc --set=ON_ERROR_STOP=1 >/dev/null

  customer_admin_connection="$(postgres_admin_connection "$DATABASE_NAME")"
  PGPASSWORD="$admin_password" psql "$customer_admin_connection" \
    --no-psqlrc --set=ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE SCHEMA IF NOT EXISTS customer_identity
  AUTHORIZATION heteronetwork_customer_identity;
ALTER SCHEMA customer_identity OWNER TO heteronetwork_customer_identity;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA customer_identity
  TO heteronetwork_customer_identity;
SQL

  PGPASSWORD="$database_password" psql "$(postgres_customer_connection)" \
    --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align \
    --command="SELECT current_database() || ':' || current_user" \
    | grep -Fxq "${DATABASE_NAME}:${DATABASE_ROLE}" \
    || die "dedicated customer database login verification failed"
  unset admin_password database_password
  log "dedicated customer identity database is reconciled"
}

wait_until_ready() {
  local attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if curl --fail --silent --show-error \
      --connect-timeout 1 --max-time 2 \
      "http://127.0.0.1:${MANAGEMENT_PORT}/health/ready" \
      >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done
  die "customer Keycloak did not become ready within 120 seconds"
}

install_node() {
  require_root
  validate_configuration_values
  validate_secret_bundle
  secure_secret_file "$db_admin_password_file" "PostgreSQL admin password"
  install_dependencies
  ensure_service_account
  prepare_release
  write_installed_config
  install_secrets
  install_runtime_files

  systemctl daemon-reload
  provision_database
  systemctl enable \
    heteronetwork-customer-keycloak-database.service \
    heteronetwork-customer-keycloak.service \
    heteronetwork-customer-keycloak-bootstrap.service >/dev/null
  systemctl start heteronetwork-customer-keycloak-database.service
  if systemctl is-active --quiet heteronetwork-customer-keycloak.service; then
    systemctl restart heteronetwork-customer-keycloak.service
  else
    systemctl start heteronetwork-customer-keycloak.service
  fi
  wait_until_ready
  systemctl start heteronetwork-customer-keycloak-bootstrap.service
  printf 'Customer Keycloak replica installed. Public issuer: %s\n' "$issuer_url"
}

verify_discovery_document() {
  local url="$1" public_tls="$2" discovery
  local -a curl_args=(
    --fail
    --silent
    --show-error
    --connect-timeout 3
    --max-time 10
    --max-filesize 1048576
  )
  if [[ "$public_tls" == "true" ]]; then
    curl_args+=(--proto '=https' --tlsv1.2)
  fi
  discovery="$(curl "${curl_args[@]}" "$url")" \
    || die "OIDC discovery request failed: $url"
  jq -e --arg issuer "$issuer_url" \
    '.issuer == $issuer
      and .authorization_endpoint == ($issuer + "/protocol/openid-connect/auth")
      and .token_endpoint == ($issuer + "/protocol/openid-connect/token")
      and .jwks_uri == ($issuer + "/protocol/openid-connect/certs")' \
    >/dev/null <<<"$discovery" \
    || die "OIDC discovery at $url does not advertise the exact customer issuer"
}

validate_live() {
  require_root
  load_installed_config
  require_command curl
  require_command jq
  require_command psql
  systemctl is-active --quiet heteronetwork-customer-keycloak-database.service \
    || die "customer database provisioning unit is not active"
  systemctl is-active --quiet heteronetwork-customer-keycloak.service \
    || die "customer Keycloak service is not active"
  curl --fail --silent --show-error \
    --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:${MANAGEMENT_PORT}/health/ready" >/dev/null \
    || die "customer Keycloak management readiness failed"
  verify_discovery_document \
    "http://127.0.0.1:${HTTP_PORT}/realms/${REALM}/.well-known/openid-configuration" \
    false
  verify_discovery_document \
    "${issuer_url}/.well-known/openid-configuration" \
    true
  "$libexec_dir/customer-keycloak-bootstrap.sh" validate

  local database_password
  database_password="$(read_secret_file "$secret_dir/db.password" \
    "customer database password")"
  PGPASSWORD="$database_password" psql "$(postgres_customer_connection)" \
    --no-psqlrc --set=ON_ERROR_STOP=1 \
    --tuples-only --no-align \
    --command="SELECT current_database() || ':' || current_user || ':' || has_schema_privilege(current_user, '${DATABASE_SCHEMA}', 'USAGE')" \
    | grep -Fxq "${DATABASE_NAME}:${DATABASE_ROLE}:t" \
    || die "customer database validation query failed"
  unset database_password
  printf 'Customer Keycloak deployment is valid at %s.\n' "$issuer_url"
}

print_plan() {
  validate_configuration_values
  cat <<EOF
mode=dry-run
identity_plane=customer
operator_identity_plane_mutated=false
keycloak_version=${KEYCLOAK_VERSION}
service=heteronetwork-customer-keycloak.service
database=${DATABASE_NAME}
database_role=${DATABASE_ROLE}
database_schema=${DATABASE_SCHEMA}
realm=${REALM}
issuer=${issuer_url}
backend=http://127.0.0.1:${HTTP_PORT}
management=http://127.0.0.1:${MANAGEMENT_PORT}
cache_bind=${cluster_bind_address}:${CACHE_PORT}
public_tls_termination=required
console_client=heteronetwork-customer-console
api_client=heteronetwork-customer-api
token_authorized_party=heteronetwork-customer-console
token_audience=heteronetwork-customer-api
realm_roles=heteronetwork-customer,org-admin
EOF
}

print_status() {
  require_root
  load_installed_config
  local unit state
  for unit in \
    heteronetwork-customer-keycloak-database.service \
    heteronetwork-customer-keycloak.service \
    heteronetwork-customer-keycloak-bootstrap.service; do
    state="$(systemctl is-active "$unit" 2>/dev/null || true)"
    printf '%s=%s\n' "$unit" "${state:-unknown}"
  done
  if curl --fail --silent \
    --connect-timeout 1 --max-time 2 \
    "http://127.0.0.1:${MANAGEMENT_PORT}/health/ready" >/dev/null 2>&1; then
    printf 'ready=true\n'
  else
    printf 'ready=false\n'
  fi
  printf 'issuer=%s\n' "$issuer_url"
}

case "${1:-}" in
  init-secrets)
    init_secrets "${2:-}"
    ;;
  validate-config)
    validate_configuration_values
    printf 'Customer Keycloak configuration is valid.\n'
    ;;
  plan|--dry-run)
    print_plan
    ;;
  install)
    install_node
    ;;
  provision-database)
    provision_database
    ;;
  validate-live)
    validate_live
    ;;
  status)
    print_status
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
