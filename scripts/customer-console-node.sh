#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly REALM="heteronetwork-customers"
readonly CONSOLE_CLIENT_ID="heteronetwork-customer-console"
readonly API_AUDIENCE="heteronetwork-customer-api"
readonly REQUIRED_ROLE="heteronetwork-customer"
readonly DEFAULT_API_URL="http://127.0.0.1:19881"
readonly LOCAL_HOST="127.0.0.1"
readonly LOCAL_PORT="28088"
readonly SERVICE_NAME="heteronetwork-customer-console.service"
readonly SERVICE_USER="heteronetwork-customer-console"
readonly CONFIG_DIR="/etc/heteronetwork/customer-console"
readonly CONFIG_PATH="${CONFIG_DIR}/customer-console.env"
readonly CURRENT_LINK="/opt/heteronetwork/customer-console"
readonly LIBEXEC_DIR="/opt/heteronetwork/libexec"
readonly START_PATH="${LIBEXEC_DIR}/customer-console-start"
readonly MAX_CONFIG_BYTES="16384"
readonly MAX_SOURCE_FILE_BYTES="2097152"
readonly MINIMUM_NODE_MAJOR="20"

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_root="${HETERONETWORK_CUSTOMER_CONSOLE_SOURCE_ROOT:-$(CDPATH= cd -- "$script_dir/.." && pwd)}"
systemd_source_dir="${HETERONETWORK_CUSTOMER_CONSOLE_SYSTEMD_DIR:-$(CDPATH= cd -- "$script_dir/../deploy/systemd" && pwd)}"
public_url="${HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL:-}"
issuer_url="${HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL:-}"
api_url="${HETERONETWORK_CUSTOMER_API_URL:-$DEFAULT_API_URL}"

readonly -a SOURCE_FILES=(
  webconsole/server.mjs
  customerui/index.html
  customerui/app.js
  customerui/styles.css
  webui/noto-sans-jp-ui.ttf
)

usage() {
  cat <<'EOF'
Usage: customer-console-node.sh COMMAND

Commands:
  validate-config  Validate deployment input without changing the host
  plan             Print a non-mutating deployment plan
  render-start     Render the installed clean-environment launcher
  install          Install assets, configuration, launcher, and systemd unit
  validate-live    Verify local service isolation and the public TLS edge
  status           Print bounded local service status

Required environment for validate-config, plan, and install:
  HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL
      Exact public HTTPS origin, without path or trailing slash.
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL
      Exact customer issuer ending in /realms/heteronetwork-customers.

Optional environment:
  HETERONETWORK_CUSTOMER_API_URL
      Customer API base URL. Default: http://127.0.0.1:19881
  HETERONETWORK_CUSTOMER_CONSOLE_SOURCE_ROOT
      Source tree containing webconsole/, customerui/, and webui/.
  HETERONETWORK_CUSTOMER_CONSOLE_SYSTEMD_DIR
      Directory containing heteronetwork-customer-console.service.

The Node backend always binds 127.0.0.1:28088. Installation does not expose it.
A same-host public reverse proxy with a publicly trusted TLS certificate is a
required, separate prerequisite.
EOF
}

die() {
  printf 'customer-console-node: error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 \
    || die "required command is unavailable: $1"
}

validate_safe_absolute_path() {
  local value="$1" label="$2"
  [[ "$value" =~ ^/[A-Za-z0-9_./-]+$ \
    && "$value" != *"//"* \
    && "/$value/" != *"/../"* \
    && "/$value/" != *"/./"* ]] \
    || die "$label must be a normalized absolute path"
}

validate_public_configuration() {
  [[ -n "$public_url" ]] \
    || die "HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL is required"
  [[ -n "$issuer_url" ]] \
    || die "HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL is required"
  require_command python3
  python3 - "$public_url" "$issuer_url" "$api_url" "$REALM" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit

public_url, issuer_url, api_url, realm = sys.argv[1:]

def fail(message):
    print(f"customer-console-node: error: {message}", file=sys.stderr)
    raise SystemExit(1)

def parse(value, label):
    if (
        not value
        or any(character.isspace() for character in value)
        or "*" in value
        or "\\" in value
        or '"' in value
        or "'" in value
    ):
        fail(f"{label} must be an exact URL without wildcard, quote, or whitespace")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(f"{label} is malformed")
    if (
        not parsed.scheme
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        fail(f"{label} must be an absolute URL without credentials or fragment")
    return parsed, port

def validate_public_host(host, label):
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
            or not all(character.isalnum() or character == "-" for character in part)
            for part in labels
        ):
            fail(f"{label} has an invalid DNS name")
    else:
        if not address.is_global:
            fail(f"{label} IP address is not globally routable")

public, public_port = parse(public_url, "customer console public URL")
if (
    public.scheme != "https"
    or public.path
    or public.query
    or public_port is not None
):
    fail("customer console public URL must be an HTTPS origin using implicit port 443")
validate_public_host(public.hostname, "customer console public URL")

issuer, issuer_port = parse(issuer_url, "customer OIDC issuer")
if (
    issuer.scheme != "https"
    or issuer.path != f"/realms/{realm}"
    or issuer.query
    or issuer_port is not None
):
    fail(
        f"customer OIDC issuer must be HTTPS on implicit port 443 "
        f"with exact path /realms/{realm}"
    )
validate_public_host(issuer.hostname, "customer OIDC issuer")

api, api_port = parse(api_url, "customer API URL")
if not api.hostname:
    fail("customer API URL has no host")
if api.path or api.query:
    fail("customer API URL must be an origin without path or query")
if api.scheme == "http":
    if api.hostname not in ("127.0.0.1", "::1"):
        fail("plain-HTTP customer API URL must use a literal loopback address")
    if api_port is None or not 1024 <= api_port <= 65535:
        fail("plain-HTTP customer API URL requires an explicit non-privileged port")
elif api.scheme == "https":
    if api_port is not None and not 1 <= api_port <= 65535:
        fail("customer API HTTPS port is invalid")
else:
    fail("customer API URL must use loopback HTTP or HTTPS")
PY
}

validate_node_runtime() {
  [[ -x /usr/bin/node ]] || die "/usr/bin/node is required"
  local major
  major="$(/usr/bin/node -p 'Number(process.versions.node.split(".")[0])')" \
    || die "unable to determine the Node.js version"
  [[ "$major" =~ ^[0-9]+$ ]] \
    || die "unable to determine the Node.js version"
  ((10#$major >= 10#$MINIMUM_NODE_MAJOR)) \
    || die "Node.js $MINIMUM_NODE_MAJOR or newer is required"
}

validate_source_tree() {
  validate_safe_absolute_path "$source_root" "customer console source root"
  [[ -d "$source_root" && ! -L "$source_root" ]] \
    || die "customer console source root must be a non-symlink directory"
  local relative path size
  for relative in "${SOURCE_FILES[@]}"; do
    path="$source_root/$relative"
    [[ -f "$path" && ! -L "$path" ]] \
      || die "required customer console source is missing or unsafe: $relative"
    size="$(stat -c '%s' -- "$path")" \
      || die "unable to inspect customer console source: $relative"
    ((10#$size > 0 && 10#$size <= MAX_SOURCE_FILE_BYTES)) \
      || die "customer console source has an invalid size: $relative"
  done
  /usr/bin/node --check "$source_root/webconsole/server.mjs" >/dev/null
  /usr/bin/node --check "$source_root/customerui/app.js" >/dev/null
}

validate_systemd_source() {
  local unit_source="$systemd_source_dir/$SERVICE_NAME"
  validate_safe_absolute_path "$systemd_source_dir" \
    "customer console systemd source directory"
  [[ -d "$systemd_source_dir" && ! -L "$systemd_source_dir" ]] \
    || die "customer console systemd source directory is missing"
  [[ -f "$unit_source" && ! -L "$unit_source" ]] \
    || die "customer console systemd unit is missing"
}

validate_install_inputs() {
  validate_public_configuration
  validate_node_runtime
  validate_source_tree
  validate_systemd_source
}

source_digest() {
  local relative hash
  {
    for relative in "${SOURCE_FILES[@]}"; do
      hash="$(sha256sum "$source_root/$relative" | awk '{print $1}')"
      printf '%s %s\n' "$relative" "$hash"
    done
  } | sha256sum | awk '{print $1}'
}

ensure_service_account() {
  if ! getent group "$SERVICE_USER" >/dev/null; then
    groupadd --system "$SERVICE_USER"
  fi
  local service_gid
  service_gid="$(getent group "$SERVICE_USER" | awk -F: 'NR == 1 { print $3 }')"
  [[ "$service_gid" =~ ^[0-9]+$ ]] \
    || die "unable to resolve the dedicated service group"

  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system \
      --gid "$SERVICE_USER" \
      --home-dir "/var/lib/$SERVICE_USER" \
      --shell /usr/sbin/nologin \
      "$SERVICE_USER"
    return
  fi

  local name _password uid gid gecos home shell
  IFS=: read -r name _password uid gid gecos home shell \
    < <(getent passwd "$SERVICE_USER") \
    || die "unable to inspect the dedicated service user"
  [[ "$name" == "$SERVICE_USER" \
    && "$uid" =~ ^[0-9]+$ \
    && "$uid" != "0" \
    && "$gid" == "$service_gid" \
    && "$home" == "/var/lib/$SERVICE_USER" \
    && "$shell" == "/usr/sbin/nologin" ]] \
    || die "existing $SERVICE_USER account does not match the dedicated service contract"
}

install_release() {
  local digest release_dir staged relative destination
  digest="$(source_digest)"
  release_dir="/opt/heteronetwork/customer-console-${digest}"
  install -d -o root -g root -m 0755 /opt/heteronetwork

  if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    [[ -d "$release_dir" && ! -L "$release_dir" \
      && -f "$release_dir/.source-sha256" \
      && "$(<"$release_dir/.source-sha256")" == "$digest" ]] \
      || die "existing customer console release path is invalid"
  else
    staged="$(mktemp -d /opt/heteronetwork/customer-console-stage.XXXXXX)"
    chown root:root "$staged"
    chmod 0755 "$staged"
    for relative in "${SOURCE_FILES[@]}"; do
      destination="$staged/$relative"
      install -d -o root -g root -m 0755 "$(dirname -- "$destination")"
      install -o root -g root -m 0644 \
        "$source_root/$relative" "$destination"
    done
    printf '%s\n' "$digest" >"$staged/.source-sha256"
    chown root:root "$staged/.source-sha256"
    chmod 0444 "$staged/.source-sha256"
    /usr/bin/node --check "$staged/webconsole/server.mjs" >/dev/null
    /usr/bin/node --check "$staged/customerui/app.js" >/dev/null
    mv "$staged" "$release_dir"
  fi

  if [[ -e "$CURRENT_LINK" && ! -L "$CURRENT_LINK" ]]; then
    die "customer console current path exists and is not a symbolic link"
  fi
  ln -sfn "$release_dir" "$CURRENT_LINK"
}

render_start() {
  cat <<'EOF'
#!/bin/sh
set -eu
: "${HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL:?customer public URL is required}"
: "${HETERONETWORK_CUSTOMER_API_URL:?customer API URL is required}"
: "${HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL:?customer issuer is required}"
exec /usr/bin/env -i \
  HOME=/var/lib/heteronetwork-customer-console \
  LANG=C.UTF-8 \
  PATH=/usr/bin:/bin \
  NODE_ENV=production \
  HOST=127.0.0.1 \
  PORT=28088 \
  HETERONETWORK_CONSOLE_MODE=customer \
  "HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL=${HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL}" \
  "HETERONETWORK_CUSTOMER_API_URL=${HETERONETWORK_CUSTOMER_API_URL}" \
  "HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=${HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL}" \
  HETERONETWORK_CUSTOMER_OIDC_CLIENT_ID=heteronetwork-customer-console \
  HETERONETWORK_CUSTOMER_OIDC_AUDIENCE=heteronetwork-customer-api \
  'HETERONETWORK_CUSTOMER_OIDC_SCOPES=openid profile email' \
  HETERONETWORK_CUSTOMER_ROLES=heteronetwork-customer \
  /usr/bin/node /opt/heteronetwork/customer-console/webconsole/server.mjs
EOF
}

write_config() {
  install -d -o root -g root -m 0755 /etc/heteronetwork
  install -d -o root -g root -m 0700 "$CONFIG_DIR"
  local temporary
  temporary="$(mktemp "$CONFIG_DIR/.customer-console.env.XXXXXX")"
  {
    printf 'HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL=%s\n' "$public_url"
    printf 'HETERONETWORK_CUSTOMER_API_URL=%s\n' "$api_url"
    printf 'HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=%s\n' "$issuer_url"
  } >"$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$CONFIG_PATH"
}

secure_config_file() {
  [[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || return 1
  local uid links mode size lines
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$CONFIG_PATH") \
    || return 1
  [[ "$uid" == "0" && "$links" == "1" && "$mode" =~ ^[0-7]{3,4}$ ]] \
    || return 1
  (( (8#$mode & 0400) != 0 && (8#$mode & 0077) == 0 )) || return 1
  ((10#$size > 0 && 10#$size <= MAX_CONFIG_BYTES)) || return 1
  lines="$(wc -l <"$CONFIG_PATH" | tr -d ' ')"
  [[ "$lines" == "3" ]] || return 1
  grep -Eq '^HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL=[^=[:space:]]+$' "$CONFIG_PATH" \
    && grep -Eq '^HETERONETWORK_CUSTOMER_API_URL=[^=[:space:]]+$' "$CONFIG_PATH" \
    && grep -Eq '^HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=[^=[:space:]]+$' "$CONFIG_PATH"
}

config_value() {
  local key="$1"
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
  ' "$CONFIG_PATH"
}

load_installed_config() {
  secure_config_file \
    || die "installed customer console configuration is missing or unsafe"
  public_url="$(config_value HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL)" \
    || die "installed customer public URL is invalid"
  api_url="$(config_value HETERONETWORK_CUSTOMER_API_URL)" \
    || die "installed customer API URL is invalid"
  issuer_url="$(config_value HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL)" \
    || die "installed customer issuer is invalid"
  validate_public_configuration
}

install_runtime_files() {
  local unit_source="$systemd_source_dir/$SERVICE_NAME"
  validate_systemd_source

  install -d -o root -g root -m 0755 "$LIBEXEC_DIR"
  render_start \
    | install -o root -g root -m 0755 /dev/stdin "$START_PATH"
  install -o root -g root -m 0644 \
    "$unit_source" "/etc/systemd/system/$SERVICE_NAME"
}

wait_local_console() {
  local attempt
  for ((attempt = 1; attempt <= 30; attempt++)); do
    if curl --fail --silent --show-error \
      --connect-timeout 1 --max-time 2 \
      "http://${LOCAL_HOST}:${LOCAL_PORT}/cloud/config" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "customer console did not become ready on loopback"
}

install_node() {
  require_root
  validate_install_inputs
  require_command curl
  require_command sha256sum
  ensure_service_account
  install_release
  write_config
  install_runtime_files
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl restart "$SERVICE_NAME"
  wait_local_console
  printf 'Customer console installed. Public URL: %s/cloud/\n' "$public_url"
}

http_status() {
  curl --silent --show-error \
    --output /dev/null --write-out '%{http_code}' \
    --connect-timeout 2 --max-time 8 "$1"
}

verify_console_config() {
  local url="$1" public_tls="$2" response
  local -a curl_args=(
    --fail
    --silent
    --show-error
    --connect-timeout 2
    --max-time 8
    --max-filesize 1048576
  )
  if [[ "$public_tls" == "true" ]]; then
    curl_args+=(--proto '=https' --tlsv1.2)
  fi
  response="$(curl "${curl_args[@]}" "$url/cloud/config")" \
    || die "customer console config request failed: $url"
  jq -e \
    --arg issuer "$issuer_url" \
    --arg client "$CONSOLE_CLIENT_ID" '
      .enabled == true
      and .auth_enabled == true
      and .operator_token_enabled == false
      and .provider == "keycloak"
      and .issuer_url == $issuer
      and .client_id == $client
      and .login_endpoint == "/cloud/login"
      and .session_refresh_endpoint == "/cloud/auth/refresh"
      and .session_logout_endpoint == "/cloud/auth/logout"
    ' >/dev/null <<<"$response" \
    || die "customer console config does not match the customer-only contract"
}

verify_isolated_routes() {
  local base="$1" status
  status="$(http_status "$base/ui/")"
  [[ "$status" == "403" || "$status" == "404" ]] \
    || die "operator UI is exposed at $base/ui/ (HTTP $status)"
  status="$(http_status "$base/v1/admin/overview")"
  [[ "$status" == "403" || "$status" == "404" ]] \
    || die "operator API is exposed at $base/v1/admin/overview (HTTP $status)"
  status="$(http_status "$base/v1/metrics")"
  [[ "$status" == "403" || "$status" == "404" ]] \
    || die "operator metrics are exposed at $base/v1/metrics (HTTP $status)"
  status="$(http_status "$base/v1/customer/session")"
  [[ "$status" == "401" ]] \
    || die "customer API did not require authentication at $base (HTTP $status)"
}

verify_oidc_discovery() {
  local discovery
  discovery="$(curl --fail --silent --show-error \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 3 --max-time 10 --max-filesize 1048576 \
    "${issuer_url}/.well-known/openid-configuration")" \
    || die "customer OIDC discovery failed"
  jq -e --arg issuer "$issuer_url" '.issuer == $issuer' \
    >/dev/null <<<"$discovery" \
    || die "customer OIDC discovery returned a different issuer"
}

validate_live() {
  require_root
  load_installed_config
  require_command curl
  require_command jq
  systemctl is-active --quiet "$SERVICE_NAME" \
    || die "$SERVICE_NAME is not active"
  local local_base="http://${LOCAL_HOST}:${LOCAL_PORT}"
  verify_console_config "$local_base" false
  verify_isolated_routes "$local_base"

  local api_health
  api_health="$(curl --fail --silent --show-error \
    --connect-timeout 2 --max-time 8 --max-filesize 1048576 \
    "${api_url}/healthz")" \
    || die "customer API upstream health check failed"
  jq -e '.status == "ok"' >/dev/null <<<"$api_health" \
    || die "customer API upstream returned an invalid health document"

  verify_console_config "$public_url" true
  verify_isolated_routes "$public_url"
  verify_oidc_discovery
  printf 'Customer console edge is valid at %s/cloud/.\n' "$public_url"
}

print_plan() {
  validate_install_inputs
  cat <<EOF
mode=dry-run
console_mode=customer
operator_environment_fallback=false
service=${SERVICE_NAME}
service_user=${SERVICE_USER}
backend=http://${LOCAL_HOST}:${LOCAL_PORT}
public_url=${public_url}
public_paths=/cloud,/v1/customer
public_tls_termination=required
customer_api_url=${api_url}
issuer=${issuer_url}
oidc_client_id=${CONSOLE_CLIENT_ID}
oidc_audience=${API_AUDIENCE}
required_role=${REQUIRED_ROLE}
EOF
}

print_status() {
  require_root
  load_installed_config
  local state
  state="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
  printf 'service=%s\n' "$SERVICE_NAME"
  printf 'state=%s\n' "${state:-unknown}"
  if curl --fail --silent \
    --connect-timeout 1 --max-time 2 \
    "http://${LOCAL_HOST}:${LOCAL_PORT}/cloud/config" >/dev/null 2>&1; then
    printf 'ready=true\n'
  else
    printf 'ready=false\n'
  fi
  printf 'public_url=%s\n' "$public_url"
  printf 'customer_api_url=%s\n' "$api_url"
  printf 'issuer=%s\n' "$issuer_url"
}

case "${1:-}" in
  validate-config)
    validate_public_configuration
    printf 'Customer console configuration is valid.\n'
    ;;
  plan|--dry-run)
    print_plan
    ;;
  render-start)
    render_start
    ;;
  install)
    install_node
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
