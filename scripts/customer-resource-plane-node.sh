#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly SERVICE_NAME="heteronetwork-control-plane.service"
readonly REALM="heteronetwork-customers"
readonly CUSTOMER_API_LISTEN="127.0.0.1:19881"
readonly CONSOLE_CLIENT_ID="heteronetwork-customer-console"
readonly API_AUDIENCE="heteronetwork-customer-api"
readonly REQUIRED_ROLE="heteronetwork-customer"
readonly OIDC_SCOPES="openid profile email"
readonly CREDENTIAL_ID="customer-controller.token"
readonly TOKEN_FILENAME="customer-controller.token"
readonly MIN_TOKEN_BYTES=32
readonly MAX_TOKEN_BYTES=512
readonly MAX_ENV_BYTES=16384

readonly TESTING="${HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TESTING:-0}"
filesystem_root=""
if [[ "$TESTING" == "1" ]]; then
  filesystem_root="${HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TEST_ROOT:-}"
  [[ "$filesystem_root" =~ ^/[A-Za-z0-9_./-]+$ \
    && "$filesystem_root" != "/" \
    && "$filesystem_root" != *"//"* \
    && "/$filesystem_root/" != *"/../"* \
    && "/$filesystem_root/" != *"/./"* \
    && -d "$filesystem_root" \
    && ! -L "$filesystem_root" ]] || {
    printf '%s\n' \
      "customer-resource-plane-node: error: unsafe test root" >&2
    exit 1
  }
elif [[ "$TESTING" != "0" \
  || -n "${HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TEST_ROOT:-}" ]]; then
  printf '%s\n' \
    "customer-resource-plane-node: error: invalid testing configuration" >&2
  exit 1
fi

root_path() {
  printf '%s%s' "$filesystem_root" "$1"
}

readonly CONFIG_DIR="$(root_path /etc/heteronetwork/customer-resource-plane)"
readonly CONFIG_PATH="${CONFIG_DIR}/customer-resource-plane.env"
readonly INSTALLED_TOKEN_PATH="${CONFIG_DIR}/${TOKEN_FILENAME}"
readonly DROP_IN_DIR="$(root_path /etc/systemd/system/${SERVICE_NAME}.d)"
readonly DROP_IN_PATH="${DROP_IN_DIR}/40-customer-resource-plane.conf"

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
readonly TEMPLATE_PATH="${script_dir}/../deploy/systemd/heteronetwork-customer-resource-plane.conf"

issuer_url="${HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL:-}"
controller_listen="${HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN:-}"
backchannel_url="${HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL:-}"
fallback_urls="${HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS:-}"
token_bundle="${HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE:-}"
token_file_input="${HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE:-}"
source_token_path=""
validated_token=""

usage() {
  cat <<'EOF'
Usage: customer-resource-plane-node.sh COMMAND [OUTPUT_DIR]

Commands:
  init-token OUTPUT_DIR
      Create OUTPUT_DIR/customer-controller.token once. Existing files are
      validated and never overwritten.
  validate-config
      Validate all deployment input without changing the host.
  plan
      Print a validated, non-secret deployment plan.
  install
      Atomically enable the customer resource plane on this Control Plane.
  disable
      Remove the installed resource-plane drop-in, environment, and token copy.
  status
      Show bounded service and installation state without printing secrets.

Required environment for validate-config, plan, and install:
  HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL
      Exact public HTTPS issuer ending in /realms/heteronetwork-customers.
  HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN
      Non-loopback private/CGNAT literal IP and non-privileged port reachable
      from the Kubernetes controller.
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE
      Root-only directory containing customer-controller.token.
    or
  HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_FILE
      Root-only customer-controller.token file. Set exactly one token source.

Optional environment:
  HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL
  HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS
      A comma-separated list. Every URL must end in the customer realm; an
      operator-realm URL is rejected.

install and disable must run as root. Distribute the same token bundle to every
HA Control Plane replica and to the Kubernetes controller Secret.
EOF
}

die() {
  printf 'customer-resource-plane-node: error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'customer-resource-plane-node: %s\n' "$*" >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 \
    || die "required command is unavailable: $1"
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

validate_absolute_path() {
  local value="$1" label="$2"
  [[ "$value" =~ ^/[A-Za-z0-9_./-]+$ \
    && "$value" != *"//"* \
    && "/$value/" != *"/../"* \
    && "/$value/" != *"/./"* ]] \
    || die "$label must be a normalized absolute path"
}

validate_no_symlink_components() {
  local value="$1" label="$2" component current="/"
  validate_absolute_path "$value" "$label"
  IFS=/ read -r -a components <<<"${value#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    if [[ "$current" == "/" ]]; then
      current="/$component"
    else
      current="$current/$component"
    fi
    if [[ -L "$current" ]]; then
      die "$label must not contain symbolic-link components"
    fi
  done
}

installation_owner_ids() {
  if [[ "$TESTING" == "1" ]]; then
    stat -c '%u %g' -- "$filesystem_root"
  else
    printf '0 0\n'
  fi
}

source_owner_is_allowed() {
  local uid="$1" install_uid current_uid
  read -r install_uid _ < <(installation_owner_ids)
  if [[ "$uid" == "$install_uid" ]]; then
    return 0
  fi
  current_uid="$(id -u)"
  if [[ "$TESTING" == "0" && "$uid" == "$current_uid" ]]; then
    return 0
  fi
  if [[ "$TESTING" == "0" \
    && "${SUDO_UID:-}" =~ ^[0-9]+$ \
    && "$uid" == "$SUDO_UID" ]]; then
    return 0
  fi
  return 1
}

validate_source_directory() {
  local path="$1" label="$2" uid mode
  validate_no_symlink_components "$path" "$label"
  [[ -d "$path" && ! -L "$path" ]] \
    || die "$label must be a non-symlink directory"
  read -r uid mode < <(stat -c '%u %a' -- "$path") \
    || die "unable to inspect $label"
  source_owner_is_allowed "$uid" \
    || die "$label must be owned by root or the invoking sudo user"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "$label has an invalid mode"
  (( (8#$mode & 0700) == 0700 && (8#$mode & 0077) == 0 )) \
    || die "$label must have mode 0700"
}

read_valid_token_file() {
  local path="$1" owner_policy="$2" label="$3"
  local uid links mode size token last_byte install_uid
  local LC_ALL=C

  validate_no_symlink_components "$path" "$label"
  [[ -f "$path" && ! -L "$path" ]] \
    || die "$label must be a regular non-symlink file"
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$path") \
    || die "unable to inspect $label"
  [[ "$links" == "1" ]] || die "$label must have exactly one hard link"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "$label has an invalid mode"
  (( (8#$mode & 0400) != 0 && (8#$mode & 0077) == 0 )) \
    || die "$label must be owner-readable and inaccessible to group/other"
  ((10#$size >= MIN_TOKEN_BYTES && 10#$size <= MAX_TOKEN_BYTES + 1)) \
    || die "$label must contain between $MIN_TOKEN_BYTES and $MAX_TOKEN_BYTES bytes"

  if [[ "$owner_policy" == "source" ]]; then
    source_owner_is_allowed "$uid" \
      || die "$label must be owned by root or the invoking sudo user"
  else
    read -r install_uid _ < <(installation_owner_ids)
    [[ "$uid" == "$install_uid" ]] \
      || die "$label must be owned by root"
  fi

  token=""
  IFS= read -r token <"$path" || [[ -n "$token" ]] \
    || die "$label is empty"
  [[ "$token" =~ ^[\!-~]{32,512}$ ]] \
    || die "$label must contain one printable non-space ASCII token"
  if ((10#$size == ${#token} + 1)); then
    last_byte="$(tail -c 1 -- "$path" | od -An -tx1 | tr -d '[:space:]')"
    [[ "$last_byte" == "0a" ]] \
      || die "$label has invalid trailing data"
  elif ((10#$size != ${#token})); then
    die "$label must contain exactly one token"
  fi
  printf '%s' "$token"
}

resolve_token_source() {
  if [[ -n "$token_bundle" && -n "$token_file_input" ]]; then
    die "set only one token bundle or token file"
  fi
  if [[ -z "$token_bundle" && -z "$token_file_input" ]]; then
    die "a customer resource-plane token bundle or token file is required"
  fi

  if [[ -n "$token_bundle" ]]; then
    validate_source_directory "$token_bundle" \
      "customer resource-plane token bundle"
    source_token_path="${token_bundle}/${TOKEN_FILENAME}"
  else
    validate_absolute_path "$token_file_input" \
      "customer resource-plane token file"
    validate_source_directory "$(dirname -- "$token_file_input")" \
      "customer resource-plane token parent"
    source_token_path="$token_file_input"
  fi

  [[ "$source_token_path" != "$INSTALLED_TOKEN_PATH" \
    && "$source_token_path" != "$CONFIG_DIR/"* ]] \
    || die "the source token must be outside the installed configuration directory"
  validated_token="$(
    read_valid_token_file "$source_token_path" source \
      "customer controller bearer token"
  )"
}

validate_network_configuration() {
  [[ -n "$issuer_url" ]] \
    || die "HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL is required"
  [[ -n "$controller_listen" ]] \
    || die "HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN is required"
  require_command python3
  python3 - \
    "$issuer_url" \
    "$controller_listen" \
    "$backchannel_url" \
    "$fallback_urls" \
    "$REALM" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit

issuer_url, controller_listen, backchannel_url, fallback_csv, realm = sys.argv[1:]

def fail(message):
    print(f"customer-resource-plane-node: error: {message}", file=sys.stderr)
    raise SystemExit(1)

def reject_unsafe_text(value, label):
    if (
        any(character.isspace() for character in value)
        or "*" in value
        or "\\" in value
        or '"' in value
        or "'" in value
        or "%" in value
    ):
        fail(f"{label} must not contain whitespace, wildcard, quote, escape, or percent encoding")

def validate_dns_name(host, label):
    lowered = host.rstrip(".").lower()
    if (
        lowered == "localhost"
        or lowered.endswith(
            (
                ".internal",
                ".local",
                ".localhost",
                ".test",
                ".example",
                ".invalid",
            )
        )
    ):
        fail(f"{label} must use a public DNS name or globally routable IP")
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

def parse_customer_url(value, label, public):
    reject_unsafe_text(value, label)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(f"{label} is malformed")
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != f"/realms/{realm}"
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} must end at the exact customer realm")
    if not parsed.hostname:
        fail(f"{label} has no host")
    if public:
        if parsed.scheme != "https" or port is not None:
            fail(f"{label} must use HTTPS on implicit port 443")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            validate_dns_name(parsed.hostname, label)
        else:
            if not address.is_global:
                fail(f"{label} IP address must be globally routable")
    elif port is not None and not 1 <= port <= 65535:
        fail(f"{label} has an invalid port")

parse_customer_url(issuer_url, "customer OIDC issuer", public=True)

if controller_listen.startswith("["):
    closing = controller_listen.find("]")
    if closing < 0 or controller_listen[closing + 1:closing + 2] != ":":
        fail("customer controller listen must be a literal IP:port")
    address_text = controller_listen[1:closing]
    port_text = controller_listen[closing + 2:]
else:
    if controller_listen.count(":") != 1:
        fail("customer controller listen must be a literal IP:port")
    address_text, port_text = controller_listen.rsplit(":", 1)

try:
    address = ipaddress.ip_address(address_text)
    port = int(port_text, 10)
except ValueError:
    fail("customer controller listen must be a literal IP:port")
if str(address) != address_text.lower():
    fail("customer controller listen IP must use canonical notation")
if not 1024 <= port <= 65535 or str(port) != port_text:
    fail("customer controller listen must use a canonical non-privileged port")
if address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast:
    fail("customer controller listen must not be loopback, unspecified, link-local, or multicast")

if address.version == 4:
    allowed = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
    )
else:
    allowed = (ipaddress.ip_network("fc00::/7"),)
if not any(address in network for network in allowed):
    fail("customer controller listen must use private or CGNAT address space")

if backchannel_url:
    parse_customer_url(backchannel_url, "customer OIDC backchannel URL", public=False)

fallbacks = fallback_csv.split(",") if fallback_csv else []
if len(fallbacks) > 8:
    fail("at most eight customer OIDC backchannel fallback URLs are allowed")
if any(not value for value in fallbacks) or len(set(fallbacks)) != len(fallbacks):
    fail("customer OIDC backchannel fallback URLs must be non-empty and unique")
for index, value in enumerate(fallbacks, 1):
    parse_customer_url(
        value,
        f"customer OIDC backchannel fallback URL {index}",
        public=False,
    )
PY
}

validate_configuration() {
  validate_network_configuration
  resolve_token_source
}

render_environment() {
  printf 'HETERONETWORK_CUSTOMER_API_ENABLED=true\n'
  printf 'HETERONETWORK_CUSTOMER_API_LISTEN=%s\n' "$CUSTOMER_API_LISTEN"
  printf 'HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN=%s\n' "$controller_listen"
  printf 'HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=%s\n' "$issuer_url"
  printf 'HETERONETWORK_CUSTOMER_OIDC_CLIENT_ID=%s\n' "$CONSOLE_CLIENT_ID"
  printf 'HETERONETWORK_CUSTOMER_OIDC_AUDIENCE=%s\n' "$API_AUDIENCE"
  printf 'HETERONETWORK_CUSTOMER_OIDC_REQUIRED_ROLE=%s\n' "$REQUIRED_ROLE"
  printf 'HETERONETWORK_CUSTOMER_OIDC_SCOPES=%s\n' "$OIDC_SCOPES"
  if [[ -n "$backchannel_url" ]]; then
    printf 'HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL=%s\n' \
      "$backchannel_url"
  fi
  if [[ -n "$fallback_urls" ]]; then
    printf 'HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS=%s\n' \
      "$fallback_urls"
  fi
}

render_drop_in() {
  cat <<'EOF'
[Service]
EnvironmentFile=/etc/heteronetwork/customer-resource-plane/customer-resource-plane.env
LoadCredential=customer-controller.token:/etc/heteronetwork/customer-resource-plane/customer-controller.token
EOF
}

validate_template() {
  [[ -f "$TEMPLATE_PATH" && ! -L "$TEMPLATE_PATH" ]] \
    || die "customer resource-plane systemd drop-in template is missing"
  cmp -s "$TEMPLATE_PATH" <(render_drop_in) \
    || die "systemd drop-in template does not match the installer contract"
}

ensure_owned_directory() {
  local path="$1" mode="$2" label="$3" enforce_mode="$4"
  local uid existing_mode owner_uid owner_gid
  read -r owner_uid owner_gid < <(installation_owner_ids)
  validate_no_symlink_components "$path" "$label"
  if [[ -e "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] \
      || die "$label must be a non-symlink directory"
    uid="$(stat -c '%u' -- "$path")" \
      || die "unable to inspect $label"
    [[ "$uid" == "$owner_uid" ]] || die "$label must be owned by root"
    existing_mode="$(stat -c '%a' -- "$path")" \
      || die "unable to inspect $label mode"
    [[ "$existing_mode" =~ ^[0-7]{3,4}$ ]] \
      || die "$label has an invalid mode"
    if [[ "$enforce_mode" == "true" ]]; then
      chmod "$mode" "$path"
    else
      (( (8#$existing_mode & 0022) == 0 )) \
        || die "$label must not be writable by group or other"
    fi
  else
    install -d -o "$owner_uid" -g "$owner_gid" -m "$mode" "$path"
  fi
}

atomic_install_stdin() {
  local destination="$1" mode="$2" label="$3"
  local directory temporary owner_uid owner_gid
  directory="$(dirname -- "$destination")"
  read -r owner_uid owner_gid < <(installation_owner_ids)
  if [[ -e "$destination" || -L "$destination" ]]; then
    [[ -f "$destination" && ! -L "$destination" ]] \
      || die "$label destination must be a regular non-symlink file"
    [[ "$(stat -c '%h' -- "$destination")" == "1" ]] \
      || die "$label destination must have exactly one hard link"
  fi
  temporary="$(mktemp "$directory/.customer-resource-plane.XXXXXX")"
  trap 'rm -f -- "${temporary:-}"' RETURN
  install -o "$owner_uid" -g "$owner_gid" -m "$mode" /dev/stdin "$temporary"
  mv -fT -- "$temporary" "$destination"
  temporary=""
  trap - RETURN
}

validate_installed_regular_file() {
  local path="$1" expected_mode="$2" max_size="$3" label="$4"
  local uid links mode size owner_uid
  [[ -f "$path" && ! -L "$path" ]] \
    || die "$label is missing or is not a regular file"
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$path") \
    || die "unable to inspect $label"
  read -r owner_uid _ < <(installation_owner_ids)
  [[ "$uid" == "$owner_uid" && "$links" == "1" ]] \
    || die "$label has unsafe ownership or hard links"
  [[ "$mode" == "$expected_mode" || "$mode" == "0$expected_mode" ]] \
    || die "$label has an unsafe mode"
  ((10#$size > 0 && 10#$size <= max_size)) \
    || die "$label has an invalid size"
}

ensure_installed_token_compatible() {
  local current
  if [[ ! -e "$INSTALLED_TOKEN_PATH" && ! -L "$INSTALLED_TOKEN_PATH" ]]; then
    return
  fi
  current="$(
    read_valid_token_file "$INSTALLED_TOKEN_PATH" installed \
      "installed customer controller bearer token"
  )"
  [[ "$current" == "$validated_token" ]] \
    || die "installed customer controller token differs; disable before deliberate rotation"
}

install_token_copy() {
  if [[ -e "$INSTALLED_TOKEN_PATH" || -L "$INSTALLED_TOKEN_PATH" ]]; then
    ensure_installed_token_compatible
    chmod 0400 "$INSTALLED_TOKEN_PATH"
    return
  fi
  printf '%s\n' "$validated_token" \
    | atomic_install_stdin "$INSTALLED_TOKEN_PATH" 0400 \
      "customer controller bearer token"
}

control_plane_load_state() {
  systemctl show "$SERVICE_NAME" --property=LoadState --value 2>/dev/null \
    || true
}

require_loaded_control_plane() {
  local load_state
  require_command systemctl
  load_state="$(control_plane_load_state)"
  [[ "$load_state" == "loaded" ]] \
    || die "$SERVICE_NAME must already be loaded"
}

restart_if_active() {
  local was_active="$1"
  systemctl daemon-reload
  if [[ "$was_active" == "true" ]]; then
    systemctl restart "$SERVICE_NAME"
  fi
}

print_plan() {
  validate_configuration
  validate_template
  cat <<EOF
mode=dry-run
service=${SERVICE_NAME}
customer_api_enabled=true
customer_api_listen=${CUSTOMER_API_LISTEN}
customer_controller_listen=${controller_listen}
customer_oidc_issuer=${issuer_url}
customer_oidc_client_id=${CONSOLE_CLIENT_ID}
customer_oidc_audience=${API_AUDIENCE}
customer_oidc_required_role=${REQUIRED_ROLE}
customer_oidc_scopes=${OIDC_SCOPES}
customer_oidc_backchannel_configured=$([[ -n "$backchannel_url" ]] && printf true || printf false)
customer_oidc_fallback_count=$([[ -n "$fallback_urls" ]] && awk -F, '{print NF}' <<<"$fallback_urls" || printf 0)
controller_token=validated-redacted
environment_path=/etc/heteronetwork/customer-resource-plane/customer-resource-plane.env
credential_id=${CREDENTIAL_ID}
drop_in=/etc/systemd/system/${SERVICE_NAME}.d/40-customer-resource-plane.conf
restart_policy=restart-only-when-active
EOF
}

init_token() {
  [[ "$#" == "1" ]] || die "init-token requires exactly one OUTPUT_DIR"
  local output_dir="$1" token_path temporary existing
  local owner_uid owner_gid
  require_command openssl
  validate_no_symlink_components "$output_dir" "token output directory"

  if [[ -e "$output_dir" ]]; then
    [[ -d "$output_dir" && ! -L "$output_dir" ]] \
      || die "token output directory must be a non-symlink directory"
    [[ "$(stat -c '%u' -- "$output_dir")" == "$(id -u)" ]] \
      || die "token output directory must be owned by the current user"
    chmod 0700 "$output_dir"
  else
    install -d -m 0700 "$output_dir"
  fi
  owner_uid="$(stat -c '%u' -- "$output_dir")"
  owner_gid="$(stat -c '%g' -- "$output_dir")"
  token_path="${output_dir}/${TOKEN_FILENAME}"

  if [[ -e "$token_path" || -L "$token_path" ]]; then
    existing="$(read_valid_token_file "$token_path" source \
      "existing customer controller bearer token")"
    [[ -n "$existing" ]]
    printf 'Customer controller token already exists and was not changed: %s\n' \
      "$token_path"
    return
  fi

  temporary="$(mktemp "$output_dir/.customer-controller.token.XXXXXX")"
  trap 'rm -f -- "${temporary:-}"' RETURN
  openssl rand -hex 32 >"$temporary"
  chown "$owner_uid:$owner_gid" "$temporary"
  chmod 0400 "$temporary"
  if ! ln -- "$temporary" "$token_path" 2>/dev/null; then
    rm -f -- "$temporary"
    temporary=""
    existing="$(read_valid_token_file "$token_path" source \
      "existing customer controller bearer token")"
    [[ -n "$existing" ]]
    printf 'Customer controller token already exists and was not changed: %s\n' \
      "$token_path"
    trap - RETURN
    return
  fi
  rm -f -- "$temporary"
  temporary=""
  trap - RETURN
  [[ "$(stat -c '%h' -- "$token_path")" == "1" ]] \
    || die "generated token has an unsafe hard-link count"
  printf 'Customer controller token created: %s\n' "$token_path"
}

install_resource_plane() {
  require_root
  validate_configuration
  validate_template
  require_loaded_control_plane
  require_command install
  require_command mktemp

  local was_active=false
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    was_active=true
  fi

  ensure_owned_directory "$(root_path /etc/heteronetwork)" 0755 \
    "HeteroNetwork configuration directory" false
  ensure_owned_directory "$CONFIG_DIR" 0700 \
    "customer resource-plane configuration directory" true
  ensure_owned_directory "$(root_path /etc/systemd/system)" 0755 \
    "systemd configuration directory" false
  ensure_owned_directory "$DROP_IN_DIR" 0755 \
    "Control Plane drop-in directory" false

  ensure_installed_token_compatible
  render_environment \
    | atomic_install_stdin "$CONFIG_PATH" 0600 \
      "customer resource-plane environment"
  install_token_copy
  render_drop_in \
    | atomic_install_stdin "$DROP_IN_PATH" 0644 \
      "customer resource-plane systemd drop-in"

  validate_installed_regular_file "$CONFIG_PATH" 600 "$MAX_ENV_BYTES" \
    "installed customer resource-plane environment"
  read_valid_token_file "$INSTALLED_TOKEN_PATH" installed \
    "installed customer controller bearer token" >/dev/null
  validate_installed_regular_file "$DROP_IN_PATH" 644 4096 \
    "installed customer resource-plane systemd drop-in"
  cmp -s "$DROP_IN_PATH" "$TEMPLATE_PATH" \
    || die "installed systemd drop-in differs from the template"

  restart_if_active "$was_active"
  printf 'Customer resource plane enabled on %s.\n' "$controller_listen"
}

validate_removal_parent() {
  local path="$1" label="$2" owner_uid uid
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return
  fi
  validate_no_symlink_components "$path" "$label"
  [[ -d "$path" && ! -L "$path" ]] \
    || die "$label must be a non-symlink directory"
  read -r owner_uid _ < <(installation_owner_ids)
  uid="$(stat -c '%u' -- "$path")" || die "unable to inspect $label"
  [[ "$uid" == "$owner_uid" ]] || die "$label must be owned by root"
}

disable_resource_plane() {
  require_root
  require_loaded_control_plane
  validate_removal_parent "$CONFIG_DIR" \
    "customer resource-plane configuration directory"
  validate_removal_parent "$DROP_IN_DIR" \
    "Control Plane drop-in directory"

  local was_active=false
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    was_active=true
  fi
  rm -f -- "$DROP_IN_PATH" "$CONFIG_PATH" "$INSTALLED_TOKEN_PATH"
  rmdir -- "$CONFIG_DIR" 2>/dev/null || true
  rmdir -- "$DROP_IN_DIR" 2>/dev/null || true
  restart_if_active "$was_active"
  printf 'Customer resource plane disabled; the source token bundle was not changed.\n'
}

status_resource_plane() {
  require_command systemctl
  local load_state active_state privileged=false installed=false
  load_state="$(control_plane_load_state)"
  active_state="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
  if [[ -f "$DROP_IN_PATH" && ! -L "$DROP_IN_PATH" ]]; then
    installed=true
  fi
  if [[ "$(id -u)" == "0" ]]; then
    privileged=true
  fi

  printf 'service=%s\n' "$SERVICE_NAME"
  printf 'load_state=%s\n' "${load_state:-unknown}"
  printf 'active_state=%s\n' "${active_state:-unknown}"
  printf 'customer_resource_plane_installed=%s\n' "$installed"
  printf 'privileged_validation=%s\n' "$privileged"
  if [[ "$privileged" == "true" && "$installed" == "true" ]]; then
    if (
      validate_installed_regular_file "$CONFIG_PATH" 600 "$MAX_ENV_BYTES" \
        "installed customer resource-plane environment"
      read_valid_token_file "$INSTALLED_TOKEN_PATH" installed \
        "installed customer controller bearer token" >/dev/null
      validate_installed_regular_file "$DROP_IN_PATH" 644 4096 \
        "installed customer resource-plane systemd drop-in"
      cmp -s "$DROP_IN_PATH" "$TEMPLATE_PATH"
    ) >/dev/null 2>&1; then
      printf 'installed_files_secure=true\n'
    else
      printf 'installed_files_secure=false\n'
    fi
  else
    printf 'installed_files_secure=not-checked\n'
  fi
}

command_name="${1:-}"
if (($# > 0)); then
  shift
fi

case "$command_name" in
  init-token)
    init_token "$@"
    ;;
  validate-config)
    (($# == 0)) || die "validate-config accepts no arguments"
    validate_configuration
    validate_template
    printf 'Customer resource-plane configuration is valid.\n'
    ;;
  plan|--dry-run)
    (($# == 0)) || die "plan accepts no arguments"
    print_plan
    ;;
  install)
    (($# == 0)) || die "install accepts no arguments"
    install_resource_plane
    ;;
  disable)
    (($# == 0)) || die "disable accepts no arguments"
    disable_resource_plane
    ;;
  status)
    (($# == 0)) || die "status accepts no arguments"
    status_resource_plane
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
