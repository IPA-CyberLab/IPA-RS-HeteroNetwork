#!/bin/sh
set -eu
set -f

umask 077

agent_status_url=http://127.0.0.1:9780/v1/status
agent_service=heteronetwork-agent.service
gateway_service=heteronetwork-gateway.service
relay_service=heteronetwork-relay.service
control_plane_service=heteronetwork-control-plane.service
signal_service=heteronetwork-signal.service
stun_service=heteronetwork-stun.service
service_group=heteronetwork-services

# Tests use an isolated filesystem tree. Production always leaves this unset.
filesystem_root=${HETERONETWORK_PUBLIC_SERVICES_TEST_ROOT:-}
if [ -n "$filesystem_root" ]; then
  if [ "${HETERONETWORK_PUBLIC_SERVICES_TESTING:-0}" != 1 ]; then
    echo "Refusing a public-services filesystem override outside test mode" >&2
    exit 1
  fi
  case "$filesystem_root" in
    /*) ;;
    *)
      echo "Public-services test filesystem root must be absolute" >&2
      exit 1
      ;;
  esac
else
  if [ "$(id -u)" -ne 0 ]; then
    echo "Automatic public-service reconciliation must run as root" >&2
    exit 1
  fi
fi

public_services_dir=$filesystem_root/etc/heteronetwork/public-services
bootstrap_env=$public_services_dir/bootstrap.env
services_env=$public_services_dir/services.env
database_url_file=$public_services_dir/database-url
database_autopilot_token_file=$public_services_dir/database-autopilot.token
keycloak_autopilot_token_file=$public_services_dir/keycloak-autopilot.token
postgres_password_file=$filesystem_root/etc/heteronetwork/postgres-autopilot/bundle/secrets/application.password
postgres_ca_file=$filesystem_root/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt
agent_drop_in_dir=$filesystem_root/etc/systemd/system/heteronetwork-agent.service.d
agent_drop_in=$agent_drop_in_dir/30-public-services.conf
control_plane_drop_in_dir=$filesystem_root/etc/systemd/system/heteronetwork-control-plane.service.d
control_plane_enrollment_drop_in=$control_plane_drop_in_dir/40-node-enrollment.conf
node_enrollment_issuer_key=$filesystem_root/etc/credstore/node-enrollment-issuer.key
node_enrollment_relay_token=$filesystem_root/etc/heteronetwork/agent-relay-admission.token
runtime_dir=$filesystem_root/run/heteronetwork-public-services-autopilot

status_file=
relay_status_file=
gateway_status_file=
gateway_targets_current_public_ip=0
services_env_tmp=
database_url_tmp=
database_autopilot_token_tmp=
keycloak_autopilot_token_tmp=
agent_drop_in_tmp=
control_plane_enrollment_drop_in_tmp=
node_enrollment_enabled=0
reconcile_finished=0

log() {
  printf '%s\n' "public-services-autopilot: $*" >&2
}

cleanup() {
  [ -z "$status_file" ] || rm -f "$status_file"
  [ -z "$relay_status_file" ] || rm -f "$relay_status_file"
  [ -z "$gateway_status_file" ] || rm -f "$gateway_status_file"
  [ -z "$services_env_tmp" ] || rm -f "$services_env_tmp"
  [ -z "$database_url_tmp" ] || rm -f "$database_url_tmp"
  [ -z "$database_autopilot_token_tmp" ] ||
    rm -f "$database_autopilot_token_tmp"
  [ -z "$keycloak_autopilot_token_tmp" ] ||
    rm -f "$keycloak_autopilot_token_tmp"
  [ -z "$agent_drop_in_tmp" ] || rm -f "$agent_drop_in_tmp"
  [ -z "$control_plane_enrollment_drop_in_tmp" ] ||
    rm -f "$control_plane_enrollment_drop_in_tmp"
}

unit_is_active() {
  systemctl is-active --quiet "$1"
}

unit_is_loaded() {
  unit_load_state=$(systemctl show "$1" --property=LoadState --value 2>/dev/null) || return 1
  [ "$unit_load_state" = loaded ]
}

stop_unit() {
  stop_unit_name=$1
  if ! unit_is_active "$stop_unit_name"; then
    return 0
  fi
  if ! systemctl stop "$stop_unit_name"; then
    log "normal stop failed for $stop_unit_name; forcing termination"
  fi
  if ! unit_is_active "$stop_unit_name"; then
    return 0
  fi
  systemctl kill --kill-whom=all --signal=SIGKILL "$stop_unit_name" >/dev/null 2>&1 || true
  systemctl stop "$stop_unit_name" >/dev/null 2>&1 || true
  if unit_is_active "$stop_unit_name"; then
    log "$stop_unit_name remains active after forced termination"
    return 1
  fi
}

demote() {
  demote_reason=$1
  demote_changed=0
  demote_failed=0

  if unit_is_active "$control_plane_service"; then
    demote_changed=1
  fi
  stop_unit "$control_plane_service" || demote_failed=1

  if unit_is_active "$signal_service"; then
    demote_changed=1
  fi
  stop_unit "$signal_service" || demote_failed=1

  if unit_is_active "$stun_service"; then
    demote_changed=1
  fi
  stop_unit "$stun_service" || demote_failed=1

  drop_in_removed=0
  if [ -e "$agent_drop_in" ] || [ -L "$agent_drop_in" ]; then
    demote_changed=1
    if rm -f "$agent_drop_in"; then
      drop_in_removed=1
    else
      log "unable to remove the automatic public-service Agent routes"
      demote_failed=1
    fi
  fi
  if [ -e "$services_env" ] || [ -L "$services_env" ]; then
    demote_changed=1
    rm -f "$services_env" || demote_failed=1
  fi
  if [ -e "$database_url_file" ] || [ -L "$database_url_file" ]; then
    demote_changed=1
    rm -f "$database_url_file" || demote_failed=1
  fi
  if [ -e "$database_autopilot_token_file" ] ||
    [ -L "$database_autopilot_token_file" ]; then
    demote_changed=1
    rm -f "$database_autopilot_token_file" || demote_failed=1
  fi
  if [ -e "$keycloak_autopilot_token_file" ] ||
    [ -L "$keycloak_autopilot_token_file" ]; then
    demote_changed=1
    rm -f "$keycloak_autopilot_token_file" || demote_failed=1
  fi

  if [ "$drop_in_removed" -eq 1 ]; then
    if ! systemctl daemon-reload; then
      log "unable to reload systemd after removing automatic public-service routes"
      demote_failed=1
    elif ! systemctl restart "$agent_service"; then
      log "unable to restart the Agent after removing automatic public-service routes"
      demote_failed=1
    fi
  fi

  if [ "$demote_changed" -eq 1 ]; then
    log "demoted: $demote_reason"
  fi
  [ "$demote_failed" -eq 0 ]
}

demote_and_exit() {
  demote_exit_reason=$1
  if demote "$demote_exit_reason"; then
    reconcile_finished=1
    exit 0
  fi
  exit 1
}

on_exit() {
  exit_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$reconcile_finished" -ne 1 ]; then
    demote "reconciliation exited before reaching a stable state"
  fi
  cleanup
  exit "$exit_status"
}

trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

secure_bootstrap_file() {
  [ -f "$bootstrap_env" ] && [ ! -L "$bootstrap_env" ] || return 1
  bootstrap_metadata=$(stat -c '%u %a' "$bootstrap_env" 2>/dev/null) || return 1
  bootstrap_uid=${bootstrap_metadata%% *}
  bootstrap_mode=${bootstrap_metadata#* }
  case "$bootstrap_uid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  case "$bootstrap_mode" in
    ''|*[!0-7]*) return 1 ;;
  esac
  if [ -n "$filesystem_root" ]; then
    expected_bootstrap_uid=$(id -u)
  else
    expected_bootstrap_uid=0
  fi
  [ "$bootstrap_uid" -eq "$expected_bootstrap_uid" ] || return 1
  bootstrap_group_digit=$((bootstrap_mode / 10 % 10))
  bootstrap_world_digit=$((bootstrap_mode % 10))
  case "$bootstrap_group_digit:$bootstrap_world_digit" in
    2:*|3:*|6:*|7:*|*:2|*:3|*:6|*:7) return 1 ;;
  esac
}

decode_config_value() {
  decode_name=$1
  eval "decode_encoded=\${$decode_name-}"
  case "$decode_encoded" in
    *[!A-Za-z0-9+/=]*) return 1 ;;
  esac
  decode_value=$(printf '%s' "$decode_encoded" | base64 -d 2>/dev/null) || return 1
  decode_canonical=$(printf '%s' "$decode_value" | base64 | tr -d '\r\n')
  [ "$decode_canonical" = "$decode_encoded" ] || return 1
  DECODED_VALUE=$decode_value
}

valid_identifier() {
  valid_identifier_value=$1
  [ -n "$valid_identifier_value" ] &&
    [ "${#valid_identifier_value}" -le 255 ] &&
    case "$valid_identifier_value" in
      *[!A-Za-z0-9_.-]*) false ;;
      *) true ;;
    esac
}

valid_positive_integer() {
  valid_integer_value=$1
  valid_integer_max=$2
  case "$valid_integer_value" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$valid_integer_value" -ge 1 ] && [ "$valid_integer_value" -le "$valid_integer_max" ]
}

valid_autopilot_bearer_token() {
  valid_token_value=$1
  [ "${#valid_token_value}" -eq 64 ] || return 1
  case "$valid_token_value" in
    *[!0-9a-f]*) return 1 ;;
  esac
}

valid_ipv4() {
  printf '%s\n' "$1" | awk -F. '
    NF != 4 { exit 1 }
    {
      for (i = 1; i <= 4; i++) {
        if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) {
          exit 1
        }
      }
    }
  '
}

valid_ipv6() {
  printf '%s\n' "$1" | awk '
    {
      address = $0
      if (address !~ /^[0-9A-Fa-f:]+$/ || index(address, ":::") != 0) {
        exit 1
      }

      remainder = address
      compressed = 0
      while ((position = index(remainder, "::")) != 0) {
        compressed++
        remainder = substr(remainder, position + 2)
      }
      if (compressed > 1) {
        exit 1
      }

      count = split(address, groups, ":")
      hextets = 0
      for (index_value = 1; index_value <= count; index_value++) {
        if (groups[index_value] == "") {
          continue
        }
        if (length(groups[index_value]) > 4 ||
            groups[index_value] !~ /^[0-9A-Fa-f]+$/) {
          exit 1
        }
        hextets++
      }

      if (compressed == 1) {
        if (hextets >= 8) {
          exit 1
        }
      } else {
        if (substr(address, 1, 1) == ":" ||
            substr(address, length(address), 1) == ":" ||
            hextets != 8) {
          exit 1
        }
      }
    }
  '
}

valid_ipv4_cidr() {
  valid_cidr_value=$1
  case "$valid_cidr_value" in
    */*) ;;
    *) return 1 ;;
  esac
  valid_cidr_ip=${valid_cidr_value%/*}
  valid_cidr_prefix=${valid_cidr_value##*/}
  valid_ipv4 "$valid_cidr_ip" || return 1
  case "$valid_cidr_prefix" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$valid_cidr_prefix" -le 32 ]
}

valid_public_key() {
  valid_key_value=$1
  case "$valid_key_value" in
    *[!A-Za-z0-9+/=]*|'') return 1 ;;
  esac
  valid_key_bytes=$(printf '%s' "$valid_key_value" | base64 -d 2>/dev/null | wc -c) ||
    return 1
  [ "$valid_key_bytes" -eq 32 ] || return 1
  valid_key_canonical=$(printf '%s' "$valid_key_value" | base64 -d 2>/dev/null |
    base64 | tr -d '\r\n') || return 1
  [ "$valid_key_canonical" = "$valid_key_value" ]
}

secure_root_credential() {
  credential_path=$1
  credential_min_bytes=$2
  credential_max_bytes=$3
  [ -f "$credential_path" ] && [ ! -L "$credential_path" ] || return 1
  credential_metadata=$(stat -c '%u %a %h %s' "$credential_path" 2>/dev/null) ||
    return 1
  set -- $credential_metadata
  [ "$#" -eq 4 ] || return 1
  credential_uid=$1
  credential_mode=$2
  credential_links=$3
  credential_size=$4
  if [ -n "$filesystem_root" ]; then
    credential_expected_uid=$(id -u)
  else
    credential_expected_uid=0
  fi
  [ "$credential_uid" -eq "$credential_expected_uid" ] || return 1
  [ "$credential_links" -eq 1 ] || return 1
  [ "$credential_size" -ge "$credential_min_bytes" ] &&
    [ "$credential_size" -le "$credential_max_bytes" ] || return 1
  credential_owner_digit=$((credential_mode / 100 % 10))
  credential_group_digit=$((credential_mode / 10 % 10))
  credential_world_digit=$((credential_mode % 10))
  case "$credential_owner_digit:$credential_group_digit:$credential_world_digit" in
    4:0:0|6:0:0) ;;
    *) return 1 ;;
  esac
}

detect_node_enrollment_credentials() {
  node_enrollment_enabled=0
  if [ ! -e "$node_enrollment_issuer_key" ] &&
    [ ! -L "$node_enrollment_issuer_key" ]; then
    return 0
  fi
  if ! secure_root_credential "$node_enrollment_issuer_key" 43 128; then
    log "ignoring an unsafe node-enrollment issuer credential"
    return 0
  fi
  enrollment_private_key=$(tr -d '\r\n' <"$node_enrollment_issuer_key") || return 1
  if ! valid_public_key "$enrollment_private_key"; then
    log "ignoring an invalid node-enrollment issuer credential"
    return 0
  fi
  enrollment_private_key=
  if ! secure_root_credential "$node_enrollment_relay_token" 32 513; then
    log "node enrollment remains disabled without a secure Relay admission credential"
    return 0
  fi
  enrollment_relay_token=$(tr -d '\r\n' <"$node_enrollment_relay_token") || return 1
  if [ "${#enrollment_relay_token}" -lt 32 ] ||
    [ "${#enrollment_relay_token}" -gt 512 ]; then
    enrollment_relay_token=
    log "node enrollment remains disabled with an invalid Relay admission credential"
    return 0
  fi
  case "$enrollment_relay_token" in
    *[!A-Za-z0-9._~+/=-]*)
      enrollment_relay_token=
      log "node enrollment remains disabled with an invalid Relay admission credential"
      return 0
      ;;
  esac
  enrollment_relay_token=
  node_enrollment_enabled=1
}

valid_http_url() {
  valid_url_value=$1
  [ -n "$valid_url_value" ] && [ "${#valid_url_value}" -le 2048 ] || return 1
  case "$valid_url_value" in
    http://*|https://*) ;;
    *) return 1 ;;
  esac
  case "$valid_url_value" in
    *[!A-Za-z0-9:/?._~%+@,\&=\#\[\]-]*) return 1 ;;
  esac
}

valid_url_csv() {
  valid_url_csv_value=$1
  valid_url_csv_allow_empty=$2
  if [ -z "$valid_url_csv_value" ]; then
    [ "$valid_url_csv_allow_empty" -eq 1 ]
    return
  fi
  case "$valid_url_csv_value" in
    ,*|*,|*,,*) return 1 ;;
  esac
  valid_url_old_ifs=$IFS
  IFS=,
  set -- $valid_url_csv_value
  IFS=$valid_url_old_ifs
  [ "$#" -gt 0 ] || return 1
  for valid_url_entry do
    valid_http_url "$valid_url_entry" || return 1
  done
}

valid_trusted_issuer_keys() {
  valid_trusted_value=$1
  [ -z "$valid_trusted_value" ] && return 0
  valid_trusted_old_ifs=$IFS
  IFS=';'
  set -- $valid_trusted_value
  IFS=$valid_trusted_old_ifs
  for valid_trusted_entry do
    [ "$(printf '%s\n' "$valid_trusted_entry" | awk -F, '{ print NF }')" -eq 3 ] ||
      return 1
    valid_trusted_issuer=
    valid_trusted_key_id=
    valid_trusted_public_key=
    valid_trusted_extra=
    IFS=, read -r valid_trusted_issuer valid_trusted_key_id \
      valid_trusted_public_key valid_trusted_extra <<EOF
$valid_trusted_entry
EOF
    [ -z "$valid_trusted_extra" ] || return 1
    valid_identifier "$valid_trusted_issuer" || return 1
    valid_identifier "$valid_trusted_key_id" || return 1
    valid_public_key "$valid_trusted_public_key" || return 1
  done
}

valid_enrollment_trusted_issuer_keys() {
  valid_enrollment_value=$1
  [ -n "$valid_enrollment_value" ] || return 1
  valid_enrollment_old_ifs=$IFS
  IFS=';'
  set -- $valid_enrollment_value
  IFS=$valid_enrollment_old_ifs
  [ "$#" -gt 0 ] || return 1
  for valid_enrollment_entry do
    [ "$(printf '%s\n' "$valid_enrollment_entry" | awk -F, '{ print NF }')" -eq 4 ] ||
      return 1
    valid_enrollment_issuer=
    valid_enrollment_key_id=
    valid_enrollment_public_key=
    valid_enrollment_ttl=
    valid_enrollment_extra=
    IFS=, read -r valid_enrollment_issuer valid_enrollment_key_id \
      valid_enrollment_public_key valid_enrollment_ttl valid_enrollment_extra <<EOF
$valid_enrollment_entry
EOF
    [ -z "$valid_enrollment_extra" ] || return 1
    valid_identifier "$valid_enrollment_issuer" || return 1
    valid_identifier "$valid_enrollment_key_id" || return 1
    valid_public_key "$valid_enrollment_public_key" || return 1
    valid_positive_integer "$valid_enrollment_ttl" 2592000 || return 1
    [ "$valid_enrollment_ttl" -ge 300 ] || return 1
  done
}

load_bootstrap() {
  secure_bootstrap_file || return 1

  unset \
    HETERONETWORK_PUBLIC_SERVICES_CLUSTER_ID_B64 \
    HETERONETWORK_PUBLIC_SERVICES_VPN_POOL_B64 \
    HETERONETWORK_PUBLIC_SERVICES_ISSUER_NODE_ID_B64 \
    HETERONETWORK_PUBLIC_SERVICES_ISSUER_KEY_ID_B64 \
    HETERONETWORK_PUBLIC_SERVICES_ISSUER_PUBLIC_KEY_B64 \
    HETERONETWORK_PUBLIC_SERVICES_TRUSTED_ISSUER_KEYS_B64 \
    HETERONETWORK_PUBLIC_SERVICES_ENROLLMENT_TRUSTED_ISSUER_KEY_B64 \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64 \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_CLIENT_ID_B64 \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_AUTH_BASE_URL_B64 \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_BASE_URL_B64 \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64 \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_SCOPES_B64 \
    HETERONETWORK_PUBLIC_SERVICES_CONTROL_PLANE_URLS_B64 \
    HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN \
    HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN \
    HETERONETWORK_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS \
    HETERONETWORK_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS

  # bootstrap.env is root-owned, non-writable by group/other, and contains only
  # installer-generated assignments.
  . "$bootstrap_env"

  decode_config_value HETERONETWORK_PUBLIC_SERVICES_CLUSTER_ID_B64 || return 1
  cluster_id=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_VPN_POOL_B64 || return 1
  vpn_pool=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_ISSUER_NODE_ID_B64 || return 1
  issuer_node_id=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_ISSUER_KEY_ID_B64 || return 1
  issuer_key_id=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_ISSUER_PUBLIC_KEY_B64 || return 1
  issuer_public_key=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_TRUSTED_ISSUER_KEYS_B64 || return 1
  trusted_issuer_keys=$DECODED_VALUE
  decode_config_value \
    HETERONETWORK_PUBLIC_SERVICES_ENROLLMENT_TRUSTED_ISSUER_KEY_B64 || return 1
  enrollment_trusted_issuer_keys=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_OIDC_ISSUER_URL_B64 || return 1
  oidc_issuer_url=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_OIDC_CLIENT_ID_B64 || return 1
  oidc_client_id=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_OIDC_AUTH_BASE_URL_B64 || return 1
  oidc_auth_base_url=$DECODED_VALUE
  decode_config_value \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_BASE_URL_B64 || return 1
  oidc_backchannel_base_url=$DECODED_VALUE
  decode_config_value \
    HETERONETWORK_PUBLIC_SERVICES_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS_B64 || return 1
  oidc_backchannel_fallback_base_urls=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_OIDC_SCOPES_B64 || return 1
  oidc_scopes=$DECODED_VALUE
  decode_config_value HETERONETWORK_PUBLIC_SERVICES_CONTROL_PLANE_URLS_B64 || return 1
  bootstrap_control_plane_urls=$DECODED_VALUE

  database_autopilot_bearer_token=${HETERONETWORK_PUBLIC_SERVICES_DATABASE_AUTOPILOT_BEARER_TOKEN-}
  keycloak_autopilot_bearer_token=${HETERONETWORK_PUBLIC_SERVICES_KEYCLOAK_AUTOPILOT_BEARER_TOKEN-}
  reconcile_interval_seconds=${HETERONETWORK_PUBLIC_SERVICES_RECONCILE_INTERVAL_SECONDS-}
  classification_max_age_seconds=${HETERONETWORK_PUBLIC_SERVICES_CLASSIFICATION_MAX_AGE_SECONDS-}

  valid_identifier "$cluster_id" || return 1
  valid_ipv4_cidr "$vpn_pool" || return 1
  valid_identifier "$issuer_node_id" || return 1
  valid_identifier "$issuer_key_id" || return 1
  valid_public_key "$issuer_public_key" || return 1
  valid_trusted_issuer_keys "$trusted_issuer_keys" || return 1
  valid_enrollment_trusted_issuer_keys "$enrollment_trusted_issuer_keys" || return 1
  valid_http_url "$oidc_issuer_url" || return 1
  valid_identifier "$oidc_client_id" || return 1
  if [ -n "$oidc_auth_base_url" ]; then
    valid_http_url "$oidc_auth_base_url" || return 1
  fi
  if [ -n "$oidc_backchannel_base_url" ]; then
    valid_http_url "$oidc_backchannel_base_url" || return 1
  fi
  valid_url_csv "$oidc_backchannel_fallback_base_urls" 1 || return 1
  case "$oidc_scopes" in
    ''|*[!A-Za-z0-9_.:\ -]*) return 1 ;;
  esac
  valid_url_csv "$bootstrap_control_plane_urls" 0 || return 1
  valid_autopilot_bearer_token "$database_autopilot_bearer_token" || return 1
  valid_autopilot_bearer_token "$keycloak_autopilot_bearer_token" || return 1
  valid_positive_integer "$reconcile_interval_seconds" 300 || return 1
  valid_positive_integer "$classification_max_age_seconds" 300 || return 1
}

postgres_proxy_is_ready() {
  if command -v pg_isready >/dev/null 2>&1; then
    pg_isready -q -h 127.0.0.1 -p 25432 -t 3 >/dev/null 2>&1
    return
  fi
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 3 127.0.0.1 25432 >/dev/null 2>&1
    return
  fi
  log "neither pg_isready nor nc is available to validate PostgreSQL HA"
  return 1
}

relay_is_ready() {
  relay_status_file=$(mktemp "$runtime_dir/relay-status.XXXXXX") || return 1
  if ! curl --fail --silent --show-error --max-time 5 --max-filesize 1048576 \
    "$relay_status_url" >"$relay_status_file"; then
    return 1
  fi
  if ! jq -e \
    --arg node_id "$node_id" \
    --arg public_endpoint "$relay_public_endpoint" \
    --arg admission_url "$relay_admission_url" '
      (.relay_node == $node_id)
      and (.health == "healthy")
      and (.capability | type == "object")
      and (.capability.enabled_by_policy == true)
      and (.capability.public_endpoint == $public_endpoint)
      and (.capability.admission_url == $admission_url)
    ' "$relay_status_file" >/dev/null; then
    return 1
  fi
  rm -f "$relay_status_file"
  relay_status_file=
}

gateway_is_ready() {
  gateway_targets_current_public_ip=0
  gateway_status_file=$(mktemp "$runtime_dir/gateway-status.XXXXXX") || return 1
  if ! curl --fail --silent --show-error --max-time 6 --max-filesize 1048576 \
    http://127.0.0.1:9780/v1/web-ui/endpoints >"$gateway_status_file"; then
    rm -f "$gateway_status_file"
    gateway_status_file=
    return 1
  fi
  if jq -e --arg public_ip "$public_ip" --arg public_url "$public_https_url" '
    (.public_gateway.public_ip == $public_ip)
    and (.public_gateway.url | type == "string")
    and ((.public_gateway.url | rtrimstr("/")) == $public_url)
  ' "$gateway_status_file" >/dev/null; then
    gateway_targets_current_public_ip=1
  fi
  if ! jq -e --arg public_ip "$public_ip" '
    (.public_gateway.phase == "ready")
    and (.public_gateway.public_ip == $public_ip)
    and (.public_gateway.url | type == "string" and startswith("https://"))
  ' "$gateway_status_file" >/dev/null; then
    rm -f "$gateway_status_file"
    gateway_status_file=
    return 1
  fi
  rm -f "$gateway_status_file"
  gateway_status_file=
}

wait_gateway_ready() {
  gateway_wait_attempt=1
  while [ "$gateway_wait_attempt" -le 6 ]; do
    if gateway_is_ready; then
      return 0
    fi
    gateway_wait_attempt=$((gateway_wait_attempt + 1))
    sleep 1
  done
  return 1
}

write_environment_entry() {
  environment_name=$1
  environment_value=$2
  environment_escaped=$(printf '%s' "$environment_value" |
    sed 's/\\/\\\\/g; s/"/\\"/g')
  printf '%s="%s"\n' "$environment_name" "$environment_escaped"
}

install_candidate() {
  candidate_tmp=$1
  candidate_path=$2
  candidate_owner=$3
  candidate_mode=$4
  chown "$candidate_owner" "$candidate_tmp" || return 1
  chmod "$candidate_mode" "$candidate_tmp" || return 1
  if [ -f "$candidate_path" ] && [ ! -L "$candidate_path" ] &&
    cmp -s "$candidate_tmp" "$candidate_path"; then
    chown "$candidate_owner" "$candidate_path" || return 1
    chmod "$candidate_mode" "$candidate_path" || return 1
    rm -f "$candidate_tmp"
    CANDIDATE_CHANGED=0
    return 0
  fi
  mv -f "$candidate_tmp" "$candidate_path" || return 1
  CANDIDATE_CHANGED=1
}

install_root_credential_candidate() {
  credential_tmp=$1
  credential_path=$2

  chown root:root "$credential_tmp" || return 1
  chmod 0400 "$credential_tmp" || return 1

  if [ -n "$filesystem_root" ]; then
    credential_expected_uid=$(id -u)
    credential_expected_gid=$(id -g)
  else
    credential_expected_uid=0
    credential_expected_gid=0
  fi
  credential_expected_metadata="$credential_expected_uid $credential_expected_gid 400 1"

  if [ -L "$credential_path" ]; then
    return 1
  fi
  if [ -e "$credential_path" ] && [ ! -f "$credential_path" ]; then
    return 1
  fi
  if [ -f "$credential_path" ]; then
    credential_metadata=$(stat -c '%u %g %a %h' "$credential_path" 2>/dev/null) ||
      return 1
    if [ "$credential_metadata" = "$credential_expected_metadata" ] &&
      cmp -s "$credential_tmp" "$credential_path"; then
      rm -f "$credential_tmp"
      CANDIDATE_CHANGED=0
      return 0
    fi
  fi

  mv -fT "$credential_tmp" "$credential_path" || return 1
  credential_metadata=$(stat -c '%u %g %a %h' "$credential_path" 2>/dev/null) ||
    return 1
  [ "$credential_metadata" = "$credential_expected_metadata" ] || return 1
  CANDIDATE_CHANGED=1
}

prepare_runtime_files() {
  mkdir -p "$public_services_dir" "$agent_drop_in_dir" \
    "$control_plane_drop_in_dir" || return 1
  chown root:"$service_group" "$public_services_dir" || return 1
  chmod 0750 "$public_services_dir" || return 1
  chown root:root "$agent_drop_in_dir" || return 1
  chmod 0755 "$agent_drop_in_dir" || return 1
  chown root:root "$control_plane_drop_in_dir" || return 1
  chmod 0755 "$control_plane_drop_in_dir" || return 1

  if [ "$node_enrollment_enabled" -eq 1 ]; then
    control_plane_enrollment_drop_in_tmp=$(
      mktemp "$control_plane_drop_in_dir/.40-node-enrollment.conf.XXXXXX"
    ) || return 1
    cat >"$control_plane_enrollment_drop_in_tmp" <<'EOF' || return 1
[Service]
LoadCredential=node-enrollment-issuer.key:/etc/credstore/node-enrollment-issuer.key
LoadCredential=node-enrollment-relay-admission.token:/etc/heteronetwork/agent-relay-admission.token
EOF
    install_candidate "$control_plane_enrollment_drop_in_tmp" \
      "$control_plane_enrollment_drop_in" root:root 0644 || return 1
    control_plane_enrollment_drop_in_tmp=
    control_plane_enrollment_drop_in_changed=$CANDIDATE_CHANGED
  elif [ -e "$control_plane_enrollment_drop_in" ] ||
    [ -L "$control_plane_enrollment_drop_in" ]; then
    rm -f "$control_plane_enrollment_drop_in" || return 1
    control_plane_enrollment_drop_in_changed=1
  else
    control_plane_enrollment_drop_in_changed=0
  fi

  services_env_tmp=$(mktemp "$public_services_dir/.services.env.XXXXXX") || return 1
  {
    write_environment_entry HETERONETWORK_CLUSTER_ID "$cluster_id"
    write_environment_entry HETERONETWORK_VPN_POOL "$vpn_pool"
    write_environment_entry HETERONETWORK_ISSUER_NODE_ID "$issuer_node_id"
    write_environment_entry HETERONETWORK_ISSUER_KEY_ID "$issuer_key_id"
    write_environment_entry HETERONETWORK_ISSUER_PUBLIC_KEY "$issuer_public_key"
    if [ -n "$trusted_issuer_keys" ]; then
      write_environment_entry HETERONETWORK_TRUSTED_ISSUER_KEYS "$trusted_issuer_keys"
    fi
    write_environment_entry \
      HETERONETWORK_TRUSTED_NODE_ENROLLMENT_ISSUER_KEYS \
      "$enrollment_trusted_issuer_keys"
    write_environment_entry HETERONETWORK_LISTEN "$vpn_ip:19088"
    write_environment_entry HETERONETWORK_SIGNAL_LISTEN "127.0.0.1:19443"
    write_environment_entry \
      HETERONETWORK_SIGNAL_CONTROL_PLANE_URLS \
      "$signal_control_plane_urls"
    write_environment_entry HETERONETWORK_STUN_LISTEN "$stun_listen"
    write_environment_entry HETERONETWORK_STUN_HTTP_LISTEN "$vpn_ip:19446"
    write_environment_entry HETERONETWORK_SERVICE_INSTANCE_ID \
      "auto-services-$node_id"
    write_environment_entry HETERONETWORK_SERVICE_OWNER_HOST_ID "$node_id"
    write_environment_entry HETERONETWORK_SERVICE_OWNER_NODE_ID "$node_id"
    write_environment_entry HETERONETWORK_SERVICE_LEASE_TTL_SECONDS 30
    write_environment_entry HETERONETWORK_SERVICE_LEASE_RENEW_INTERVAL_SECONDS 10
    write_environment_entry HETERONETWORK_ADVERTISE_CONTROL_PLANE_URL \
      "http://$vpn_ip:19088"
    write_environment_entry HETERONETWORK_ADVERTISE_SIGNAL_URL "$public_https_url"
    write_environment_entry HETERONETWORK_ADVERTISE_STUN_URL \
      "$stun_public_url"
    write_environment_entry HETERONETWORK_ADVERTISE_RELAY_URL \
      "$relay_public_url"
    write_environment_entry HETERONETWORK_ADVERTISE_WEB_UI_URL \
      "http://$vpn_ip:19088"
    write_environment_entry HETERONETWORK_WEB_UI_ENABLED true
    write_environment_entry HETERONETWORK_DYNAMIC_WEB_GATEWAY_ENABLED false
    if [ "$node_enrollment_enabled" -eq 1 ]; then
      write_environment_entry HETERONETWORK_NODE_ENROLLMENT_ENABLED true
      write_environment_entry HETERONETWORK_NODE_ENROLLMENT_ISSUER_KEY_ID web-enrollment
      write_environment_entry HETERONETWORK_NODE_ENROLLMENT_MAX_TTL_SECONDS 604800
      write_environment_entry HETERONETWORK_NODE_ENROLLMENT_BINARY_PATH \
        /opt/heteronetwork/bin/iparsd
      write_environment_entry HETERONETWORK_NODE_ENROLLMENT_CLI_BINARY_PATH \
        /opt/heteronetwork/bin/ipars
      write_environment_entry HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_PATH \
        /run/credentials/heteronetwork-control-plane.service/node-enrollment-relay-admission.token
    else
      write_environment_entry HETERONETWORK_NODE_ENROLLMENT_ENABLED false
    fi
    write_environment_entry HETERONETWORK_WEB_AUTH_PROVIDER keycloak
    write_environment_entry HETERONETWORK_WEB_PUBLIC_URL \
      "http://$vpn_ip:19088"
    write_environment_entry HETERONETWORK_WEB_OIDC_ISSUER_URL "$oidc_issuer_url"
    write_environment_entry HETERONETWORK_WEB_OIDC_CLIENT_ID "$oidc_client_id"
    write_environment_entry HETERONETWORK_WEB_OIDC_SCOPES "$oidc_scopes"
    if [ -n "$oidc_auth_base_url" ]; then
      write_environment_entry HETERONETWORK_WEB_OIDC_AUTH_BASE_URL "$oidc_auth_base_url"
    fi
    if [ -n "$oidc_backchannel_base_url" ]; then
      write_environment_entry \
        HETERONETWORK_WEB_OIDC_BACKCHANNEL_BASE_URL \
        "$oidc_backchannel_base_url"
    fi
    if [ -n "$oidc_backchannel_fallback_base_urls" ]; then
      write_environment_entry \
        HETERONETWORK_WEB_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS \
        "$oidc_backchannel_fallback_base_urls"
    fi
  } >"$services_env_tmp" || return 1
  install_candidate "$services_env_tmp" "$services_env" \
    "root:$service_group" 0640 || return 1
  services_env_tmp=
  services_env_changed=$CANDIDATE_CHANGED

  database_url_tmp=$(mktemp "$public_services_dir/.database-url.XXXXXX") || return 1
  printf '%s\n' \
    "postgresql://heteronetwork:$database_password@postgres.heteronetwork.internal:25432/heteronetwork?sslmode=verify-full&sslrootcert=$postgres_ca_file" \
    >"$database_url_tmp" || return 1
  install_candidate "$database_url_tmp" "$database_url_file" \
    root:root 0400 || return 1
  database_url_tmp=
  database_url_changed=$CANDIDATE_CHANGED

  database_autopilot_token_tmp=$(
    mktemp "$public_services_dir/.database-autopilot.token.XXXXXX"
  ) || return 1
  printf '%s\n' "$database_autopilot_bearer_token" \
    >"$database_autopilot_token_tmp" || return 1
  install_root_credential_candidate \
    "$database_autopilot_token_tmp" \
    "$database_autopilot_token_file" || return 1
  database_autopilot_token_tmp=
  database_autopilot_token_changed=$CANDIDATE_CHANGED

  keycloak_autopilot_token_tmp=$(
    mktemp "$public_services_dir/.keycloak-autopilot.token.XXXXXX"
  ) || return 1
  printf '%s\n' "$keycloak_autopilot_bearer_token" \
    >"$keycloak_autopilot_token_tmp" || return 1
  install_root_credential_candidate \
    "$keycloak_autopilot_token_tmp" \
    "$keycloak_autopilot_token_file" || return 1
  keycloak_autopilot_token_tmp=
  keycloak_autopilot_token_changed=$CANDIDATE_CHANGED

  agent_drop_in_tmp=$(mktemp "$agent_drop_in_dir/.30-public-services.conf.XXXXXX") ||
    return 1
  cat >"$agent_drop_in_tmp" <<EOF || return 1
[Service]
Environment="HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_CONTROL_PLANE_UPSTREAM=$vpn_ip:19088"
Environment="HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_SIGNAL_UPSTREAM=127.0.0.1:19443"
Environment="HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_RELAY_ADMISSION_UPSTREAM=$vpn_ip:18447"
EOF
  install_candidate "$agent_drop_in_tmp" "$agent_drop_in" root:root 0644 || return 1
  agent_drop_in_tmp=
  agent_drop_in_changed=$CANDIDATE_CHANGED
}

promote() {
  runtime_configuration_changed=0
  if [ "$services_env_changed" -eq 1 ] ||
    [ "$database_url_changed" -eq 1 ] ||
    [ "$database_autopilot_token_changed" -eq 1 ] ||
    [ "$keycloak_autopilot_token_changed" -eq 1 ] ||
    [ "$control_plane_enrollment_drop_in_changed" -eq 1 ]; then
    runtime_configuration_changed=1
  fi

  if [ "$control_plane_enrollment_drop_in_changed" -eq 1 ]; then
    systemctl daemon-reload || return 1
  fi

  if [ "$runtime_configuration_changed" -eq 1 ]; then
    stop_unit "$control_plane_service" || return 1
    stop_unit "$signal_service" || return 1
    stop_unit "$stun_service" || return 1
  fi

  if [ "$agent_drop_in_changed" -eq 1 ]; then
    systemctl daemon-reload || return 1
    systemctl restart --no-block "$agent_service" || return 1
    log "staged automatic public-service Agent routes; activation continues next cycle"
    return 0
  fi

  unit_is_active "$agent_service" || return 1
  unit_is_active "$gateway_service" || return 1
  unit_is_active "$relay_service" || return 1
  wait_gateway_ready || return 1
  relay_is_ready || return 1

  if ! unit_is_active "$signal_service"; then
    systemctl start "$signal_service" || return 1
  elif [ "$runtime_configuration_changed" -eq 1 ]; then
    systemctl restart "$signal_service" || return 1
  fi
  unit_is_active "$signal_service" || return 1

  if ! unit_is_active "$stun_service"; then
    systemctl start "$stun_service" || return 1
  elif [ "$runtime_configuration_changed" -eq 1 ]; then
    systemctl restart "$stun_service" || return 1
  fi
  unit_is_active "$stun_service" || return 1

  if ! unit_is_active "$control_plane_service"; then
    systemctl start "$control_plane_service" || return 1
  elif [ "$runtime_configuration_changed" -eq 1 ]; then
    systemctl restart "$control_plane_service" || return 1
  fi
  unit_is_active "$control_plane_service" || return 1

  if [ "$runtime_configuration_changed" -eq 1 ] ||
    [ "$agent_drop_in_changed" -eq 1 ]; then
    log "promoted node to automatic Control Plane, Signal, and STUN services"
  fi
}

if ! load_bootstrap; then
  demote_and_exit "bootstrap configuration is missing or invalid"
fi

for required_unit in \
  "$agent_service" \
  "$gateway_service" \
  "$relay_service" \
  "$control_plane_service" \
  "$signal_service" \
  "$stun_service"; do
  if ! unit_is_loaded "$required_unit"; then
    demote_and_exit "required systemd unit is unavailable"
  fi
done

if ! unit_is_active "$agent_service"; then
  demote_and_exit "Agent dependency is not active"
fi
if ! unit_is_active "$gateway_service"; then
  demote_and_exit "Caddy gateway dependency is not active"
fi
if ! unit_is_active "$relay_service"; then
  demote_and_exit "Relay dependency is not active"
fi

mkdir -p "$runtime_dir"
chmod 0700 "$runtime_dir"
status_file=$(mktemp "$runtime_dir/status.XXXXXX")
if ! curl --fail --silent --show-error --max-time 5 --max-filesize 1048576 \
  "$agent_status_url" >"$status_file"; then
  demote_and_exit "local Agent status is unavailable"
fi

if ! jq -e --argjson max_age "$classification_max_age_seconds" '
  . as $status
  | .nat_classification as $nat
  | (try ($nat.assessed_at
      | sub("\\.[0-9]+Z$"; "Z")
      | fromdateiso8601) catch null) as $assessed
  | ($status.node_id
      | type == "string"
        and length > 0
        and length <= 255
        and test("^[A-Za-z0-9_.-]+$"))
    and ($status.vpn_ip
      | type == "string"
        and length > 0
        and length <= 64
        and test("^[0-9A-Fa-f:.]+$"))
    and ($nat | type == "object")
    and ($nat.local_addr | type == "string")
    and ($nat.observations | type == "array" and length > 0)
    and (
      (($nat.connectivity_state == "public")
        and ($nat.mapping_behavior == "no_nat")
        and ($nat.strategy == "direct_candidate")
        and ($nat.observed_endpoint == $nat.local_addr)
        and all($nat.observations[];
          .local_addr == $nat.local_addr
          and .reflexive_addr == $nat.local_addr))
      or
      (($nat.connectivity_state == "mapped_public")
        and ($nat.mapping_behavior == "endpoint_independent")
        and ($nat.observed_endpoint | type == "string")
        and ($nat.observed_endpoint != $nat.local_addr)
        and all($nat.observations[]; .local_addr == $nat.local_addr))
    )
    and ($assessed != null)
    and ($assessed <= (now + 5))
    and ($assessed >= (now - $max_age))
' "$status_file" >/dev/null; then
  demote_and_exit "direct-public NAT classification is absent, inconsistent, or stale"
fi

node_id=$(jq -er '.node_id' "$status_file") ||
  demote_and_exit "Agent node identity is invalid"
vpn_ip=$(jq -er '.vpn_ip' "$status_file") ||
  demote_and_exit "Agent VPN address is invalid"
nat_local_addr=$(jq -er '
  .nat_classification
  | if .connectivity_state == "mapped_public" then
      .observed_endpoint
    else
      .local_addr
    end
' "$status_file") ||
  demote_and_exit "Agent public endpoint is invalid"

case "$nat_local_addr" in
  \[*)
    public_ip=$(jq -er '
      .nat_classification
      | if .connectivity_state == "mapped_public" then
          .observed_endpoint
        else
          .local_addr
        end
      | capture("^\\[(?<host>[0-9A-Fa-f:]+)\\]:[0-9]+$").host
    ' "$status_file") ||
      demote_and_exit "Agent public endpoint is malformed IPv6"
    if ! valid_ipv6 "$public_ip"; then
      demote_and_exit "Agent public endpoint is malformed IPv6"
    fi
    public_url_host="[$public_ip]"
    relay_public_endpoint="[$public_ip]:18445"
    stun_listen='[::]:19444'
    ;;
  *)
    public_ip=$(jq -er '
      .nat_classification
      | if .connectivity_state == "mapped_public" then
          .observed_endpoint
        else
          .local_addr
        end
      | capture("^(?<host>[0-9.]+):[0-9]+$").host
    ' "$status_file") ||
      demote_and_exit "Agent public endpoint is malformed IPv4"
    if ! valid_ipv4 "$public_ip"; then
      demote_and_exit "Agent public endpoint is malformed IPv4"
    fi
    public_url_host=$public_ip
    relay_public_endpoint="$public_ip:18445"
    stun_listen='0.0.0.0:19444'
    ;;
esac

if ! valid_ipv4 "$vpn_ip"; then
  demote_and_exit "automatic Control Plane requires an IPv4 HeteroNetwork address"
fi

public_https_url="https://$public_url_host"
stun_public_url="udp://$public_url_host:19444"
relay_public_url="udp://$public_url_host:18445"
relay_admission_url="http://$vpn_ip:18447"
relay_status_url="$relay_admission_url/v1/status"

if ! gateway_is_ready; then
  if [ "$gateway_targets_current_public_ip" -eq 1 ]; then
    log "public Web gateway is still converging for the current public address"
    reconcile_finished=1
    exit 0
  fi
  demote_and_exit "public Web gateway is not ready for the current public address"
fi
if ! relay_is_ready; then
  demote_and_exit "Relay health or advertised endpoint does not match this node"
fi
if [ ! -f "$postgres_password_file" ] || [ -L "$postgres_password_file" ] ||
  [ ! -f "$postgres_ca_file" ] || [ -L "$postgres_ca_file" ]; then
  demote_and_exit "PostgreSQL HA credentials are unavailable"
fi
if ! postgres_proxy_is_ready; then
  demote_and_exit "local PostgreSQL HA proxy is unavailable"
fi

database_password=$(tr -d '\r\n' <"$postgres_password_file")
case "$database_password" in
  ''|*[!A-Za-z0-9._~-]*)
    demote_and_exit "PostgreSQL HA application credential has an invalid format"
    ;;
esac
if [ "${#database_password}" -gt 512 ]; then
  demote_and_exit "PostgreSQL HA application credential is too large"
fi

signal_control_plane_urls="http://$vpn_ip:19088,$bootstrap_control_plane_urls"

if ! detect_node_enrollment_credentials; then
  demote_and_exit "unable to validate optional node-enrollment credentials"
fi

if ! prepare_runtime_files; then
  demote_and_exit "unable to stage automatic public-service configuration"
fi
if ! promote; then
  demote_and_exit "automatic public-service activation failed"
fi

reconcile_finished=1
exit 0
