#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly KEYCLOAK_VERSION="26.6.4"
readonly KEYCLOAK_ARCHIVE_SHA256="386b566bbea05527226e275c43e5cf6f218896ad2441ac4be5c39f1226772e8f"
readonly AGENT_STATUS_URL="http://127.0.0.1:9780/v1/status"
readonly KEYCLOAK_READY_URL="http://127.0.0.1:19000/health/ready"
readonly MAX_CONFIG_BYTES="65536"
readonly MAX_SECRET_BYTES="4096"
readonly MAX_RESPONSE_BYTES="262144"
readonly MAX_CONTROL_PLANE_URLS="16"
readonly MAX_REPLICAS="3"
readonly REPLICA_PORT="18080"
readonly EDGE_PORT="18079"
readonly FAILURE_LIMIT="3"
readonly COOLDOWN_SECONDS="120"

filesystem_root="${HETERONETWORK_KEYCLOAK_AUTOPILOT_TEST_ROOT:-}"
if [[ -n "$filesystem_root" ]]; then
  [[ "${HETERONETWORK_KEYCLOAK_AUTOPILOT_TESTING:-0}" == "1" ]] \
    || {
      printf 'keycloak-autopilot: refusing a filesystem override outside test mode\n' >&2
      exit 1
    }
  [[ "$filesystem_root" == /* ]] \
    || {
      printf 'keycloak-autopilot: test filesystem root must be absolute\n' >&2
      exit 1
    }
  expected_root_uid="$(id -u)"
  helper="${HETERONETWORK_KEYCLOAK_AUTOPILOT_HELPER:-$filesystem_root/opt/heteronetwork/libexec/keycloak-ha-node.sh}"
else
  [[ "$(id -u)" == "0" ]] \
    || {
      printf 'keycloak-autopilot: reconciliation must run as root\n' >&2
      exit 1
    }
  expected_root_uid=0
  helper="/opt/heteronetwork/libexec/keycloak-ha-node.sh"
fi

readonly config_path="$filesystem_root/etc/heteronetwork/keycloak-autopilot.env"
readonly state_dir="$filesystem_root/var/lib/heteronetwork-keycloak-autopilot"
readonly runtime_dir="$filesystem_root/run/heteronetwork-keycloak-autopilot"
readonly bundle_dir="$filesystem_root/etc/heteronetwork/postgres-autopilot/bundle"
readonly db_password_file="$bundle_dir/secrets/keycloak.password"
readonly bootstrap_admin_password_file="$bundle_dir/secrets/keycloak-bootstrap-admin.password"
readonly agent_drop_in_dir="$filesystem_root/etc/systemd/system/heteronetwork-agent.service.d"
readonly agent_drop_in="$agent_drop_in_dir/30-keycloak-gateway.conf"
readonly failure_count_path="$state_dir/restart-failures"
readonly cooldown_until_path="$state_dir/cooldown-until"

request_file=""
response_file=""
candidate_response_file=""
curl_config_file=""

log() {
  printf 'keycloak-autopilot: %s\n' "$*" >&2
}

cleanup() {
  [[ -z "$request_file" ]] || rm -f "$request_file"
  [[ -z "$response_file" ]] || rm -f "$response_file"
  [[ -z "$candidate_response_file" ]] || rm -f "$candidate_response_file"
  [[ -z "$curl_config_file" ]] || rm -f "$curl_config_file"
}
trap cleanup EXIT HUP INT TERM

secure_root_file() {
  local path="$1" maximum_size="$2"
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] || return 1
  local uid links mode size
  read -r uid links mode size < <(stat -c '%u %h %a %s' -- "$path") \
    || return 1
  [[ "$uid" == "$expected_root_uid" \
    && "$links" == "1" \
    && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 0400) != 0 && (8#$mode & 0077) == 0 )) || return 1
  ((10#$size > 0 && 10#$size <= maximum_size))
}

decode_base64_value() {
  local encoded="$1"
  [[ -n "$encoded" && "$encoded" != *[!A-Za-z0-9+/=]* ]] || return 1
  local decoded canonical
  decoded="$(printf '%s' "$encoded" | base64 -d 2>/dev/null)" || return 1
  canonical="$(printf '%s' "$decoded" | base64 | tr -d '\r\n')" || return 1
  [[ "$canonical" == "$encoded" ]] || return 1
  DECODED_VALUE="$decoded"
}

valid_identifier() {
  local value="$1"
  [[ -n "$value" && ${#value} -le 255 && "$value" =~ ^[A-Za-z0-9_.-]+$ ]]
}

valid_http_url() {
  local value="$1"
  [[ -n "$value" && ${#value} -le 2048 \
    && "$value" =~ ^https?://[][A-Za-z0-9._~:/?#%+@,\&=-]+$ \
    && "$value" != *[[:space:]]* ]]
}

valid_archive_url() {
  local value="$1"
  [[ -n "$value" && ${#value} -le 2048 \
    && "$value" =~ ^https://[][A-Za-z0-9._~:/?#%+@,\&=-]+$ \
    && "$value" != *[[:space:]]* ]]
}

valid_oidc_probe_path() {
  local value="$1"
  [[ ${#value} -le 1024 \
    && "$value" =~ ^/realms/[A-Za-z0-9._-]+/[.]well-known/openid-configuration$ ]]
}

load_config() {
  secure_root_file "$config_path" "$MAX_CONFIG_BYTES" \
    || {
      log "root-only autopilot configuration is missing or invalid"
      return 1
    }

  unset \
    HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN \
    HETERONETWORK_KEYCLOAK_CLUSTER_ID_B64 \
    HETERONETWORK_KEYCLOAK_CONTROL_PLANE_URLS_B64 \
    HETERONETWORK_KEYCLOAK_VERSION \
    HETERONETWORK_KEYCLOAK_ARCHIVE_URL_B64 \
    HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256 \
    HETERONETWORK_KEYCLOAK_OIDC_PROBE_PATH_B64

  # The file is root-owned, single-linked, and inaccessible to group/world.
  # shellcheck disable=SC1090
  source "$config_path"

  [[ "${HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN:-}" =~ ^[a-f0-9]{64}$ \
    && "${HETERONETWORK_KEYCLOAK_VERSION:-}" == "$KEYCLOAK_VERSION" \
    && "${HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256:-}" == "$KEYCLOAK_ARCHIVE_SHA256" ]] \
    || {
      log "autopilot credential, version, or archive digest is invalid"
      return 1
    }

  autopilot_bearer_token="$HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN"
  unset HETERONETWORK_KEYCLOAK_AUTOPILOT_BEARER_TOKEN

  decode_base64_value "${HETERONETWORK_KEYCLOAK_CLUSTER_ID_B64:-}" || return 1
  cluster_id="$DECODED_VALUE"
  valid_identifier "$cluster_id" || return 1

  decode_base64_value "${HETERONETWORK_KEYCLOAK_ARCHIVE_URL_B64:-}" || return 1
  archive_url="$DECODED_VALUE"
  valid_archive_url "$archive_url" || return 1

  decode_base64_value "${HETERONETWORK_KEYCLOAK_OIDC_PROBE_PATH_B64:-}" || return 1
  oidc_probe_path="$DECODED_VALUE"
  valid_oidc_probe_path "$oidc_probe_path" || return 1

  local encoded_url
  control_plane_urls=()
  for encoded_url in ${HETERONETWORK_KEYCLOAK_CONTROL_PLANE_URLS_B64:-}; do
    decode_base64_value "$encoded_url" || return 1
    valid_http_url "$DECODED_VALUE" || return 1
    control_plane_urls+=("${DECODED_VALUE%/}")
    ((${#control_plane_urls[@]} <= MAX_CONTROL_PLANE_URLS)) || return 1
  done
  ((${#control_plane_urls[@]} > 0)) || return 1

  unset \
    HETERONETWORK_KEYCLOAK_CLUSTER_ID_B64 \
    HETERONETWORK_KEYCLOAK_CONTROL_PLANE_URLS_B64 \
    HETERONETWORK_KEYCLOAK_VERSION \
    HETERONETWORK_KEYCLOAK_ARCHIVE_URL_B64 \
    HETERONETWORK_KEYCLOAK_ARCHIVE_SHA256 \
    HETERONETWORK_KEYCLOAK_OIDC_PROBE_PATH_B64
}

valid_ipv4() {
  local value="$1" a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" \
    && -n "${c:-}" && -n "${d:-}" ]] || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

valid_private_ipv4() {
  local value="$1" a b c d
  valid_ipv4 "$value" || return 1
  IFS=. read -r a b c d <<<"$value"
  ((10#$a == 10)) \
    || ((10#$a == 172 && 10#$b >= 16 && 10#$b <= 31)) \
    || ((10#$a == 192 && 10#$b == 168)) \
    || ((10#$a == 100 && 10#$b >= 64 && 10#$b <= 127))
}

read_agent_identity() {
  local status
  status="$(curl --fail --silent --show-error \
    --connect-timeout 2 --max-time 5 --max-filesize 1048576 \
    "$AGENT_STATUS_URL" 2>/dev/null)" || return 1
  node_id="$(jq -er '.node_id | select(type == "string")' <<<"$status")" || return 1
  vpn_ip="$(jq -er '.vpn_ip | select(type == "string")' <<<"$status")" || return 1
  valid_identifier "$node_id" && valid_private_ipv4 "$vpn_ip"
}

manifest_value() {
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
  ' "$bundle_dir/manifest.env"
}

bundle_contains_node() {
  local identities entry name identity count=0
  identities="$(manifest_value HETERONETWORK_DB_MEMBER_IDENTITIES)" || return 1
  local -a entries=()
  IFS=, read -r -a entries <<<"$identities"
  ((${#entries[@]} > 0 && ${#entries[@]} <= 32)) || return 1
  for entry in "${entries[@]}"; do
    [[ "$entry" == *=* ]] || return 1
    name="${entry%%=*}"
    identity="${entry#*=}"
    valid_identifier "$name" && valid_identifier "$identity" || return 1
    [[ "$identity" != "$node_id" ]] || count=$((count + 1))
  done
  ((count == 1))
}

full_database_member_is_ready() {
  [[ -d "$bundle_dir" && ! -L "$bundle_dir" \
    && ! -e "$bundle_dir/.proxy-only" \
    && -f "$bundle_dir/manifest.env" && ! -L "$bundle_dir/manifest.env" \
    && -f "$bundle_dir/cluster-id" && ! -L "$bundle_dir/cluster-id" ]] \
    || return 1
  [[ "$(<"$bundle_dir/cluster-id")" == "$cluster_id" ]] || return 1
  bundle_contains_node || return 1
  systemctl is-active --quiet heteronetwork-db.service \
    && systemctl is-active --quiet heteronetwork-db-proxy.service
}

replica_inputs_are_ready() {
  full_database_member_is_ready \
    && secure_root_file "$db_password_file" "$MAX_SECRET_BYTES" \
    && secure_root_file "$bootstrap_admin_password_file" "$MAX_SECRET_BYTES"
}

replica_is_ready() {
  systemctl is-active --quiet heteronetwork-keycloak.service \
    && systemctl is-active --quiet heteronetwork-keycloak-backchannel.service \
    && curl --fail --silent --show-error \
      --connect-timeout 2 --max-time 5 --max-filesize 1048576 \
      "$KEYCLOAK_READY_URL" >/dev/null 2>&1
}

read_nonnegative_state_value() {
  local path="$1" default_value="$2" value
  if [[ ! -f "$path" || -L "$path" ]]; then
    printf '%s\n' "$default_value"
    return
  fi
  value="$(<"$path")"
  [[ "$value" =~ ^[0-9]+$ ]] || {
    printf '%s\n' "$default_value"
    return
  }
  printf '%s\n' "$value"
}

write_state_value() {
  local path="$1" value="$2" temporary
  temporary="$(mktemp "$state_dir/.state.XXXXXX")"
  printf '%s\n' "$value" >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$path"
}

cooldown_is_active() {
  local now until
  now="$(date +%s)"
  until="$(read_nonnegative_state_value "$cooldown_until_path" 0)"
  if ((10#$until > 10#$now)); then
    return 0
  fi
  rm -f "$cooldown_until_path"
  return 1
}

enter_cooldown() {
  local now
  now="$(date +%s)"
  write_state_value "$cooldown_until_path" "$((10#$now + COOLDOWN_SECONDS))"
  write_state_value "$failure_count_path" 0
}

reset_failures() {
  write_state_value "$failure_count_path" 0
}

record_activation_failure() {
  local failures
  failures="$(read_nonnegative_state_value "$failure_count_path" 0)"
  failures=$((10#$failures + 1))
  write_state_value "$failure_count_path" "$failures"
  ((failures >= FAILURE_LIMIT))
}

configure_candidate() {
  HETERONETWORK_KEYCLOAK_CLUSTER_BIND_ADDRESS="$vpn_ip" \
  HETERONETWORK_KEYCLOAK_DB_PASSWORD_FILE="$db_password_file" \
  HETERONETWORK_KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD_FILE="$bootstrap_admin_password_file" \
  "$helper" configure >/dev/null 2>&1
}

write_request() {
  local eligible="$1" ready="$2"
  request_file="$(mktemp "$runtime_dir/request.XXXXXX")"
  jq -cn \
    --arg node_id "$node_id" \
    --arg vpn_ip "$vpn_ip" \
    --arg version "$KEYCLOAK_VERSION" \
    --argjson eligible "$eligible" \
    --argjson ready "$ready" '{
      node_id: $node_id,
      vpn_ip: $vpn_ip,
      eligible: $eligible,
      ready: $ready,
      version: $version
    }' >"$request_file"
  chmod 0600 "$request_file"
}

write_curl_config() {
  curl_config_file="$(mktemp "$runtime_dir/curl.XXXXXX")"
  {
    printf '%s\n' \
      'fail' \
      'silent' \
      'show-error' \
      'connect-timeout = 2' \
      'max-time = 10' \
      "max-filesize = $MAX_RESPONSE_BYTES"
    printf 'header = "Authorization: Bearer %s"\n' "$autopilot_bearer_token"
  } >"$curl_config_file"
  chmod 0600 "$curl_config_file"
}

request_reconciliation() {
  local base
  response_file="$(mktemp "$runtime_dir/response.XXXXXX")"
  write_curl_config
  for base in "${control_plane_urls[@]}"; do
    candidate_response_file="$(mktemp "$runtime_dir/response-candidate.XXXXXX")"
    if curl --config "$curl_config_file" \
      --header 'Content-Type: application/json' \
      --data-binary "@$request_file" \
      --output "$candidate_response_file" \
      "${base}/v1/keycloak-autopilot/reconcile" 2>/dev/null; then
      mv -f "$candidate_response_file" "$response_file"
      candidate_response_file=""
      return 0
    fi
    rm -f "$candidate_response_file"
    candidate_response_file=""
  done
  return 1
}

validate_response() {
  jq -e \
    --arg cluster_id "$cluster_id" \
    --arg node_id "$node_id" \
    --arg vpn_ip "$vpn_ip" \
    --arg version "$KEYCLOAK_VERSION" \
    --argjson maximum "$MAX_REPLICAS" '
      type == "object"
      and (.cluster_id == $cluster_id)
      and (.placement_id | type == "string" and test("^[a-f0-9]{64}$"))
      and (.desired_replicas == 3)
      and (.lease_ttl_seconds | type == "number" and . >= 15 and . <= 300)
      and (.reconcile_after_seconds | type == "number" and . >= 5 and . <= 60)
      and (.assigned | type == "boolean")
      and (.replicas | type == "array" and length <= $maximum)
      and all(.replicas[];
        type == "object"
        and (.node_id | type == "string" and test("^[A-Za-z0-9_.-]{1,255}$"))
        and (.vpn_ip | type == "string" and length <= 64)
        and (.version == $version)
        and (.ready | type == "boolean")
        and (.lease_expires_at | type == "string" and length <= 64))
      and (([.replicas[].node_id] | unique | length) == (.replicas | length))
      and (([.replicas[].vpn_ip] | unique | length) == (.replicas | length))
      and (.assigned == any(.replicas[]; .node_id == $node_id))
      and all(.replicas[]; .node_id != $node_id or .vpn_ip == $vpn_ip)
    ' "$response_file" >/dev/null || return 1

  local replica_ip
  while IFS= read -r replica_ip; do
    valid_private_ipv4 "$replica_ip" || return 1
  done < <(jq -r '.replicas[].vpn_ip' "$response_file")
}

restart_agent_if_drop_in_changed() {
  local desired="$1" changed=0 temporary
  install -d -m 0755 "$agent_drop_in_dir"
  if [[ -z "$filesystem_root" ]]; then
    chown root:root "$agent_drop_in_dir"
  fi
  if [[ "$desired" == "present" ]]; then
    temporary="$(mktemp "$agent_drop_in_dir/.30-keycloak-gateway.conf.XXXXXX")"
    cat >"$temporary" <<EOF
[Service]
Environment="HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_OIDC_UPSTREAM=127.0.0.1:${EDGE_PORT}"
Environment="HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_OIDC_PROBE_PATH=${oidc_probe_path}"
EOF
    chmod 0644 "$temporary"
    if [[ -f "$agent_drop_in" && ! -L "$agent_drop_in" ]] \
      && cmp -s "$temporary" "$agent_drop_in"; then
      rm -f "$temporary"
    else
      mv -f "$temporary" "$agent_drop_in"
      changed=1
    fi
  elif [[ -e "$agent_drop_in" || -L "$agent_drop_in" ]]; then
    rm -f "$agent_drop_in"
    changed=1
  fi

  if ((changed == 1)); then
    systemctl daemon-reload >/dev/null 2>&1 \
      && systemctl restart heteronetwork-agent.service >/dev/null 2>&1
  fi
}

reconcile_edge_proxy() {
  local replica_count upstreams
  replica_count="$(jq -r '.replicas | length' "$response_file")"
  if ((10#$replica_count == 0)); then
    "$helper" deactivate-edge-proxy >/dev/null 2>&1 || true
    restart_agent_if_drop_in_changed absent \
      || log "unable to remove the Agent Keycloak gateway route"
    return
  fi

  upstreams="$(jq -r --arg port "$REPLICA_PORT" \
    '[.replicas[].vpn_ip + ":" + $port] | join(",")' "$response_file")"
  if HETERONETWORK_KEYCLOAK_EDGE_UPSTREAMS="$upstreams" \
    HETERONETWORK_KEYCLOAK_EDGE_LISTEN_PORT="$EDGE_PORT" \
    HETERONETWORK_KEYCLOAK_EDGE_HEALTH_PATH="$oidc_probe_path" \
    "$helper" configure-edge-proxy >/dev/null 2>&1; then
    restart_agent_if_drop_in_changed present \
      || log "unable to activate the Agent Keycloak gateway route"
  else
    log "unable to reconcile the local Keycloak edge proxy"
  fi
}

deactivate_local_replica() {
  "$helper" deactivate >/dev/null 2>&1 \
    || log "unable to stop the unassigned Keycloak replica"
}

withdraw_after_failures() {
  log "replica activation failed three times; withdrawing for 120 seconds"
  enter_cooldown
  deactivate_local_replica
  rm -f "$request_file" "$response_file" "$curl_config_file"
  request_file=""
  response_file=""
  curl_config_file=""
  write_request false false
  if ! request_reconciliation || ! validate_response; then
    log "candidate withdrawal could not be confirmed; local cooldown remains active"
    return
  fi
  reconcile_edge_proxy
  if jq -e '.assigned == false' "$response_file" >/dev/null; then
    deactivate_local_replica
  fi
}

apply_assignment() {
  local eligible="$1" assigned
  assigned="$(jq -r '.assigned' "$response_file")"
  reconcile_edge_proxy

  if [[ "$assigned" == "false" ]]; then
    deactivate_local_replica
    reset_failures
    return
  fi
  if [[ "$eligible" != "true" ]]; then
    log "Control Plane assigned an ineligible local replica; keeping it stopped"
    deactivate_local_replica
    return
  fi
  if replica_is_ready; then
    reset_failures
    return
  fi
  if "$helper" activate >/dev/null 2>&1; then
    reset_failures
    return
  fi
  if record_activation_failure; then
    withdraw_after_failures
  else
    log "Keycloak replica activation failed"
  fi
}

prepare_command() {
  load_config || exit 1
  [[ -x "$helper" ]] || {
    log "Keycloak node helper is unavailable"
    exit 1
  }
  "$helper" prepare-edge
  if ! read_agent_identity; then
    log "local Agent identity is unavailable; replica preparation deferred"
    return
  fi
  if ! replica_inputs_are_ready; then
    log "edge proxy is prepared; this node is not a full database candidate"
    return
  fi
  HETERONETWORK_KEYCLOAK_ARCHIVE_URL="$archive_url" \
    "$helper" prepare
}

reconcile_command() {
  load_config || exit 1
  [[ -x "$helper" ]] || {
    log "Keycloak node helper is unavailable; preserving current state"
    return
  }
  mkdir -p "$state_dir" "$runtime_dir"
  chmod 0700 "$state_dir" "$runtime_dir"

  if ! read_agent_identity; then
    log "local Agent identity is unavailable; preserving current state"
    return
  fi

  local eligible=false ready=false
  if replica_inputs_are_ready; then
    if "$helper" prepared >/dev/null 2>&1; then
      eligible=true
    else
      systemctl start --no-block heteronetwork-keycloak-prepare.service \
        >/dev/null 2>&1 \
        || log "unable to schedule local Keycloak replica preparation"
    fi
  fi
  if cooldown_is_active; then
    eligible=false
  elif [[ "$eligible" == "true" ]] && ! configure_candidate; then
    eligible=false
    log "local Keycloak candidate configuration is invalid"
  fi
  if [[ "$eligible" == "true" ]] && replica_is_ready; then
    ready=true
  fi

  write_request "$eligible" "$ready"
  if ! request_reconciliation; then
    log "every Control Plane is unavailable; preserving current Keycloak state"
    return
  fi
  if ! validate_response; then
    log "Control Plane returned an invalid Keycloak placement; preserving current state"
    return
  fi
  apply_assignment "$eligible"
}

case "${1:-}" in
  prepare)
    prepare_command
    ;;
  reconcile)
    reconcile_command
    ;;
  -h|--help|help)
    printf '%s\n' 'Usage: keycloak-autopilot.sh {prepare|reconcile}'
    ;;
  *)
    printf '%s\n' 'Usage: keycloak-autopilot.sh {prepare|reconcile}' >&2
    exit 2
    ;;
esac
