#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_AGENT_API_URL="http://127.0.0.1:9780"
readonly DEFAULT_STATE_DIR="/etc/heteronetwork/postgres-autopilot"
readonly DEFAULT_RECONCILE_INTERVAL_SECONDS="30"
readonly MIN_DATABASE_MEMBER_COUNT="3"
readonly MAX_DATABASE_MEMBER_COUNT="32"
readonly MAX_DATABASE_CANDIDATE_COUNT="64"
readonly TARGET_DCS_MEMBER_COUNT="5"
readonly MAX_DCS_MEMBER_COUNT="9"
readonly BUNDLE_PORT="17446"
readonly DATABASE_NETWORK_PLANE="underlay-v1"
readonly PROXY_BUNDLE_FORMAT_VERSION="1"
readonly REQUIRED_CONVERGENCE_RECONCILES="3"
readonly BUNDLE_HEALTH_RETRY_ATTEMPTS="6"
readonly BUNDLE_HEALTH_RETRY_SECONDS="5"
readonly UNDERLAY_HEALTH_MAX_CONNECTIONS="8"
readonly UNDERLAY_HEALTH_READ_TIMEOUT_SECONDS="2"
readonly MAX_BUNDLE_ARCHIVE_BYTES="4194304"
readonly MAX_BUNDLE_UNPACKED_BYTES="8388608"
readonly MAX_BUNDLE_FILE_BYTES="1048576"
readonly MAX_BUNDLE_ENTRY_COUNT="512"

state_dir="${HETERONETWORK_DB_AUTOPILOT_STATE_DIR:-$DEFAULT_STATE_DIR}"
config_path="${HETERONETWORK_DB_AUTOPILOT_CONFIG:-$state_dir/autopilot.env}"
agent_api_url="${HETERONETWORK_AGENT_API_URL:-$DEFAULT_AGENT_API_URL}"
reconcile_interval_seconds="${HETERONETWORK_DB_RECONCILE_INTERVAL_SECONDS:-$DEFAULT_RECONCILE_INTERVAL_SECONDS}"
helper="/opt/heteronetwork/libexec/postgres-ha-node.sh"
bundle_dir="$state_dir/bundle"
bundle_archive="$state_dir/bundle.tar.gz"
bundle_member_vpn_path="$state_dir/bundle-member-vpn.txt"
proxy_bundle_archive="$state_dir/proxy-bundle.tar.gz"
proxy_bundle_vpn_path="$state_dir/proxy-bundle-vpn.txt"
proxy_bundle_marker_name=".proxy-only"
eligible_path="$state_dir/eligible.tsv"
authoritative_path="$state_dir/authoritative.tsv"
active_path="$state_dir/active.tsv"
registered_vpn_path="$state_dir/registered-vpn.tsv"
vpn_cidr_path="$state_dir/vpn-cidr"
selected_path="$state_dir/selected.tsv"
selection_epoch_path="$state_dir/selection-epoch"
local_reachability_path="$state_dir/local-reachability.tsv"
authoritative_stability_path="$state_dir/authoritative-stability.tsv"
reciprocal_stability_path="$state_dir/reciprocal-stability.tsv"
applied_revision_path="$state_dir/applied-revision"
configured_revision_path="$state_dir/configured-revision"
proxy_applied_digest_path="$state_dir/proxy-applied-digest"
curl_config_path="$state_dir/curl.conf"
underlay_health_handler="${HETERONETWORK_DB_UNDERLAY_HEALTH_HANDLER:-/opt/heteronetwork/libexec/postgres-underlay-health.py}"
underlay_health_handler_changed=0
legacy_database_service_path="${HETERONETWORK_DB_LEGACY_SERVICE_PATH:-/etc/systemd/system/heteronetwork-db.service}"

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
  [[ -n "${HETERONETWORK_DB_CONTROL_PLANE_URLS_B64:-}" ]] \
    || die "database autopilot control-plane URLs are missing"
  local encoded_control_plane_url decoded_control_plane_url
  for encoded_control_plane_url in $HETERONETWORK_DB_CONTROL_PLANE_URLS_B64; do
    [[ "$encoded_control_plane_url" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] \
      || die "invalid encoded database autopilot control-plane URL"
    decoded_control_plane_url="$(
      printf '%s' "$encoded_control_plane_url" | base64 -d
    )" || die "invalid encoded database autopilot control-plane URL"
    case "$decoded_control_plane_url" in
      http://*|https://*) ;;
      *) die "database autopilot control-plane URL must use HTTP or HTTPS" ;;
    esac
    [[ "$decoded_control_plane_url" != *[[:space:]]* ]] \
      || die "database autopilot control-plane URL contains whitespace"
  done
  if [[ ! "$reconcile_interval_seconds" =~ ^[0-9]+$ ]] \
    || ((10#$reconcile_interval_seconds < 5 || 10#$reconcile_interval_seconds > 3600)); then
    die "reconcile interval must be between 5 and 3600 seconds"
  fi
  if [[ -n "${HETERONETWORK_DB_UNDERLAY_INTERFACE:-}" ]]; then
    [[ "$HETERONETWORK_DB_UNDERLAY_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] \
      || die "invalid database underlay interface"
    [[ "$HETERONETWORK_DB_UNDERLAY_INTERFACE" != "heteronetwork0" ]] \
      || die "database underlay interface must not be heteronetwork0"
  fi
  validate_database_access_values \
    "${HETERONETWORK_DB_CLIENT_CIDRS:-}" \
    "${HETERONETWORK_DB_EXTRA_HBA_ENTRIES:-}" \
    || die "invalid database client CIDRs or extra HBA entries"
}

install_coordination_dependencies() {
  [[ -f "$state_dir/dependencies.ready" ]] && return
  require_command apt-get
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=300 update
  apt-get -o DPkg::Lock::Timeout=300 install --yes --no-install-recommends \
    ca-certificates curl iproute2 jq openssl python3 socat tar util-linux
  touch "$state_dir/dependencies.ready"
}

write_curl_config() {
  cat >"$curl_config_path" <<EOF
fail
silent
show-error
connect-timeout = 2
max-time = 15
max-filesize = 4194304
header = "Authorization: Bearer ${HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN}"
EOF
  chmod 0600 "$curl_config_path"
}

agent_is_ready() {
  curl -fsS --connect-timeout 2 --max-time 5 "$agent_api_url/healthz" >/dev/null 2>&1
}

unmanaged_legacy_database_exists() {
  [[ -f "$legacy_database_service_path" && ! -d "$bundle_dir" ]]
}

full_database_bundle_exists() {
  [[ -d "$bundle_dir" \
    && ! -L "$bundle_dir" \
    && ! -e "$bundle_dir/$proxy_bundle_marker_name" ]]
}

proxy_only_bundle_exists() {
  [[ -d "$bundle_dir" \
    && ! -L "$bundle_dir" \
    && -f "$bundle_dir/$proxy_bundle_marker_name" \
    && ! -L "$bundle_dir/$proxy_bundle_marker_name" \
    && "$(<"$bundle_dir/$proxy_bundle_marker_name")" == "$PROXY_BUNDLE_FORMAT_VERSION" ]]
}

read_agent_status() {
  curl -fsS --connect-timeout 2 --max-time 10 "$agent_api_url/v1/status"
}

read_authoritative_node_registry() {
  local selection_epoch member_node_ids request encoded_base base registry
  selection_epoch="$(candidate_selection_epoch)" || return 1
  member_node_ids='[]'
  if [[ -d "$bundle_dir" ]]; then
    load_bundle_manifest "$bundle_dir" || return 1
    member_node_ids="$(tr ',' '\n' <<<"$manifest_member_identities" \
      | awk -F= '{ print $2 }' \
      | jq -Rsc 'split("\n") | map(select(length > 0))')" || return 1
  fi
  request="$(jq -cn \
    --argjson selection_epoch "$selection_epoch" \
    --argjson member_node_ids "$member_node_ids" '{
      selection_epoch: $selection_epoch,
      member_node_ids: $member_node_ids
    }')" || return 1
  for encoded_base in $HETERONETWORK_DB_CONTROL_PLANE_URLS_B64; do
    base="$(printf '%s' "$encoded_base" | base64 -d)" || continue
    registry="$(curl --config "$curl_config_path" \
      --header "Content-Type: application/json" \
      --data "$request" \
      "${base%/}/v1/database-autopilot/nodes" 2>/dev/null)" || continue
    if jq -e \
      --arg cluster_id "$HETERONETWORK_DB_CLUSTER_ID" \
      --argjson selection_epoch "$selection_epoch" '
      select(.cluster_id == $cluster_id)
      | select(.vpn_cidr | type == "string")
      | select(.selection_epoch == $selection_epoch)
      | select(.nodes | type == "array" and length <= 64)
      | select(all(.nodes[]; (
          (.node_id | type == "string")
          and (.vpn_ip | type == "string")
          and (.role | type == "string")
          and (.active | type == "boolean")
        )))
    ' <<<"$registry" >/dev/null; then
      printf '%s' "$registry"
      return 0
    fi
  done
  return 1
}

is_valid_ipv4() {
  local value="$1"
  local a b c d extra octet
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] \
    || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

ipv4_to_uint() {
  local value="$1"
  is_valid_ipv4 "$value" || return 1
  local a b c d
  IFS=. read -r a b c d <<<"$value"
  printf '%u\n' "$((
    (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d
  ))"
}

validate_vpn_cidr() {
  local value="$1"
  local address prefix extra address_uint mask
  IFS=/ read -r address prefix extra <<<"$value"
  [[ -z "${extra:-}" && "$prefix" =~ ^[0-9]+$ ]] || return 1
  ((10#$prefix >= 1 && 10#$prefix <= 32)) || return 1
  address_uint="$(ipv4_to_uint "$address")" || return 1
  mask="$(( (0xffffffff << (32 - 10#$prefix)) & 0xffffffff ))"
  (( (10#$address_uint & mask) == 10#$address_uint ))
}

ipv4_is_in_cidr() {
  local address="$1"
  local cidr="$2"
  validate_vpn_cidr "$cidr" || return 1
  local network prefix address_uint network_uint mask
  IFS=/ read -r network prefix <<<"$cidr"
  address_uint="$(ipv4_to_uint "$address")" || return 1
  network_uint="$(ipv4_to_uint "$network")" || return 1
  mask="$(( (0xffffffff << (32 - 10#$prefix)) & 0xffffffff ))"
  (( (10#$address_uint & mask) == (10#$network_uint & mask) ))
}

is_valid_node_id() {
  local value="$1"
  [[ ${#value} -le 255 && "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]
}

is_valid_access_cidr() {
  local value="$1"
  local address prefix extra
  IFS=/ read -r address prefix extra <<<"$value"
  [[ -z "${extra:-}" && -n "${address:-}" && "$prefix" =~ ^[0-9]{1,2}$ ]] \
    || return 1
  ((10#$prefix <= 32)) || return 1
  is_valid_ipv4 "$address"
}

validate_database_access_values() {
  local client_cidrs_input="$1"
  local extra_hba_entries_input="$2"
  local entry database user cidr remainder
  local -a entries

  if [[ -n "$client_cidrs_input" ]]; then
    [[ "$client_cidrs_input" == "${client_cidrs_input//[[:space:]]/}" \
      && "$client_cidrs_input" != ,* \
      && "$client_cidrs_input" != *, \
      && "$client_cidrs_input" != *,,* ]] || return 1
    IFS=, read -r -a entries <<<"$client_cidrs_input"
    for cidr in "${entries[@]}"; do
      is_valid_access_cidr "$cidr" || return 1
    done
  fi

  if [[ -n "$extra_hba_entries_input" ]]; then
    [[ "$extra_hba_entries_input" == "${extra_hba_entries_input//[[:space:]]/}" \
      && "$extra_hba_entries_input" != ,* \
      && "$extra_hba_entries_input" != *, \
      && "$extra_hba_entries_input" != *,,* ]] || return 1
    IFS=, read -r -a entries <<<"$extra_hba_entries_input"
    for entry in "${entries[@]}"; do
      database="${entry%%:*}"
      remainder="${entry#*:}"
      [[ "$remainder" != "$entry" ]] || return 1
      user="${remainder%%:*}"
      cidr="${remainder#*:}"
      [[ "$cidr" != "$remainder" && "$cidr" != *:* ]] || return 1
      [[ ${#database} -le 63 && "$database" =~ ^[a-z_][a-z0-9_]*$ ]] \
        || return 1
      [[ ${#user} -le 63 && "$user" =~ ^[a-z_][a-z0-9_]*$ ]] \
        || return 1
      is_valid_access_cidr "$cidr" || return 1
    done
  fi
}

candidate_ipv4_addresses() {
  jq -r '
    [
      .[]
      | select(.kind == "local_udp")
      | . as $candidate
      | try (
          .addr
          | capture("^(?<address>[0-9]+(?:\\.[0-9]+){3}):[0-9]+$")
          | {
              address: .address,
              priority: ($candidate.priority // 0),
              cost: ($candidate.cost // 4294967295)
            }
        )
    ]
    | sort_by([-.priority, .cost, .address])
    | .[].address
  '
}

select_underlay_candidate() {
  local candidates_json="$1"
  local forbidden_addresses="$2"
  local address
  while IFS= read -r address; do
    is_valid_ipv4 "$address" || continue
    if grep -Fxq "$address" <<<"$forbidden_addresses"; then
      continue
    fi
    printf '%s' "$address"
    return 0
  done < <(candidate_ipv4_addresses <<<"$candidates_json")
  return 1
}

local_identity_row() {
  local status="${1:-}"
  local vpn_ip node_id underlay_ip underlay_interface
  [[ -n "$status" ]] || status="$(read_agent_status)" || return 1
  vpn_ip="$(jq -er \
    '.vpn_ip | select(type == "string" and test("^[0-9]+(\\.[0-9]+){3}$"))' \
    <<<"$status")" || return 1
  node_id="$(jq -er '.node_id | select(type == "string" and length > 0)' \
    <<<"$status")" || return 1
  underlay_interface="${HETERONETWORK_DB_UNDERLAY_INTERFACE:-}"
  if [[ -n "$underlay_interface" ]]; then
    underlay_ip="$(address_for_interface "$underlay_interface")" || return 1
  elif underlay_ip="$(address_for_interface tailscale0 2>/dev/null)"; then
    :
  else
    underlay_ip="$(select_underlay_candidate \
      "$(jq -c '.candidates // []' <<<"$status")" "$vpn_ip")" || return 1
  fi
  [[ "$underlay_ip" != "$vpn_ip" ]] || return 1
  underlay_interface="$(interface_for_address "$underlay_ip")" || return 1
  [[ "$underlay_interface" != "heteronetwork0" ]] || return 1
  printf '%s\t%s\t%s\n' "$vpn_ip" "$node_id" "$underlay_ip"
}

agent_status_is_direct_public() {
  local status="$1"
  local max_age
  max_age="$((10#$reconcile_interval_seconds * 3 + 30))"
  ((max_age >= 90)) || max_age=90
  jq -e --argjson max_age "$max_age" '
    .nat_classification as $nat
    | (try ($nat.assessed_at
        | sub("\\.[0-9]+Z$"; "Z")
        | fromdateiso8601) catch null) as $assessed
    | (.node_id
        | type == "string"
          and length > 0
          and length <= 255
          and test("^[A-Za-z0-9._:-]+$"))
      and (.vpn_ip
        | type == "string"
          and test("^[0-9]+(\\.[0-9]+){3}$"))
      and ($nat | type == "object")
      and ($nat.connectivity_state == "public")
      and ($nat.mapping_behavior == "no_nat")
      and ($nat.strategy == "direct_candidate")
      and ($nat.local_addr | type == "string")
      and ($nat.observed_endpoint == $nat.local_addr)
      and ($nat.observations | type == "array" and length > 0)
      and all($nat.observations[];
        .local_addr == $nat.local_addr
        and .reflexive_addr == $nat.local_addr)
      and ($assessed != null)
      and ($assessed <= (now + 5))
      and ($assessed >= (now - $max_age))
  ' <<<"$status" >/dev/null
}

address_for_interface() {
  local interface="$1"
  ip -o -4 address show dev "$interface" scope global \
    | awk '
        {
          split($4, parts, "/")
          if (parts[1] != "") {
            count += 1
            address = parts[1]
          }
        }
        END {
          if (count != 1) {
            exit 1
          }
          print address
        }
      '
}

interface_for_address() {
  local address="$1"
  ip -o -4 address show scope global \
    | awk -v address="$address" '
        {
          split($4, parts, "/")
          if (parts[1] == address) {
            count += 1
            interface = $2
          }
        }
        END {
          if (count != 1) {
            exit 1
          }
          print interface
        }
      '
}

route_output_uses_interface() {
  local output="$1"
  local expected_interface="$2"
  local expected_source="$3"
  [[ "$expected_interface" != "heteronetwork0" ]] || return 1
  awk \
    -v expected_interface="$expected_interface" \
    -v expected_source="$expected_source" '
    {
      for (field_index = 1; field_index <= NF; field_index += 1) {
        if ($field_index == "dev" && field_index < NF) {
          interface_count += 1
          interface = $(field_index + 1)
        } else if (($field_index == "src" || $field_index == "from") && field_index < NF) {
          source_count += 1
          candidate_source = $(field_index + 1)
          if (source_count == 1) {
            source = candidate_source
          } else if (source != candidate_source) {
            source_conflict = 1
          }
        }
      }
    }
    END {
      invalid = interface_count != 1 || interface != expected_interface
      invalid = invalid || interface == "heteronetwork0" || source_count < 1
      invalid = invalid || source_conflict
      invalid = invalid || source != expected_source
      if (invalid) {
        exit 1
      }
    }
  ' <<<"$output"
}

route_to_address_uses_interface() {
  local destination="$1"
  local source="$2"
  local expected_interface="$3"
  if [[ "$destination" == "$source" || "$destination" == 127.* ]]; then
    return 0
  fi
  local route
  route="$(ip -4 route get "$destination" from "$source" 2>/dev/null)" \
    || return 1
  route_output_uses_interface "$route" "$expected_interface" "$source"
}

activate_overlay_discovery() {
  curl -fsS --connect-timeout 2 --max-time 5 \
    --header "Content-Type: application/json" \
    --data "$(
      jq -cn --arg destination "$1" --argjson port "$BUNDLE_PORT" '{
        destination: $destination,
        pin: false,
        protocol: "tcp",
        destination_port: $port,
        detector: "postgres-autopilot-discovery",
        application: "http",
        tcp_state: "syn_sent"
      }'
    )" \
    "$agent_api_url/v1/packet-flow" >/dev/null 2>&1 || true
}

underlay_from_member_descriptor() {
  local descriptor="$1"
  local expected_node_id="$2"
  jq -er \
    --arg node_id "$expected_node_id" \
    --arg network_plane "$DATABASE_NETWORK_PLANE" '
      select(.node_id == $node_id)
      | select(.network_plane == $network_plane)
      | .underlay_ip
      | select(type == "string")
    ' <<<"$descriptor"
}

validate_registered_vpn_snapshot() {
  local path="$1"
  local vpn_ip node_id extra
  local -A seen_vpn_ips=()
  local -A seen_node_ids=()
  while IFS=$'\t' read -r vpn_ip node_id extra; do
    [[ -n "$vpn_ip" && -n "$node_id" && -z "${extra:-}" ]] || return 1
    is_valid_ipv4 "$vpn_ip" || return 1
    is_valid_node_id "$node_id" || return 1
    [[ -z "${seen_vpn_ips[$vpn_ip]:-}" ]] || return 1
    [[ -z "${seen_node_ids[$node_id]:-}" ]] || return 1
    seen_vpn_ips["$vpn_ip"]=1
    seen_node_ids["$node_id"]=1
  done <"$path"
  ((${#seen_node_ids[@]} > 0))
}

validate_authoritative_snapshot() {
  local path="$1"
  local node_id vpn_ip extra
  local -A seen_node_ids=()
  local -A seen_vpn_ips=()
  while IFS=$'\t' read -r node_id vpn_ip extra; do
    [[ -n "$node_id" && -n "$vpn_ip" && -z "${extra:-}" ]] || return 1
    is_valid_node_id "$node_id" || return 1
    is_valid_ipv4 "$vpn_ip" || return 1
    grep -Fqx "$vpn_ip"$'\t'"$node_id" "$registered_vpn_path" || return 1
    [[ -z "${seen_node_ids[$node_id]:-}" ]] || return 1
    [[ -z "${seen_vpn_ips[$vpn_ip]:-}" ]] || return 1
    seen_node_ids["$node_id"]=1
    seen_vpn_ips["$vpn_ip"]=1
  done <"$path"
  ((${#seen_node_ids[@]} > 0))
}

validate_active_snapshot() {
  local path="$1"
  local node_id vpn_ip extra
  local -A seen_node_ids=()
  local -A seen_vpn_ips=()
  while IFS=$'\t' read -r node_id vpn_ip extra; do
    [[ -n "$node_id" && -n "$vpn_ip" && -z "${extra:-}" ]] || return 1
    is_valid_node_id "$node_id" || return 1
    is_valid_ipv4 "$vpn_ip" || return 1
    grep -Fqx "$node_id"$'\t'"$vpn_ip" "$authoritative_path" || return 1
    [[ -z "${seen_node_ids[$node_id]:-}" ]] || return 1
    [[ -z "${seen_vpn_ips[$vpn_ip]:-}" ]] || return 1
    seen_node_ids["$node_id"]=1
    seen_vpn_ips["$vpn_ip"]=1
  done <"$path"
}

write_registry_snapshots() {
  local local_vpn_ip="$1"
  local local_node_id="$2"
  local registry vpn_cidr vpn_cidr_temporary
  local registered_temporary authoritative_temporary active_temporary
  registry="$(read_authoritative_node_registry)" || return 1

  vpn_cidr="$(jq -er '.vpn_cidr | select(type == "string")' <<<"$registry")" \
    || return 1
  validate_vpn_cidr "$vpn_cidr" || return 1
  vpn_cidr_temporary="$(mktemp "$state_dir/vpn-cidr.XXXXXX")"
  registered_temporary="$(mktemp "$state_dir/registered-vpn.XXXXXX")"
  authoritative_temporary="$(mktemp "$state_dir/authoritative.XXXXXX")"
  active_temporary="$(mktemp "$state_dir/active.XXXXXX")"
  printf '%s\n' "$vpn_cidr" >"$vpn_cidr_temporary"
  {
    printf '%s\t%s\n' "$local_vpn_ip" "$local_node_id"
    jq -r '.nodes[] | [.vpn_ip, .node_id] | @tsv' <<<"$registry"
  } | LC_ALL=C sort -V -u >"$registered_temporary"
  if ! validate_registered_vpn_snapshot "$registered_temporary"; then
    rm -f \
      "$vpn_cidr_temporary" "$registered_temporary" \
      "$authoritative_temporary" "$active_temporary"
    return 1
  fi
  install -m 0600 "$vpn_cidr_temporary" "$vpn_cidr_path"
  install -m 0600 "$registered_temporary" "$registered_vpn_path"

  {
    jq -r '
      .nodes[]
      | select(.role != "client")
      | [.node_id, .vpn_ip]
      | @tsv
    ' <<<"$registry"
  } | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -u >"$authoritative_temporary"
  if ! validate_authoritative_snapshot "$authoritative_temporary"; then
    rm -f \
      "$vpn_cidr_temporary" "$registered_temporary" \
      "$authoritative_temporary" "$active_temporary"
    return 1
  fi
  install -m 0600 "$authoritative_temporary" "$authoritative_path"

  jq -r '
    .nodes[]
    | select(.role != "client" and .active)
    | [.node_id, .vpn_ip]
    | @tsv
  ' <<<"$registry" \
    | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -u >"$active_temporary"
  if ! validate_active_snapshot "$active_temporary"; then
    rm -f \
      "$vpn_cidr_temporary" "$registered_temporary" \
      "$authoritative_temporary" "$active_temporary"
    return 1
  fi
  install -m 0600 "$active_temporary" "$active_path"
  rm -f \
    "$vpn_cidr_temporary" "$registered_temporary" \
    "$authoritative_temporary" "$active_temporary"
}

registered_vpn_contains() {
  local address="$1"
  [[ -f "$vpn_cidr_path" && ! -L "$vpn_cidr_path" ]] || return 0
  local vpn_cidr
  vpn_cidr="$(<"$vpn_cidr_path")"
  ipv4_is_in_cidr "$address" "$vpn_cidr"
}

validate_selected_snapshot() {
  local path="$1"
  local node_id vpn_ip extra count=0
  local -A seen_node_ids=()
  local -A seen_vpn_ips=()
  while IFS=$'\t' read -r node_id vpn_ip extra; do
    [[ -n "$node_id" && -n "$vpn_ip" && -z "${extra:-}" ]] || return 1
    is_valid_node_id "$node_id" || return 1
    is_valid_ipv4 "$vpn_ip" || return 1
    grep -Fqx "$node_id"$'\t'"$vpn_ip" "$authoritative_path" || return 1
    [[ -z "${seen_node_ids[$node_id]:-}" ]] || return 1
    [[ -z "${seen_vpn_ips[$vpn_ip]:-}" ]] || return 1
    seen_node_ids["$node_id"]=1
    seen_vpn_ips["$vpn_ip"]=1
    count=$((count + 1))
  done <"$path"
  ((count > 0 && count <= MAX_DATABASE_CANDIDATE_COUNT))
}

candidate_selection_epoch() {
  if [[ -n "${HETERONETWORK_DB_CANDIDATE_EPOCH:-}" ]]; then
    [[ "$HETERONETWORK_DB_CANDIDATE_EPOCH" =~ ^[0-9]+$ ]] \
      || return 1
    printf '%s\n' "$HETERONETWORK_DB_CANDIDATE_EPOCH"
    return
  fi
  local period
  period="$((10#$reconcile_interval_seconds * (REQUIRED_CONVERGENCE_RECONCILES + 2)))"
  ((period >= 60)) || period=60
  printf '%s\n' "$(( $(date +%s) / period ))"
}

write_selected_snapshot() {
  local identities=""
  if [[ -d "$bundle_dir" ]]; then
    load_bundle_manifest "$bundle_dir" || return 1
    identities="$manifest_member_identities"
  fi
  local temporary selection_epoch
  selection_epoch="$(candidate_selection_epoch)" || return 1
  temporary="$(mktemp "$state_dir/selected.XXXXXX")"
  if ! python3 - "$authoritative_path" "$active_path" "$identities" \
      "$MAX_DATABASE_CANDIDATE_COUNT" "$selection_epoch" >"$temporary" <<'PY'
import sys

authoritative_path, active_path, identities_raw, limit_raw, epoch_raw = sys.argv[1:]
limit = int(limit_raw)
epoch = int(epoch_raw)
by_node_id = {}
with open(authoritative_path, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 2:
            raise SystemExit("invalid authoritative database peer row")
        node_id, vpn_ip = fields
        by_node_id[node_id] = vpn_ip

active = []
with open(active_path, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 2:
            raise SystemExit("invalid active database peer row")
        node_id, vpn_ip = fields
        if by_node_id.get(node_id) != vpn_ip:
            raise SystemExit("active database peer is absent from authoritative registry")
        active.append((node_id, vpn_ip))

selected = []
seen = set()
if identities_raw:
    for entry in identities_raw.split(","):
        name, separator, node_id = entry.partition("=")
        if not separator or not name or not node_id or node_id in seen:
            raise SystemExit("invalid persisted member identity")
        if node_id not in by_node_id:
            raise SystemExit("persisted database member is absent from the authoritative peer set")
        selected.append((node_id, by_node_id[node_id]))
        seen.add(node_id)
remaining = [(node_id, vpn_ip) for node_id, vpn_ip in active if node_id not in seen]
slots = limit - len(selected)
if slots < 0:
    raise SystemExit("persisted database members exceed the candidate limit")
if remaining and slots:
    offset = (epoch * slots) % len(remaining)
    rotated = remaining[offset:] + remaining[:offset]
    for node_id, vpn_ip in rotated[:slots]:
        selected.append((node_id, vpn_ip))
        seen.add(node_id)
for node_id, vpn_ip in selected:
    print(f"{node_id}\t{vpn_ip}")
PY
  then
    rm -f "$temporary"
    return 1
  fi
  if ! validate_selected_snapshot "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  install -m 0600 "$temporary" "$selected_path"
  printf '%s\n' "$selection_epoch" >"$selection_epoch_path"
  chmod 0600 "$selection_epoch_path"
  rm -f "$temporary"
}

peer_member_descriptor() {
  local vpn_ip="$1"
  local expected_node_id="$2"
  local descriptor
  activate_overlay_discovery "$vpn_ip"
  descriptor="$(curl --config "$curl_config_path" \
    "http://${vpn_ip}:${BUNDLE_PORT}/v1/postgres-ha/member" 2>/dev/null)" \
    || return 1
  underlay_from_member_descriptor "$descriptor" "$expected_node_id" >/dev/null \
    || return 1
  printf '%s' "$descriptor"
}

peer_advertised_underlay_address() {
  local vpn_ip="$1"
  local expected_node_id="$2"
  local descriptor="$3"
  local underlay_ip
  underlay_ip="$(underlay_from_member_descriptor \
    "$descriptor" "$expected_node_id")" || return 1
  is_valid_ipv4 "$underlay_ip" || return 1
  [[ "$underlay_ip" != "$vpn_ip" ]] || return 1
  registered_vpn_contains "$underlay_ip" && return 1
  printf '%s' "$underlay_ip"
}

peer_autopilot_is_ready() {
  local underlay_ip="$1"
  local local_underlay_ip="$2"
  local local_underlay_interface="$3"
  route_to_address_uses_interface \
    "$underlay_ip" "$local_underlay_ip" "$local_underlay_interface" \
    || return 1
  curl -fsS --connect-timeout 2 --max-time 5 \
    "http://${underlay_ip}:${BUNDLE_PORT}/health" >/dev/null 2>&1
}

validate_eligible_snapshot() {
  local path="$1"
  local maximum_count="${2:-$MAX_DATABASE_MEMBER_COUNT}"
  [[ "$maximum_count" =~ ^[0-9]+$ \
    && 10#$maximum_count -ge 1 \
    && 10#$maximum_count -le MAX_DATABASE_CANDIDATE_COUNT ]] || return 1
  [[ -f "$registered_vpn_path" ]] || return 1
  local vpn_ip node_id underlay_ip extra count=0
  local -A seen_vpn_ips=()
  local -A seen_node_ids=()
  local -A seen_underlay_ips=()
  while IFS=$'\t' read -r vpn_ip node_id underlay_ip extra; do
    [[ -n "$vpn_ip" && -n "$node_id" && -n "$underlay_ip" && -z "${extra:-}" ]] \
      || return 1
    is_valid_ipv4 "$vpn_ip" || return 1
    is_valid_node_id "$node_id" || return 1
    is_valid_ipv4 "$underlay_ip" || return 1
    [[ "$vpn_ip" != "$underlay_ip" ]] || return 1
    registered_vpn_contains "$underlay_ip" && return 1
    [[ -z "${seen_vpn_ips[$vpn_ip]:-}" ]] || return 1
    [[ -z "${seen_node_ids[$node_id]:-}" ]] || return 1
    [[ -z "${seen_underlay_ips[$underlay_ip]:-}" ]] || return 1
    seen_vpn_ips["$vpn_ip"]=1
    seen_node_ids["$node_id"]=1
    seen_underlay_ips["$underlay_ip"]=1
    count=$((count + 1))
  done <"$path"
  ((count > 0 && count <= 10#$maximum_count))
}

descriptor_is_current() {
  local descriptor="$1"
  local source_node_id="$2"
  local source_underlay_ip="$3"
  local authoritative_digest="$4"
  local observed_at now max_age selection_epoch selection_digest
  [[ -f "$selection_epoch_path" && -f "$selected_path" ]] || return 1
  selection_epoch="$(<"$selection_epoch_path")"
  [[ "$selection_epoch" =~ ^[0-9]+$ ]] || return 1
  selection_digest="$(snapshot_digest "$selected_path")" || return 1
  observed_at="$(jq -er '.observed_at | select(type == "number" and floor == .)' \
    <<<"$descriptor")" || return 1
  now="$(date +%s)"
  max_age=$((10#$reconcile_interval_seconds * 3 + 30))
  ((max_age >= 90)) || max_age=90
  ((10#$observed_at <= 10#$now + 30 \
      && 10#$observed_at >= 10#$now - max_age)) || return 1
  jq -e \
    --arg node_id "$source_node_id" \
    --arg underlay_ip "$source_underlay_ip" \
    --arg network_plane "$DATABASE_NETWORK_PLANE" \
    --arg authoritative_digest "$authoritative_digest" \
    --arg selection_digest "$selection_digest" \
    --argjson selection_epoch "$selection_epoch" \
    --argjson maximum "$MAX_DATABASE_CANDIDATE_COUNT" '
      select(.node_id == $node_id)
      | select(.underlay_ip == $underlay_ip)
      | select(.network_plane == $network_plane)
      | select(.authoritative_digest == $authoritative_digest)
      | select(.selection_epoch == $selection_epoch)
      | select(.selection_digest == $selection_digest)
      | select(
          (
            .bundle_revision == null
            and .bundle_digest == null
          )
          or (
            (.bundle_revision | type == "number" and floor == . and . >= 1)
            and (.bundle_digest | type == "string" and test("^[a-f0-9]{64}$"))
          )
        )
      | select(
          (.reachability | type == "array" and length <= $maximum)
          and all(.reachability[]; (
            (.vpn_ip | type == "string")
            and (.node_id | type == "string")
            and (.underlay_ip | type == "string")
          ))
        )
    ' <<<"$descriptor" >/dev/null
}

write_local_reachability() {
  local local_vpn_ip="$1"
  local local_node_id="$2"
  local local_underlay_ip="$3"
  local local_underlay_interface="$4"
  local authoritative_digest="$5"
  local temporary node_id vpn_ip descriptor underlay_ip
  temporary="$(mktemp "$state_dir/local-reachability.XXXXXX")"
  while IFS=$'\t' read -r node_id vpn_ip; do
    if [[ "$node_id" == "$local_node_id" ]]; then
      underlay_ip="$local_underlay_ip"
    else
      descriptor="$(peer_member_descriptor "$vpn_ip" "$node_id")" || continue
      underlay_ip="$(peer_advertised_underlay_address \
        "$vpn_ip" "$node_id" "$descriptor")" || continue
      descriptor_is_current \
        "$descriptor" "$node_id" "$underlay_ip" "$authoritative_digest" \
        || continue
      peer_autopilot_is_ready \
        "$underlay_ip" "$local_underlay_ip" "$local_underlay_interface" \
        || continue
    fi
    printf '%s\t%s\t%s\n' "$vpn_ip" "$node_id" "$underlay_ip" >>"$temporary"
  done <"$selected_path"
  if ! validate_eligible_snapshot \
      "$temporary" "$MAX_DATABASE_CANDIDATE_COUNT"; then
    rm -f "$temporary"
    return 1
  fi
  install -m 0600 "$temporary" "$local_reachability_path"
  rm -f "$temporary"
  publish_member_descriptor \
    "$local_node_id" "$local_underlay_ip" \
    "$authoritative_digest" "$local_reachability_path"
}

snapshot_count() {
  local path="$1"
  local count
  if [[ ! -f "$path" ]]; then
    printf '0\n'
    return
  fi
  count="$(wc -l <"$path" | tr -d '[:space:]')" || count=0
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  printf '%s\n' "$count"
}

eligible_count() {
  snapshot_count "$eligible_path"
}

snapshot_digest() {
  sha256sum "$1" | awk '{print $1}'
}

observe_snapshot_stability() {
  local state_path="$1"
  local digest="$2"
  local previous_digest="" previous_count=0 extra=""
  if [[ -f "$state_path" ]]; then
    IFS=$'\t' read -r previous_digest previous_count extra <"$state_path" || true
  fi
  [[ "$previous_count" =~ ^[0-9]+$ ]] || previous_count=0
  local count=1
  if [[ "$previous_digest" == "$digest" && -z "$extra" ]]; then
    count=$((10#$previous_count + 1))
  fi
  ((count <= REQUIRED_CONVERGENCE_RECONCILES)) \
    || count="$REQUIRED_CONVERGENCE_RECONCILES"
  local temporary
  temporary="$(mktemp "$state_dir/stability.XXXXXX")"
  printf '%s\t%s\n' "$digest" "$count" >"$temporary"
  install -m 0600 "$temporary" "$state_path"
  rm -f "$temporary"
  ((count >= REQUIRED_CONVERGENCE_RECONCILES))
}

reset_reciprocal_snapshot() {
  rm -f "$eligible_path" "$reciprocal_stability_path"
}

reset_convergence_state() {
  rm -f "$authoritative_stability_path"
  reset_reciprocal_snapshot
}

initial_coordinator_node_id() {
  awk -F '\t' 'NR == 1 { print $1 }' "$selected_path"
}

observe_reciprocal_stability() {
  local topology_digest="$1"
  local eligible_snapshot="$2"
  local descriptors_path="$3"
  local temporary
  temporary="$(mktemp "$state_dir/reciprocal-stability.XXXXXX")"
  if ! python3 - \
      "$reciprocal_stability_path" "$topology_digest" \
      "$eligible_snapshot" "$descriptors_path" \
      "$REQUIRED_CONVERGENCE_RECONCILES" >"$temporary" <<'PY'
import json
import pathlib
import sys

state_path, topology_digest, eligible_path, descriptors_path, required_raw = sys.argv[1:]
required = int(required_raw)
selected = []
with open(eligible_path, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 3:
            raise SystemExit("invalid reciprocal eligible row")
        selected.append(fields[1])

observed = {}
with open(descriptors_path, encoding="utf-8") as source:
    for line in source:
        descriptor = json.loads(line)
        node_id = descriptor.get("node_id")
        observed_at = descriptor.get("observed_at")
        if node_id in observed or not isinstance(observed_at, int):
            raise SystemExit("invalid reciprocal descriptor generation")
        observed[node_id] = observed_at
observed = {node_id: observed[node_id] for node_id in selected}

previous = {}
try:
    previous = json.loads(pathlib.Path(state_path).read_text(encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError, OSError):
    pass

count = 1
stored_observed = observed
if (
    previous.get("topology_digest") == topology_digest
    and isinstance(previous.get("count"), int)
    and isinstance(previous.get("observed_at"), dict)
    and set(previous["observed_at"]) == set(observed)
):
    previous_observed = previous["observed_at"]
    if all(
        isinstance(previous_observed[node_id], int)
        and observed[node_id] > previous_observed[node_id]
        for node_id in observed
    ):
        count = min(required, previous["count"] + 1)
    elif all(
        isinstance(previous_observed[node_id], int)
        and observed[node_id] >= previous_observed[node_id]
        for node_id in observed
    ):
        count = max(1, min(required, previous["count"]))
        stored_observed = previous_observed

json.dump(
    {
        "topology_digest": topology_digest,
        "count": count,
        "observed_at": stored_observed,
        "ready": count >= required,
    },
    sys.stdout,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stdout.write("\n")
PY
  then
    rm -f "$temporary"
    return 1
  fi
  install -m 0600 "$temporary" "$reciprocal_stability_path"
  rm -f "$temporary"
  jq -e '.ready == true' "$reciprocal_stability_path" >/dev/null
}

write_reciprocal_eligible_snapshot() {
  local local_node_id="$1"
  local authoritative_digest="$2"
  if ! validate_eligible_snapshot \
      "$local_reachability_path" "$MAX_DATABASE_CANDIDATE_COUNT"; then
    reset_reciprocal_snapshot
    return 1
  fi

  local descriptors_path eligible_temporary
  descriptors_path="$(mktemp "$state_dir/reciprocal-descriptors.XXXXXX")"
  eligible_temporary="$(mktemp "$state_dir/reciprocal-eligible.XXXXXX")"
  local vpn_ip node_id underlay_ip descriptor
  while IFS=$'\t' read -r vpn_ip node_id underlay_ip; do
    if [[ "$node_id" == "$local_node_id" ]]; then
      descriptor="$(<"$state_dir/member.json")"
    else
      descriptor="$(peer_member_descriptor "$vpn_ip" "$node_id")" || {
        rm -f "$descriptors_path" "$eligible_temporary"
        reset_reciprocal_snapshot
        return 1
      }
    fi
    if ! descriptor_is_current \
        "$descriptor" "$node_id" "$underlay_ip" "$authoritative_digest"; then
      rm -f "$descriptors_path" "$eligible_temporary"
      reset_reciprocal_snapshot
      return 1
    fi
    jq -c . <<<"$descriptor" >>"$descriptors_path"
  done <"$local_reachability_path"

  local identities="" members=""
  if [[ -d "$bundle_dir" ]]; then
    load_bundle_manifest "$bundle_dir" || {
      rm -f "$descriptors_path" "$eligible_temporary"
      reset_reciprocal_snapshot
      return 1
    }
    identities="$manifest_member_identities"
    members="$manifest_members"
  fi
  if ! python3 - \
      "$selected_path" "$active_path" \
      "$local_reachability_path" "$descriptors_path" \
      "$identities" "$members" "$local_node_id" \
      "$MAX_DATABASE_MEMBER_COUNT" \
      >"$eligible_temporary" <<'PY'
import json
import sys

(
    candidate_path,
    active_path,
    local_path,
    descriptors_path,
    identities_raw,
    members_raw,
    coordinator_node_id,
    limit_raw,
) = sys.argv[1:]
limit = int(limit_raw)

def mapping(raw, label):
    result = {}
    order = []
    if not raw:
        return result, order
    for entry in raw.split(","):
        name, separator, value = entry.partition("=")
        if not separator or not name or not value or name in result:
            raise SystemExit(f"invalid {label}")
        result[name] = value
        order.append(name)
    return result, order

candidates = []
candidate_vpn = {}
with open(candidate_path, encoding="utf-8") as source:
    for line in source:
        node_id, vpn_ip = line.rstrip("\n").split("\t")
        candidates.append(node_id)
        candidate_vpn[node_id] = vpn_ip

active_node_ids = set()
with open(active_path, encoding="utf-8") as source:
    for line in source:
        node_id, vpn_ip = line.rstrip("\n").split("\t")
        if candidate_vpn.get(node_id) == vpn_ip:
            active_node_ids.add(node_id)

local = {}
with open(local_path, encoding="utf-8") as source:
    for line in source:
        vpn_ip, node_id, underlay_ip = line.rstrip("\n").split("\t")
        if node_id in local or candidate_vpn.get(node_id) != vpn_ip:
            raise SystemExit("invalid local reachability evidence")
        local[node_id] = (vpn_ip, underlay_ip)

descriptors = {}
reachability = {}
with open(descriptors_path, encoding="utf-8") as source:
    for line in source:
        descriptor = json.loads(line)
        node_id = descriptor["node_id"]
        if node_id in descriptors or node_id not in local:
            raise SystemExit("invalid reciprocal descriptor identity")
        rows = {}
        seen_vpn = set()
        seen_underlay = set()
        for row in descriptor["reachability"]:
            peer_id = row["node_id"]
            vpn_ip = row["vpn_ip"]
            underlay_ip = row["underlay_ip"]
            if (
                peer_id in rows
                or candidate_vpn.get(peer_id) != vpn_ip
                or vpn_ip in seen_vpn
                or underlay_ip in seen_underlay
            ):
                raise SystemExit("invalid descriptor reachability set")
            rows[peer_id] = (vpn_ip, underlay_ip)
            seen_vpn.add(vpn_ip)
            seen_underlay.add(underlay_ip)
        if rows.get(node_id) != local[node_id]:
            raise SystemExit("descriptor does not contain its own selected underlay")
        descriptors[node_id] = descriptor
        reachability[node_id] = rows

members, member_names = mapping(members_raw, "database member map")
identities, identity_names = mapping(identities_raw, "database identity map")
if member_names != identity_names:
    raise SystemExit("database member and identity orders differ")
persisted = {identities[name]: members[name] for name in member_names}

available = [
    node_id
    for node_id in candidates
    if (
        node_id in active_node_ids
        and node_id in local
        and node_id in descriptors
    )
]
available_set = set(available)
candidate_rank = {node_id: index for index, node_id in enumerate(candidates)}

for node_id in persisted:
    if node_id in active_node_ids:
        if node_id not in available_set:
            raise SystemExit("active persisted member has no fresh reciprocal descriptor")
        if local[node_id][1] != persisted[node_id]:
            raise SystemExit("persisted member underlay address drift")

def mutual(left, right):
    return (
        reachability[left].get(right) == local[right]
        and reachability[right].get(left) == local[left]
    )

mandatory = [
    node_id
    for node_id in candidates
    if node_id in persisted and node_id in active_node_ids
]
if not persisted:
    if coordinator_node_id not in available_set:
        raise SystemExit("initial coordinator has no fresh reciprocal descriptor")
    mandatory = [coordinator_node_id]
if len(mandatory) > limit:
    raise SystemExit("mandatory database member set exceeds the topology limit")
if any(
    not mutual(left, right)
    for index, left in enumerate(mandatory)
    for right in mandatory[index + 1 :]
):
    raise SystemExit("active persisted members are not mutually reachable")

compatible = [
    node_id
    for node_id in available
    if node_id not in mandatory
    and all(mutual(node_id, member) for member in mandatory)
]
degree = {
    node_id: sum(
        1
        for other in available
        if other != node_id and mutual(node_id, other)
    )
    for node_id in available
}
extension_order = sorted(
    compatible,
    key=lambda node_id: (-degree[node_id], candidate_rank[node_id]),
)

seeds = [tuple(mandatory)]
for node_id in compatible:
    seeds.append(tuple(mandatory + [node_id]))
if len(mandatory) <= 1:
    for index, left in enumerate(compatible):
        for right in compatible[index + 1 :]:
            if mutual(left, right):
                seeds.append(tuple(mandatory + [left, right]))

best = tuple(mandatory)
best_rank = tuple(candidate_rank[node_id] for node_id in best)
for seed in seeds:
    clique = list(dict.fromkeys(seed))
    if len(clique) > limit:
        continue
    for node_id in extension_order:
        if len(clique) >= limit:
            break
        if node_id in clique:
            continue
        if all(mutual(node_id, member) for member in clique):
            clique.append(node_id)
    ordered = tuple(
        node_id for node_id in candidates if node_id in set(clique)
    )
    rank = tuple(candidate_rank[node_id] for node_id in ordered)
    if len(ordered) > len(best) or (
        len(ordered) == len(best) and rank < best_rank
    ):
        best = ordered
        best_rank = rank

if any(node_id not in best for node_id in mandatory):
    raise SystemExit("not every mandatory database member is in the reciprocal set")
for node_id in best:
    vpn_ip, underlay_ip = local[node_id]
    print(f"{vpn_ip}\t{node_id}\t{underlay_ip}")
PY
  then
    rm -f "$descriptors_path" "$eligible_temporary"
    reset_reciprocal_snapshot
    return 1
  fi
  if ! validate_eligible_snapshot "$eligible_temporary"; then
    rm -f "$descriptors_path" "$eligible_temporary"
    reset_reciprocal_snapshot
    return 1
  fi

  local digest_input digest
  digest_input="$(mktemp "$state_dir/reciprocal-digest.XXXXXX")"
  {
    printf '%s\n' "$authoritative_digest"
    cat "$eligible_temporary"
  } >"$digest_input"
  digest="$(snapshot_digest "$digest_input")"
  rm -f "$digest_input"
  if ! observe_reciprocal_stability \
      "$digest" "$eligible_temporary" "$descriptors_path"; then
    rm -f "$descriptors_path" "$eligible_temporary"
    rm -f "$eligible_path"
    return 1
  fi
  install -m 0600 "$eligible_temporary" "$eligible_path"
  rm -f "$descriptors_path" "$eligible_temporary"
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

load_bundle_manifest() {
  local directory="$1"
  [[ -f "$directory/manifest.env" && ! -L "$directory/manifest.env" ]] \
    || return 1
  manifest_cluster_name="$(manifest_value "$directory" HETERONETWORK_DB_CLUSTER_NAME)"
  manifest_members="$(manifest_value "$directory" HETERONETWORK_DB_MEMBERS)"
  manifest_member_identities="$(
    manifest_value "$directory" HETERONETWORK_DB_MEMBER_IDENTITIES
  )"
  manifest_dcs_members="$(manifest_value "$directory" HETERONETWORK_DB_DCS_MEMBERS)"
  manifest_dcs_bootstrap_members="$(
    manifest_value "$directory" HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS
  )"
  manifest_client_cidrs="$(
    manifest_value "$directory" HETERONETWORK_DB_CLIENT_CIDRS true
  )" || return 1
  manifest_extra_hba_entries="$(
    manifest_value "$directory" HETERONETWORK_DB_EXTRA_HBA_ENTRIES true
  )" || return 1
  manifest_service_name="$(manifest_value "$directory" HETERONETWORK_DB_SERVICE_NAME)"
  manifest_postgres_port="$(manifest_value "$directory" HETERONETWORK_DB_POSTGRES_PORT)"
  manifest_rest_port="$(manifest_value "$directory" HETERONETWORK_DB_REST_PORT)"
  manifest_revision="$(manifest_value "$directory" HETERONETWORK_DB_TOPOLOGY_REVISION)"
  manifest_network_plane="$(manifest_value "$directory" HETERONETWORK_DB_NETWORK_PLANE)"
  validate_database_access_values \
    "$manifest_client_cidrs" "$manifest_extra_hba_entries" || return 1
  [[ "$manifest_revision" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$manifest_network_plane" == "$DATABASE_NETWORK_PLANE" ]] || return 1
  [[ -f "$directory/cluster-id" && ! -L "$directory/cluster-id" ]] || return 1
  [[ "$(<"$directory/cluster-id")" == "$HETERONETWORK_DB_CLUSTER_ID" ]] || return 1
}

run_helper_for_bundle() {
  local directory="$1"
  shift
  load_bundle_manifest "$directory" || die "invalid database bundle manifest"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_INTERFACE=${HETERONETWORK_DB_INTERFACE:-}" \
    "HETERONETWORK_DB_NODE_NAME=${HETERONETWORK_DB_NODE_NAME:-db-a}" \
    "HETERONETWORK_DB_NODE_ADDRESS=${HETERONETWORK_DB_NODE_ADDRESS:-10.255.255.254}" \
    "HETERONETWORK_DB_MEMBERS=$manifest_members" \
    "HETERONETWORK_DB_MEMBER_IDENTITIES=$manifest_member_identities" \
    "HETERONETWORK_DB_DCS_MEMBERS=$manifest_dcs_members" \
    "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=$manifest_dcs_bootstrap_members" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$manifest_members" \
    "HETERONETWORK_DB_CLIENT_CIDRS=$manifest_client_cidrs" \
    "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=$manifest_extra_hba_entries" \
    "HETERONETWORK_DB_BUNDLE_DIR=$directory" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$manifest_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$manifest_network_plane" \
    "$helper" "$@"
}

validate_bundle_directory() {
  local directory="$1"
  load_bundle_manifest "$directory" || return 1
  run_helper_for_bundle "$directory" validate-bundle "$directory" >/dev/null 2>&1
}

validate_proxy_bundle_directory() {
  local directory="$1"
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  [[ -f "$directory/$proxy_bundle_marker_name" \
    && ! -L "$directory/$proxy_bundle_marker_name" \
    && "$(<"$directory/$proxy_bundle_marker_name")" == "$PROXY_BUNDLE_FORMAT_VERSION" ]] \
    || return 1
  load_bundle_manifest "$directory" || return 1
  if ! python3 - \
    "$directory" \
    "$manifest_cluster_name" "$manifest_members" "$manifest_member_identities" \
    "$manifest_dcs_members" "$manifest_dcs_bootstrap_members" \
    "$manifest_service_name" "$manifest_postgres_port" "$manifest_rest_port" \
    "$MAX_DATABASE_MEMBER_COUNT" "$MAX_DCS_MEMBER_COUNT" \
    "$proxy_bundle_marker_name" <<'PY'
import ipaddress
import os
import pathlib
import re
import stat
import sys

(
    root_raw,
    cluster_name,
    members_raw,
    identities_raw,
    dcs_raw,
    dcs_bootstrap_raw,
    service_name,
    postgres_port_raw,
    rest_port_raw,
    member_limit_raw,
    dcs_limit_raw,
    marker_name,
) = sys.argv[1:]
root = pathlib.Path(root_raw)
member_limit = int(member_limit_raw)
dcs_limit = int(dcs_limit_raw)
expected_files = {
    marker_name,
    "manifest.env",
    "cluster-id",
    "ca/ca.crt",
    "secrets/application.password",
}
expected_directories = {"ca", "secrets"}
actual_files = set()
actual_directories = set()
for path in root.rglob("*"):
    if path.is_symlink():
        raise SystemExit("proxy bundle contains a symlink")
    relative = path.relative_to(root).as_posix()
    mode = path.stat().st_mode
    if stat.S_ISREG(mode):
        if path.stat().st_nlink != 1:
            raise SystemExit("proxy bundle contains a hard-linked file")
        actual_files.add(relative)
    elif stat.S_ISDIR(mode):
        actual_directories.add(relative)
    else:
        raise SystemExit("proxy bundle contains an unsupported object")
if actual_files != expected_files or actual_directories != expected_directories:
    raise SystemExit("proxy bundle file allowlist mismatch")
for relative in (marker_name, "manifest.env", "cluster-id", "secrets/application.password"):
    if os.stat(root / relative).st_mode & 0o077:
        raise SystemExit("proxy bundle private file is group/world accessible")
for relative in (".", "ca", "secrets"):
    if os.stat(root / relative).st_mode & 0o077:
        raise SystemExit("proxy bundle directory is group/world accessible")
if os.stat(root / "ca/ca.crt").st_mode & 0o022:
    raise SystemExit("proxy bundle CA is group/world writable")

name_pattern = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
node_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
dns_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
if not 1 <= len(cluster_name) <= 63 or not name_pattern.fullmatch(cluster_name):
    raise SystemExit("invalid proxy bundle cluster name")
if (
    not 1 <= len(service_name) <= 253
    or not dns_pattern.fullmatch(service_name)
    or ".." in service_name
):
    raise SystemExit("invalid proxy bundle service name")
for port_raw in (postgres_port_raw, rest_port_raw):
    if not port_raw.isdigit() or not 1024 <= int(port_raw) <= 65535:
        raise SystemExit("invalid proxy bundle port")

def parse_address_map(raw, label, minimum, maximum, require_odd=False):
    entries = raw.split(",") if raw else []
    if not minimum <= len(entries) <= maximum:
        raise SystemExit(f"invalid {label} count")
    if require_odd and len(entries) % 2 != 1:
        raise SystemExit(f"{label} count must be odd")
    result = {}
    addresses = set()
    order = []
    for entry in entries:
        name, separator, address = entry.partition("=")
        if (
            not separator
            or not name_pattern.fullmatch(name)
            or name in result
            or any(character.isspace() for character in entry)
        ):
            raise SystemExit(f"invalid {label} entry")
        try:
            parsed = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as error:
            raise SystemExit(f"invalid {label} address") from error
        if parsed in addresses:
            raise SystemExit(f"duplicate {label} address")
        result[name] = address
        addresses.add(parsed)
        order.append(name)
    return result, order

members, member_order = parse_address_map(
    members_raw, "database member", 3, member_limit
)
identities = {}
identity_order = []
node_ids = set()
for entry in identities_raw.split(",") if identities_raw else []:
    name, separator, node_id = entry.partition("=")
    if (
        not separator
        or not name_pattern.fullmatch(name)
        or not node_pattern.fullmatch(node_id)
        or len(node_id) > 255
        or name in identities
        or node_id in node_ids
        or any(character.isspace() for character in entry)
    ):
        raise SystemExit("invalid database member identity")
    identities[name] = node_id
    node_ids.add(node_id)
    identity_order.append(name)
if identity_order != member_order:
    raise SystemExit("database member and identity orders differ")
dcs, _ = parse_address_map(
    dcs_raw, "DCS member", 3, dcs_limit, require_odd=True
)
dcs_bootstrap, _ = parse_address_map(
    dcs_bootstrap_raw, "DCS bootstrap member", 3, dcs_limit
)
for name, address in dcs.items():
    if members.get(name) != address:
        raise SystemExit("DCS member is absent from database members")
for name, address in dcs_bootstrap.items():
    if dcs.get(name) != address:
        raise SystemExit("DCS bootstrap member is absent from requested DCS members")
PY
  then
    return 1
  fi
  local application_password
  application_password="$(
    tr -d '\r\n' <"$directory/secrets/application.password"
  )" || return 1
  [[ "$application_password" =~ ^[A-Za-z0-9]{32,128}$ ]] || return 1
  openssl x509 -in "$directory/ca/ca.crt" -noout -checkend 0 >/dev/null 2>&1 \
    || return 1
  openssl verify \
    -CAfile "$directory/ca/ca.crt" "$directory/ca/ca.crt" >/dev/null 2>&1
}

safe_extract_bundle() {
  local archive="$1"
  local destination="$2"
  python3 - \
    "$archive" "$destination" \
    "$MAX_BUNDLE_ARCHIVE_BYTES" "$MAX_BUNDLE_UNPACKED_BYTES" \
    "$MAX_BUNDLE_FILE_BYTES" "$MAX_BUNDLE_ENTRY_COUNT" <<'PY'
import os
import pathlib
import shutil
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
archive_limit, unpacked_limit, file_limit, entry_limit = map(int, sys.argv[3:])
if (
    not archive.is_file()
    or archive.is_symlink()
    or archive.stat().st_size > archive_limit
):
    raise SystemExit("database bundle archive is missing, unsafe, or oversized")
destination.mkdir(mode=0o700, parents=True, exist_ok=False)
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    if len(members) > entry_limit:
        raise SystemExit("database bundle has too many entries")
    seen = set()
    unpacked_size = 0
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        parts = tuple(part for part in path.parts if part not in ("", "."))
        normalized = pathlib.PurePosixPath(*parts)
        if (
            path.is_absolute()
            or ".." in parts
            or len(parts) > 8
            or len(normalized.as_posix().encode("utf-8")) > 255
            or normalized in seen
        ):
            raise SystemExit("unsafe path in database bundle")
        seen.add(normalized)
        if not member.isdir() and not member.isfile():
            raise SystemExit("non-regular object in database bundle")
        if member.isfile():
            if member.size < 0 or member.size > file_limit:
                raise SystemExit("oversized file in database bundle")
            unpacked_size += member.size
            if unpacked_size > unpacked_limit:
                raise SystemExit("database bundle expands beyond its size limit")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        parts = tuple(part for part in path.parts if part not in ("", "."))
        if not parts:
            continue
        target = destination.joinpath(*parts)
        if member.isdir():
            target.mkdir(mode=member.mode & 0o777, parents=True, exist_ok=True)
            os.chmod(target, member.mode & 0o777)
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

exchange_bundle_directory() {
  local source="$1"
  if [[ ! -e "$bundle_dir" ]]; then
    mv "$source" "$bundle_dir" \
      || die "failed to atomically install the initial database material"
    return
  fi
  python3 - "$source" "$bundle_dir" <<'PY'
import ctypes
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
if (
    not source.is_dir()
    or source.is_symlink()
    or not destination.is_dir()
    or destination.is_symlink()
    or source.parent != destination.parent
):
    raise SystemExit("database bundle exchange paths are unsafe")

libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
at_fdcwd = -100
rename_exchange = 2
result = renameat2(
    at_fdcwd,
    os.fsencode(source),
    at_fdcwd,
    os.fsencode(destination),
    rename_exchange,
)
if result != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
PY
  rm -rf "$source"
}

install_bundle_directory() {
  local source="$1"
  validate_bundle_directory "$source" || die "downloaded database bundle failed validation"
  exchange_bundle_directory "$source"
}

install_proxy_bundle_directory() {
  local source="$1"
  validate_proxy_bundle_directory "$source" \
    || die "downloaded database proxy bundle failed validation"
  exchange_bundle_directory "$source"
}

publish_member_descriptor() {
  local node_id="$1"
  local underlay_ip="$2"
  local authoritative_digest="$3"
  local reachability_path="$4"
  local reachability observed_at temporary selection_epoch selection_digest
  local bundle_revision="" bundle_digest=""
  [[ -f "$selection_epoch_path" && -f "$selected_path" ]] \
    || die "database candidate selection metadata is unavailable"
  selection_epoch="$(<"$selection_epoch_path")"
  [[ "$selection_epoch" =~ ^[0-9]+$ ]] \
    || die "invalid database candidate selection epoch"
  selection_digest="$(snapshot_digest "$selected_path")"
  if full_database_bundle_exists && load_bundle_manifest "$bundle_dir"; then
    bundle_revision="$manifest_revision"
    bundle_digest="$(bundle_content_digest "$bundle_dir")" \
      || die "unable to digest the local database bundle"
  fi
  reachability="$(jq -Rn '
    [
      inputs
      | split("\t")
      | select(length == 3)
      | {vpn_ip: .[0], node_id: .[1], underlay_ip: .[2]}
    ]
  ' <"$reachability_path")"
  observed_at="$(date +%s)"
  temporary="$(mktemp "$state_dir/member.json.XXXXXX")"
  jq -cn \
    --arg node_id "$node_id" \
    --arg underlay_ip "$underlay_ip" \
    --arg network_plane "$DATABASE_NETWORK_PLANE" \
    --arg authoritative_digest "$authoritative_digest" \
    --arg selection_digest "$selection_digest" \
    --argjson selection_epoch "$selection_epoch" \
    --arg bundle_revision "$bundle_revision" \
    --arg bundle_digest "$bundle_digest" \
    --argjson observed_at "$observed_at" \
    --argjson reachability "$reachability" '{
      node_id: $node_id,
      underlay_ip: $underlay_ip,
      network_plane: $network_plane,
      authoritative_digest: $authoritative_digest,
      selection_epoch: $selection_epoch,
      selection_digest: $selection_digest,
      bundle_revision: (
        if $bundle_revision == "" then null else ($bundle_revision | tonumber) end
      ),
      bundle_digest: (
        if $bundle_digest == "" then null else $bundle_digest end
      ),
      observed_at: $observed_at,
      reachability: $reachability
    }' >"$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$state_dir/member.json"
}

ensure_member_descriptor() {
  local node_id="$1"
  local underlay_ip="$2"
  if [[ -f "$state_dir/member.json" ]] \
    && jq -e \
      --arg node_id "$node_id" \
      --arg underlay_ip "$underlay_ip" \
      --arg network_plane "$DATABASE_NETWORK_PLANE" '
        select(.node_id == $node_id)
        | select(.underlay_ip == $underlay_ip)
        | select(.network_plane == $network_plane)
      ' "$state_dir/member.json" >/dev/null 2>&1; then
    return
  fi
  local empty
  empty="$(mktemp "$state_dir/reachability-empty.XXXXXX")"
  publish_member_descriptor "$node_id" "$underlay_ip" "" "$empty"
  rm -f "$empty"
}

write_bundle_handlers() {
  cat >"$state_dir/serve-bundle.sh" <<'EOF'
#!/bin/sh
set -eu
bundle_server_env=${HETERONETWORK_DB_BUNDLE_SERVER_ENV:-/etc/heteronetwork/postgres-autopilot/bundle-server.env}
case "$bundle_server_env" in
  /*) ;;
  *) exit 1 ;;
esac
[ -f "$bundle_server_env" ] && [ ! -L "$bundle_server_env" ] || exit 1
. "$bundle_server_env"
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
bundle_peer_is_authorized() {
  authorization_path="$1"
  [ -n "${SOCAT_PEERADDR:-}" ] \
    && [ -f "$authorization_path" ] \
    && [ ! -L "$authorization_path" ] \
    && grep -Fqx -- "$SOCAT_PEERADDR" "$authorization_path"
}
case "$request" in
  "GET /health HTTP/1.1")
    body=ready
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "${#body}" "$body"
    ;;
  "GET /v1/postgres-ha/member HTTP/1.1")
    if [ ! -s "$MEMBER_DESCRIPTOR" ]; then
      body=waiting
      printf 'HTTP/1.1 503 Service Unavailable\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "${#body}" "$body"
      exit 0
    fi
    length=$(wc -c <"$MEMBER_DESCRIPTOR" | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n' \
      "$length"
    cat "$MEMBER_DESCRIPTOR"
    ;;
  "GET /v1/postgres-ha/bundle HTTP/1.1")
    if ! bundle_peer_is_authorized "$BUNDLE_MEMBER_VPN_PATH"; then
      body=forbidden
      printf 'HTTP/1.1 403 Forbidden\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "${#body}" "$body"
      exit 0
    fi
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
  "GET /v1/postgres-ha/proxy-bundle HTTP/1.1")
    if ! bundle_peer_is_authorized "$PROXY_BUNDLE_VPN_PATH"; then
      body=forbidden
      printf 'HTTP/1.1 403 Forbidden\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "${#body}" "$body"
      exit 0
    fi
    if [ ! -s "$PROXY_BUNDLE_ARCHIVE" ]; then
      body=waiting
      printf 'HTTP/1.1 503 Service Unavailable\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "${#body}" "$body"
      exit 0
    fi
    length=$(wc -c <"$PROXY_BUNDLE_ARCHIVE" | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n' \
      "$length"
    cat "$PROXY_BUNDLE_ARCHIVE"
    ;;
  *)
    body='not found'
    printf 'HTTP/1.1 404 Not Found\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
      "${#body}" "$body"
    ;;
esac
EOF
  chmod 0700 "$state_dir/serve-bundle.sh"

  install -d -m 0755 "$(dirname "$underlay_health_handler")"
  local handler_temporary
  handler_temporary="$(mktemp "$state_dir/underlay-health.XXXXXX")"
  cat >"$handler_temporary" <<'PY'
#!/usr/bin/env python3
import argparse
import selectors
import socket
import time

MAX_REQUEST_BYTES = 4096


def response(status, reason, body):
    payload = body.encode("ascii")
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + payload


READY = response(200, "OK", "ready")
NOT_FOUND = response(404, "Not Found", "not found")
TOO_LARGE = response(413, "Content Too Large", "request too large")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--listen-address", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--max-connections", required=True, type=int)
    parser.add_argument("--read-timeout", required=True, type=float)
    args = parser.parse_args()
    if not 1 <= args.max_connections <= 32 or not 0.1 <= args.read_timeout <= 10:
        raise SystemExit("invalid health listener bounds")

    selector = selectors.DefaultSelector()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_address, args.port))
    listener.listen(args.max_connections)
    listener.setblocking(False)
    selector.register(listener, selectors.EVENT_READ)
    clients = {}

    def close_client(client):
        clients.pop(client, None)
        try:
            selector.unregister(client)
        except (KeyError, ValueError):
            pass
        client.close()

    def send_and_close(client, payload):
        try:
            client.setblocking(True)
            client.settimeout(0.5)
            client.sendall(payload)
        except OSError:
            pass
        finally:
            close_client(client)

    while True:
        now = time.monotonic()
        for key, _ in selector.select(timeout=0.25):
            if key.fileobj is listener:
                client, _ = listener.accept()
                if len(clients) >= args.max_connections:
                    client.close()
                    continue
                client.setblocking(False)
                clients[client] = [bytearray(), now + args.read_timeout]
                selector.register(client, selectors.EVENT_READ)
                continue

            client = key.fileobj
            state = clients.get(client)
            if state is None:
                continue
            try:
                chunk = client.recv(MAX_REQUEST_BYTES + 1 - len(state[0]))
            except (BlockingIOError, OSError):
                chunk = b""
            if not chunk:
                close_client(client)
                continue
            state[0].extend(chunk)
            if len(state[0]) > MAX_REQUEST_BYTES:
                send_and_close(client, TOO_LARGE)
                continue
            if b"\r\n\r\n" not in state[0] and b"\n\n" not in state[0]:
                continue
            request_line = bytes(state[0]).splitlines()[0] if state[0] else b""
            payload = READY if request_line == b"GET /health HTTP/1.1" else NOT_FOUND
            send_and_close(client, payload)

        now = time.monotonic()
        for client, (_, deadline) in list(clients.items()):
            if deadline <= now:
                close_client(client)


if __name__ == "__main__":
    main()
PY
  chmod 0755 "$handler_temporary"
  underlay_health_handler_changed=0
  if [[ ! -f "$underlay_health_handler" ]] \
    || ! cmp -s "$handler_temporary" "$underlay_health_handler"; then
    if [[ "$(id -u)" == "0" ]]; then
      install -o root -g root -m 0755 \
        "$handler_temporary" "$underlay_health_handler"
    else
      install -m 0755 "$handler_temporary" "$underlay_health_handler"
    fi
    underlay_health_handler_changed=1
  fi
  rm -f "$handler_temporary"
}

render_bundle_listener_unit() {
  local description="$1"
  local listen_address="$2"
  local handler="$3"
  local dependencies="$4"
  cat <<EOF
[Unit]
Description=${description}
${dependencies}

[Service]
Type=simple
ExecStart=/usr/bin/socat -T 15 TCP4-LISTEN:${BUNDLE_PORT},bind=${listen_address},reuseaddr,fork,max-children=64 EXEC:${handler},nofork
Restart=always
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=${state_dir}
RestrictAddressFamilies=AF_INET AF_UNIX
TasksMax=130
MemoryMax=256M
LimitNOFILE=512

[Install]
WantedBy=multi-user.target
EOF
}

render_underlay_listener_unit() {
  local description="$1"
  local listen_address="$2"
  local handler="$3"
  cat <<EOF
[Unit]
Description=${description}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/python3 ${handler} --listen-address ${listen_address} --port ${BUNDLE_PORT} --max-connections ${UNDERLAY_HEALTH_MAX_CONNECTIONS} --read-timeout ${UNDERLAY_HEALTH_READ_TIMEOUT_SECONDS}
Restart=always
RestartSec=2s
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
TasksMax=4
MemoryMax=64M
LimitNOFILE=64
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

install_bundle_listener_unit() {
  local service_name="$1"
  local description="$2"
  local listen_address="$3"
  local handler="$4"
  local dependencies="$5"
  local unit_name="${service_name}.service"
  local unit_path="/etc/systemd/system/${unit_name}"
  local unit_temporary unit_changed=0
  unit_temporary="$(mktemp "$state_dir/${unit_name}.XXXXXX")"
  render_bundle_listener_unit \
    "$description" "$listen_address" "$handler" "$dependencies" \
    >"$unit_temporary"
  if [[ ! -f "$unit_path" ]] || ! cmp -s "$unit_temporary" "$unit_path"; then
    install -o root -g root -m 0644 "$unit_temporary" "$unit_path"
    unit_changed=1
  fi
  rm -f "$unit_temporary"
  ((unit_changed == 0)) || systemctl daemon-reload
  systemctl enable "$unit_name" >/dev/null
  if ! systemctl is-active --quiet "$unit_name"; then
    systemctl start "$unit_name"
  elif ((unit_changed == 1)); then
    systemctl restart "$unit_name"
  fi
}

install_underlay_listener_unit() {
  local service_name="$1"
  local description="$2"
  local listen_address="$3"
  local handler="$4"
  local handler_changed="$5"
  local unit_name="${service_name}.service"
  local unit_path="/etc/systemd/system/${unit_name}"
  local unit_temporary unit_changed=0
  unit_temporary="$(mktemp "$state_dir/${unit_name}.XXXXXX")"
  render_underlay_listener_unit \
    "$description" "$listen_address" "$handler" >"$unit_temporary"
  if [[ ! -f "$unit_path" ]] || ! cmp -s "$unit_temporary" "$unit_path"; then
    install -o root -g root -m 0644 "$unit_temporary" "$unit_path"
    unit_changed=1
  fi
  rm -f "$unit_temporary"
  ((unit_changed == 0)) || systemctl daemon-reload
  systemctl enable "$unit_name" >/dev/null
  if ! systemctl is-active --quiet "$unit_name"; then
    systemctl start "$unit_name"
  elif ((unit_changed == 1 || handler_changed == 1)); then
    systemctl restart "$unit_name"
  fi
}

start_bundle_servers() {
  local vpn_ip="$1"
  local node_id="$2"
  local underlay_ip="$3"
  ensure_member_descriptor "$node_id" "$underlay_ip"
  write_proxy_bundle_vpn_snapshot \
    || die "database proxy bundle authorization exceeds the bounded candidate set"
  publish_proxy_bundle_archive
  cat >"$state_dir/bundle-server.env" <<EOF
BUNDLE_BEARER_TOKEN=${HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN}
BUNDLE_ARCHIVE=${bundle_archive}
BUNDLE_MEMBER_VPN_PATH=${bundle_member_vpn_path}
PROXY_BUNDLE_ARCHIVE=${proxy_bundle_archive}
PROXY_BUNDLE_VPN_PATH=${proxy_bundle_vpn_path}
MEMBER_DESCRIPTOR=${state_dir}/member.json
EOF
  chmod 0600 "$state_dir/bundle-server.env"
  write_bundle_handlers
  install_bundle_listener_unit \
    heteronetwork-postgres-bundle \
    "HeteroNetwork PostgreSQL HA overlay discovery and bundle endpoint" \
    "$vpn_ip" \
    "$state_dir/serve-bundle.sh" \
    $'Requires=heteronetwork-agent.service\nAfter=heteronetwork-agent.service'
  install_underlay_listener_unit \
    heteronetwork-postgres-underlay-probe \
    "HeteroNetwork PostgreSQL HA underlay reachability endpoint" \
    "$underlay_ip" \
    "$underlay_health_handler" \
    "$underlay_health_handler_changed"
}

stop_bundle_servers() {
  systemctl disable --now \
    heteronetwork-postgres-bundle.service \
    heteronetwork-postgres-underlay-probe.service >/dev/null 2>&1 || true
}

snapshot_contains_node_id() {
  local path="$1"
  local node_id="$2"
  awk -F '\t' -v node_id="$node_id" '
    $1 == node_id { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$path"
}

bundle_contains_node_id() {
  local node_id="$1"
  [[ -d "$bundle_dir" ]] || return 1
  load_bundle_manifest "$bundle_dir" || return 1
  member_name_for_node_id "$manifest_member_identities" "$node_id" >/dev/null 2>&1
}

write_bundle_member_vpn_snapshot() {
  full_database_bundle_exists || return 1
  load_bundle_manifest "$bundle_dir" || return 1
  local temporary
  temporary="$(mktemp "$state_dir/bundle-member-vpn.XXXXXX")"
  if ! python3 - \
      "$manifest_member_identities" "$authoritative_path" >"$temporary" <<'PY'
import ipaddress
import sys

identities_raw, authoritative_path = sys.argv[1:]
vpn_by_node_id = {}
with open(authoritative_path, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 2:
            raise SystemExit("invalid authoritative database peer row")
        node_id, vpn_ip = fields
        if node_id in vpn_by_node_id:
            raise SystemExit("duplicate authoritative database peer identity")
        if ipaddress.ip_address(vpn_ip).version != 4:
            raise SystemExit("database peer VPN address must be IPv4")
        vpn_by_node_id[node_id] = vpn_ip

allowed = []
seen_node_ids = set()
seen_vpn_ips = set()
for entry in identities_raw.split(","):
    name, separator, node_id = entry.partition("=")
    if not separator or not name or not node_id or node_id in seen_node_ids:
        raise SystemExit("invalid persisted database member identity")
    vpn_ip = vpn_by_node_id.get(node_id)
    if vpn_ip is None:
        seen_node_ids.add(node_id)
        continue
    if vpn_ip in seen_vpn_ips:
        raise SystemExit("duplicate database member VPN address")
    allowed.append(vpn_ip)
    seen_node_ids.add(node_id)
    seen_vpn_ips.add(vpn_ip)

for vpn_ip in sorted(allowed, key=lambda value: ipaddress.ip_address(value)):
    print(vpn_ip)
PY
  then
    rm -f "$temporary"
    return 1
  fi
  install -m 0600 "$temporary" "$bundle_member_vpn_path"
  rm -f "$temporary"
}

write_proxy_bundle_vpn_snapshot() {
  local temporary
  temporary="$(mktemp "$state_dir/proxy-bundle-vpn.XXXXXX")"
  if ! python3 - \
      "$selected_path" "$active_path" \
      "$MAX_DATABASE_CANDIDATE_COUNT" >"$temporary" <<'PY'
import ipaddress
import sys

selected_path, active_path, limit_raw = sys.argv[1:]
limit = int(limit_raw)
active = set()
with open(active_path, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 2:
            raise SystemExit("invalid active database peer row")
        active.add(tuple(fields))

allowed = []
seen_node_ids = set()
seen_vpn_ips = set()
with open(selected_path, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 2:
            raise SystemExit("invalid selected database peer row")
        node_id, vpn_ip = fields
        if node_id in seen_node_ids or vpn_ip in seen_vpn_ips:
            raise SystemExit("duplicate selected proxy bundle recipient")
        if (node_id, vpn_ip) in active:
            if ipaddress.ip_address(vpn_ip).version != 4:
                raise SystemExit("proxy bundle recipient VPN address must be IPv4")
            allowed.append(vpn_ip)
        seen_node_ids.add(node_id)
        seen_vpn_ips.add(vpn_ip)
if len(seen_node_ids) > limit or len(allowed) > limit:
    raise SystemExit("proxy bundle authorization exceeds the candidate limit")
for vpn_ip in sorted(allowed, key=lambda value: ipaddress.ip_address(value)):
    print(vpn_ip)
PY
  then
    rm -f "$temporary"
    return 1
  fi
  install -m 0600 "$temporary" "$proxy_bundle_vpn_path"
  rm -f "$temporary"
}

publish_proxy_bundle_archive() {
  if ! full_database_bundle_exists && ! proxy_only_bundle_exists; then
    rm -f "$proxy_bundle_archive"
    return
  fi
  local stage temporary
  stage="$state_dir/proxy-publish.$RANDOM.$RANDOM"
  install -d -m 0700 "$stage" "$stage/ca" "$stage/secrets"
  install -m 0600 "$bundle_dir/manifest.env" "$stage/manifest.env"
  install -m 0600 "$bundle_dir/cluster-id" "$stage/cluster-id"
  install -m 0644 "$bundle_dir/ca/ca.crt" "$stage/ca/ca.crt"
  install -m 0600 \
    "$bundle_dir/secrets/application.password" \
    "$stage/secrets/application.password"
  printf '%s\n' "$PROXY_BUNDLE_FORMAT_VERSION" \
    >"$stage/$proxy_bundle_marker_name"
  chmod 0600 "$stage/$proxy_bundle_marker_name"
  if ! validate_proxy_bundle_directory "$stage"; then
    rm -rf "$stage"
    die "refusing to publish an invalid database proxy bundle"
  fi
  temporary="$(mktemp "$state_dir/proxy-bundle.tar.gz.XXXXXX")"
  tar --format=ustar --create --gzip --file "$temporary" --directory "$stage" .
  chmod 0600 "$temporary"
  mv "$temporary" "$proxy_bundle_archive"
  rm -rf "$stage"
}

publish_bundle_archive() {
  full_database_bundle_exists || return
  write_bundle_member_vpn_snapshot \
    || die "database bundle members are absent from the authoritative registry"
  local temporary
  temporary="$(mktemp "$state_dir/bundle.tar.gz.XXXXXX")"
  tar --format=ustar --create --gzip --file "$temporary" --directory "$bundle_dir" .
  chmod 0600 "$temporary"
  mv "$temporary" "$bundle_archive"
  publish_proxy_bundle_archive
}

bundle_content_digest() {
  local directory="$1"
  python3 - "$directory" <<'PY'
import hashlib
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
if not root.is_dir() or root.is_symlink():
    raise SystemExit("invalid database bundle directory")

digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix().encode("utf-8")
    mode = path.lstat().st_mode
    if stat.S_ISDIR(mode):
        kind = b"d"
    elif stat.S_ISREG(mode):
        kind = b"f"
    else:
        raise SystemExit("unsupported object in database bundle")
    digest.update(kind)
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update((mode & 0o777).to_bytes(2, "big"))
    if kind == b"f":
        size = path.stat().st_size
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
print(digest.hexdigest())
PY
}

bundle_replication_quorum_reached() {
  local local_node_id="$1"
  local authoritative_digest="$2"
  load_bundle_manifest "$bundle_dir" || return 1
  local expected_revision="$manifest_revision"
  local expected_digest
  expected_digest="$(bundle_content_digest "$bundle_dir")" || return 1
  local actual_count required acknowledgements=0
  actual_count="$(member_count "$manifest_dcs_bootstrap_members")"
  required="$((10#$actual_count / 2 + 1))"

  local entry name node_id vpn_ip descriptor underlay_ip
  local -a entries
  IFS=, read -r -a entries <<<"$manifest_dcs_bootstrap_members"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    node_id="$(member_value_for_name "$manifest_member_identities" "$name")" \
      || return 1
    if [[ "$node_id" == "$local_node_id" ]]; then
      acknowledgements=$((acknowledgements + 1))
      continue
    fi
    vpn_ip="$(awk -F '\t' -v node_id="$node_id" '
      $1 == node_id {
        count += 1
        vpn_ip = $2
      }
      END {
        if (count != 1 || vpn_ip == "") {
          exit 1
        }
        print vpn_ip
      }
    ' "$selected_path")" || continue
    descriptor="$(peer_member_descriptor "$vpn_ip" "$node_id")" || continue
    underlay_ip="$(underlay_from_member_descriptor \
      "$descriptor" "$node_id")" || continue
    descriptor_is_current \
      "$descriptor" "$node_id" "$underlay_ip" "$authoritative_digest" \
      || continue
    if jq -e \
      --argjson revision "$expected_revision" \
      --arg digest "$expected_digest" '
        .bundle_revision == $revision
        and .bundle_digest == $digest
      ' <<<"$descriptor" >/dev/null; then
      acknowledgements=$((acknowledgements + 1))
    fi
  done
  ((acknowledgements >= required))
}

download_best_bundle() {
  local current_revision=0
  local current_digest=""
  if full_database_bundle_exists \
    && load_bundle_manifest "$bundle_dir" 2>/dev/null; then
    current_revision="$manifest_revision"
    current_digest="$(bundle_content_digest "$bundle_dir")" || return 1
  fi
  local best_revision="$current_revision"
  local best_digest="$current_digest"
  local best_directory=""
  local node_id vpn_ip archive extracted candidate_revision candidate_digest
  while IFS=$'\t' read -r node_id vpn_ip; do
    archive="$(mktemp "$state_dir/download.XXXXXX")"
    if ! curl --config "$curl_config_path" \
      "http://${vpn_ip}:${BUNDLE_PORT}/v1/postgres-ha/bundle" \
      --output "$archive" 2>/dev/null; then
      rm -f "$archive"
      continue
    fi
    extracted="$state_dir/downloaded.$RANDOM.$RANDOM"
    if ! safe_extract_bundle "$archive" "$extracted" >/dev/null 2>&1 \
      || ! validate_bundle_directory "$extracted" \
      || bundle_uses_registered_vpn_address "$extracted"; then
      rm -f "$archive"
      rm -rf "$extracted"
      continue
    fi
    candidate_revision="$manifest_revision"
    candidate_digest="$(bundle_content_digest "$extracted")" || {
      rm -f "$archive"
      rm -rf "$extracted"
      continue
    }
    rm -f "$archive"
    if ((10#$candidate_revision > 10#$best_revision)); then
      [[ -z "$best_directory" ]] || rm -rf "$best_directory"
      best_revision="$candidate_revision"
      best_digest="$candidate_digest"
      best_directory="$extracted"
    elif ((10#$candidate_revision == 10#$best_revision)) \
      && [[ -n "$best_digest" && "$candidate_digest" != "$best_digest" ]]; then
      rm -rf "$extracted"
      [[ -z "$best_directory" ]] || rm -rf "$best_directory"
      die "divergent database bundles share topology revision $candidate_revision"
    else
      rm -rf "$extracted"
    fi
  done <"$selected_path"

  if [[ -n "$best_directory" ]]; then
    install_bundle_directory "$best_directory"
    publish_bundle_archive
    log "installed replicated database topology revision $best_revision"
  fi
}

download_best_proxy_bundle() {
  full_database_bundle_exists && return 0
  local current_revision=0
  local current_digest=""
  if proxy_only_bundle_exists \
    && validate_proxy_bundle_directory "$bundle_dir"; then
    current_revision="$manifest_revision"
    current_digest="$(bundle_content_digest "$bundle_dir")" || return 1
  fi
  local best_revision="$current_revision"
  local best_digest="$current_digest"
  local best_directory=""
  local node_id vpn_ip archive extracted candidate_revision candidate_digest
  while IFS=$'\t' read -r node_id vpn_ip; do
    archive="$(mktemp "$state_dir/proxy-download.XXXXXX")"
    if ! curl --config "$curl_config_path" \
      "http://${vpn_ip}:${BUNDLE_PORT}/v1/postgres-ha/proxy-bundle" \
      --output "$archive" 2>/dev/null; then
      rm -f "$archive"
      continue
    fi
    extracted="$state_dir/proxy-downloaded.$RANDOM.$RANDOM"
    if ! safe_extract_bundle "$archive" "$extracted" >/dev/null 2>&1 \
      || ! validate_proxy_bundle_directory "$extracted" \
      || bundle_uses_registered_vpn_address "$extracted"; then
      rm -f "$archive"
      rm -rf "$extracted"
      continue
    fi
    candidate_revision="$manifest_revision"
    candidate_digest="$(bundle_content_digest "$extracted")" || {
      rm -f "$archive"
      rm -rf "$extracted"
      continue
    }
    rm -f "$archive"
    if ((10#$candidate_revision > 10#$best_revision)); then
      [[ -z "$best_directory" ]] || rm -rf "$best_directory"
      best_revision="$candidate_revision"
      best_digest="$candidate_digest"
      best_directory="$extracted"
    elif ((10#$candidate_revision == 10#$best_revision)) \
      && [[ -n "$best_digest" && "$candidate_digest" != "$best_digest" ]]; then
      rm -rf "$extracted"
      [[ -z "$best_directory" ]] || rm -rf "$best_directory"
      die "divergent database proxy bundles share topology revision $candidate_revision"
    else
      rm -rf "$extracted"
    fi
  done <"$selected_path"

  if [[ -n "$best_directory" ]]; then
    install_proxy_bundle_directory "$best_directory"
    publish_proxy_bundle_archive
    log "installed database proxy bundle for topology revision $best_revision"
  fi
  proxy_only_bundle_exists && validate_proxy_bundle_directory "$bundle_dir"
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
  local output="" index=0 _vpn_ip _node_id underlay_ip name
  while IFS=$'\t' read -r _vpn_ip _node_id underlay_ip; do
    ((index < MAX_DATABASE_MEMBER_COUNT)) || break
    name="$(member_name_for_index "$index")"
    [[ -z "$output" ]] || output+=","
    output+="${name}=${underlay_ip}"
    index=$((index + 1))
  done <"$eligible_path"
  printf '%s' "$output"
}

initial_member_identities_from_snapshot() {
  local output="" index=0 _vpn_ip node_id _underlay_ip name
  while IFS=$'\t' read -r _vpn_ip node_id _underlay_ip; do
    ((index < MAX_DATABASE_MEMBER_COUNT)) || break
    name="$(member_name_for_index "$index")"
    [[ -z "$output" ]] || output+=","
    output+="${name}=${node_id}"
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
  python3 - "$1" "$2" "$eligible_path" "$MAX_DATABASE_MEMBER_COUNT" <<'PY'
import string
import sys

current = sys.argv[1].split(",")
identities = sys.argv[2].split(",")
snapshot = sys.argv[3]
limit = int(sys.argv[4])

def parse(entries, label):
    result = {}
    order = []
    for entry in entries:
        name, separator, value = entry.partition("=")
        if not separator or not name or not value or name in result:
            raise SystemExit(f"invalid {label} entry")
        result[name] = value
        order.append(name)
    return result, order

addresses_by_name, names = parse(current, "database member")
node_ids_by_name, identity_names = parse(identities, "database identity")
if names != identity_names:
    raise SystemExit("database member and identity order differ")
name_by_address = {address: name for name, address in addresses_by_name.items()}
name_by_node_id = {node_id: name for name, node_id in node_ids_by_name.items()}
if len(name_by_address) != len(names) or len(name_by_node_id) != len(names):
    raise SystemExit("duplicate database address or node identity")

with open(snapshot, encoding="utf-8") as source:
    for line in source:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 3:
            raise SystemExit("invalid eligible database member row")
        _, node_id, address = fields
        if node_id in name_by_node_id:
            name = name_by_node_id[node_id]
            if addresses_by_name[name] != address:
                raise SystemExit(
                    f"underlay address drift for {node_id}: "
                    f"{addresses_by_name[name]} -> {address}"
                )
            continue
        if address in name_by_address:
            raise SystemExit(
                f"underlay address {address} is already bound to "
                f"{node_ids_by_name[name_by_address[address]]}"
            )
        if len(names) >= limit:
            continue
        for index in range(limit):
            suffix = (
                string.ascii_lowercase[index]
                if index < 26
                else "a" + string.ascii_lowercase[index - 26]
            )
            name = f"db-{suffix}"
            if name not in addresses_by_name:
                break
        else:
            raise SystemExit("no generated database member name is available")
        names.append(name)
        addresses_by_name[name] = address
        node_ids_by_name[name] = node_id
        name_by_address[address] = name
        name_by_node_id[node_id] = name

print(",".join(f"{name}={addresses_by_name[name]}" for name in names))
print(",".join(f"{name}={node_ids_by_name[name]}" for name in names))
PY
}

member_count() {
  tr ',' '\n' <<<"$1" | wc -l | tr -d ' '
}

target_dcs_topology() {
  local all_members="$1"
  python3 - "$all_members" "$TARGET_DCS_MEMBER_COUNT" <<'PY'
import sys

members = sys.argv[1].split(",")
target = int(sys.argv[2])
if len(members) < target:
    raise SystemExit("not enough database members for the target DCS topology")
print(",".join(members[:target]))
PY
}

member_name_for_ip() {
  local input="$1"
  local address="$2"
  tr ',' '\n' <<<"$input" \
    | awk -F= -v address="$address" '$2 == address { print $1; found = 1 } END { if (!found) exit 1 }'
}

member_name_for_node_id() {
  local input="$1"
  local node_id="$2"
  tr ',' '\n' <<<"$input" \
    | awk -F= -v node_id="$node_id" \
      '$2 == node_id { print $1; found = 1 } END { if (!found) exit 1 }'
}

member_value_for_name() {
  local input="$1"
  local name="$2"
  tr ',' '\n' <<<"$input" \
    | awk -F= -v name="$name" \
      '$1 == name { print $2; found = 1 } END { if (!found) exit 1 }'
}

snapshot_matches_bundle_identities() {
  local path="$1"
  load_bundle_manifest "$bundle_dir" || return 1
  local entry name node_id expected_address actual_address
  local -a entries
  IFS=, read -r -a entries <<<"$manifest_member_identities"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    node_id="${entry#*=}"
    expected_address="$(member_value_for_name "$manifest_members" "$name")" \
      || return 1
    actual_address="$(awk -F '\t' -v node_id="$node_id" '
      $2 == node_id {
        count += 1
        address = $3
      }
      END {
        if (count != 1 || address == "") {
          exit 1
        }
        print address
      }
    ' "$path")" || return 1
    if [[ "$actual_address" != "$expected_address" ]]; then
      log "refusing underlay address drift for $node_id ($expected_address -> $actual_address)"
      return 1
    fi
  done
}

bundle_uses_registered_vpn_address() (
  local directory="$1"
  load_bundle_manifest "$directory" || return 0
  local entry vpn_ip
  local -a entries
  IFS=, read -r -a entries <<<"$manifest_members"
  for entry in "${entries[@]}"; do
    vpn_ip="${entry#*=}"
    registered_vpn_contains "$vpn_ip" && return 0
  done
  return 1
)

bundle_routes_use_interface() {
  local members_input="$1"
  local local_underlay_ip="$2"
  local local_underlay_interface="$3"
  local entry address
  local -a entries
  IFS=, read -r -a entries <<<"$members_input"
  for entry in "${entries[@]}"; do
    address="${entry#*=}"
    route_to_address_uses_interface \
      "$address" "$local_underlay_ip" "$local_underlay_interface" \
      || return 1
  done
}

configure_helper_environment() {
  local directory="$1"
  local local_node_id="$2"
  local local_underlay_ip="$3"
  load_bundle_manifest "$directory" || die "database bundle manifest is unavailable"
  HETERONETWORK_DB_NODE_NAME="$(
    member_name_for_node_id "$manifest_member_identities" "$local_node_id"
  )"
  local expected_underlay_ip
  expected_underlay_ip="$(
    member_value_for_name "$manifest_members" "$HETERONETWORK_DB_NODE_NAME"
  )"
  [[ "$expected_underlay_ip" == "$local_underlay_ip" ]] \
    || die "underlay address drift is refused for $local_node_id ($expected_underlay_ip -> $local_underlay_ip)"
  HETERONETWORK_DB_NODE_ADDRESS="$local_underlay_ip"
  HETERONETWORK_DB_INTERFACE="$(interface_for_address "$local_underlay_ip")" \
    || die "database underlay address $local_underlay_ip is not assigned to exactly one interface"
  [[ "$HETERONETWORK_DB_INTERFACE" != "heteronetwork0" ]] \
    || die "database services must not bind to the HeteroNetwork overlay interface"
  bundle_routes_use_interface \
    "$manifest_members" "$local_underlay_ip" "$HETERONETWORK_DB_INTERFACE" \
    || die "a database member route does not use selected host-underlay interface $HETERONETWORK_DB_INTERFACE"
  export HETERONETWORK_DB_INTERFACE HETERONETWORK_DB_NODE_NAME HETERONETWORK_DB_NODE_ADDRESS
}

wait_for_bundle_health() {
  local attempt output
  for ((attempt = 1; attempt <= BUNDLE_HEALTH_RETRY_ATTEMPTS; attempt += 1)); do
    if output="$(run_helper_for_bundle "$bundle_dir" verify 2>&1)"; then
      log "$output"
      return 0
    fi
    if ((attempt == BUNDLE_HEALTH_RETRY_ATTEMPTS)); then
      log "database topology revision $manifest_revision is not healthy yet: $output"
      return 1
    fi
    sleep "$BUNDLE_HEALTH_RETRY_SECONDS"
  done
}

apply_local_bundle() {
  local local_node_id="$1"
  local local_underlay_ip="$2"
  load_bundle_manifest "$bundle_dir" || return
  local local_name expected_underlay_ip
  if ! local_name="$(
    member_name_for_node_id "$manifest_member_identities" "$local_node_id"
  )"; then
    log "node is outside the ${MAX_DATABASE_MEMBER_COUNT}-member database replica limit"
    return
  fi
  expected_underlay_ip="$(member_value_for_name "$manifest_members" "$local_name")" \
    || return
  if [[ "$expected_underlay_ip" != "$local_underlay_ip" ]]; then
    log "refusing underlay address drift for $local_node_id ($expected_underlay_ip -> $local_underlay_ip)"
    return
  fi
  if member_value_for_name \
      "$manifest_dcs_members" "$local_name" >/dev/null 2>&1 \
    && ! member_value_for_name \
      "$manifest_dcs_bootstrap_members" "$local_name" >/dev/null 2>&1; then
    log "waiting for $local_name to be added to the actual DCS membership"
    return
  fi
  configure_helper_environment "$bundle_dir" "$local_node_id" "$local_underlay_ip"
  local applied_revision=0
  [[ -f "$applied_revision_path" ]] && applied_revision="$(<"$applied_revision_path")"
  if [[ "$applied_revision" == "$manifest_revision" ]] \
    && systemctl is-active --quiet heteronetwork-db.service; then
    return
  fi
  local configured_revision=0
  [[ -f "$configured_revision_path" ]] \
    && configured_revision="$(<"$configured_revision_path")"
  if [[ "$configured_revision" != "$manifest_revision" ]] \
    || ! systemctl is-active --quiet heteronetwork-db.service; then
    local initial_state="existing"
    [[ "$manifest_revision" == "1" ]] && initial_state="new"
    log "applying database topology revision $manifest_revision as $local_name"
    env \
      "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
      "HETERONETWORK_DB_INTERFACE=$HETERONETWORK_DB_INTERFACE" \
      "HETERONETWORK_DB_NODE_NAME=$local_name" \
      "HETERONETWORK_DB_NODE_ADDRESS=$local_underlay_ip" \
      "HETERONETWORK_DB_MEMBERS=$manifest_members" \
      "HETERONETWORK_DB_MEMBER_IDENTITIES=$manifest_member_identities" \
      "HETERONETWORK_DB_DCS_MEMBERS=$manifest_dcs_members" \
      "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=$manifest_dcs_bootstrap_members" \
      "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=$initial_state" \
      "HETERONETWORK_DB_PROXY_BACKENDS=$manifest_members" \
      "HETERONETWORK_DB_CLIENT_CIDRS=$manifest_client_cidrs" \
      "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=$manifest_extra_hba_entries" \
      "HETERONETWORK_DB_BUNDLE_DIR=$bundle_dir" \
      "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
      "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
      "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
      "HETERONETWORK_DB_TOPOLOGY_REVISION=$manifest_revision" \
      "HETERONETWORK_DB_NETWORK_PLANE=$manifest_network_plane" \
      "$helper" reconfigure-node
    printf '%s\n' "$manifest_revision" >"$configured_revision_path"
    chmod 0600 "$configured_revision_path"
  fi
  if ! wait_for_bundle_health; then
    return
  fi
  printf '%s\n' "$manifest_revision" >"$applied_revision_path"
  chmod 0600 "$applied_revision_path"
}

apply_local_proxy_bundle() {
  local local_underlay_ip="$1"
  local local_underlay_interface="$2"
  validate_proxy_bundle_directory "$bundle_dir" || return 1
  bundle_routes_use_interface \
    "$manifest_members" "$local_underlay_ip" "$local_underlay_interface" \
    || {
      log "database proxy backends are not reachable through $local_underlay_interface"
      return 1
    }
  local digest applied_digest=""
  digest="$(bundle_content_digest "$bundle_dir")" || return 1
  [[ -f "$proxy_applied_digest_path" ]] \
    && applied_digest="$(<"$proxy_applied_digest_path")"
  if [[ "$applied_digest" == "$digest" \
    && -f /etc/ssl/certs/heteronetwork-postgres-ha-ca.crt \
    && ! -L /etc/ssl/certs/heteronetwork-postgres-ha-ca.crt ]] \
    && systemctl is-active --quiet heteronetwork-db-proxy.service; then
    return 0
  fi
  log "applying proxy-only database topology revision $manifest_revision"
  run_helper_for_bundle "$bundle_dir" install-proxy
  systemctl is-active --quiet heteronetwork-db-proxy.service || return 1
  printf '%s\n' "$digest" >"$proxy_applied_digest_path"
  chmod 0600 "$proxy_applied_digest_path"
}

bootstrap_bundle() {
  local members member_identities dcs_count dcs temporary
  members="$(initial_members_from_snapshot)"
  member_identities="$(initial_member_identities_from_snapshot)"
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
    "HETERONETWORK_DB_MEMBER_IDENTITIES=$member_identities" \
    "HETERONETWORK_DB_DCS_MEMBERS=$dcs" \
    "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=$dcs" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=new" \
    "HETERONETWORK_DB_CLIENT_CIDRS=${HETERONETWORK_DB_CLIENT_CIDRS:-}" \
    "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=${HETERONETWORK_DB_EXTRA_HBA_ENTRIES:-}" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=1" \
    "HETERONETWORK_DB_NETWORK_PLANE=$DATABASE_NETWORK_PLANE" \
    "$helper" init-bundle "$temporary"
  printf '%s\n' "$HETERONETWORK_DB_CLUSTER_ID" >"$temporary/cluster-id"
  chmod 0600 "$temporary/cluster-id"
  install_bundle_directory "$temporary"
  publish_bundle_archive
  log "created automatic database topology with $count replicas and $dcs_count DCS voters"
}

coordinator_node_id_for_bundle() {
  local node_id _vpn_ip
  while IFS=$'\t' read -r node_id _vpn_ip; do
    if member_name_for_node_id \
        "$manifest_member_identities" "$node_id" >/dev/null 2>&1; then
      printf '%s' "$node_id"
      return 0
    fi
  done <"$active_path"
  return 1
}

stage_topology() {
  local new_members="$1"
  local new_member_identities="$2"
  local new_dcs="$3"
  local new_dcs_bootstrap="$4"
  local new_revision="$5"
  local local_node_id="$6"
  local local_underlay_ip="$7"
  local stage="$state_dir/stage.$RANDOM.$RANDOM"
  cp -a "$bundle_dir" "$stage"
  local local_name
  local_name="$(
    member_name_for_node_id "$manifest_member_identities" "$local_node_id"
  )"
  env \
    "HETERONETWORK_DB_CLUSTER_NAME=$manifest_cluster_name" \
    "HETERONETWORK_DB_INTERFACE=$HETERONETWORK_DB_INTERFACE" \
    "HETERONETWORK_DB_NODE_NAME=$local_name" \
    "HETERONETWORK_DB_NODE_ADDRESS=$local_underlay_ip" \
    "HETERONETWORK_DB_MEMBERS=$new_members" \
    "HETERONETWORK_DB_MEMBER_IDENTITIES=$new_member_identities" \
    "HETERONETWORK_DB_DCS_MEMBERS=$new_dcs" \
    "HETERONETWORK_DB_DCS_BOOTSTRAP_MEMBERS=$new_dcs_bootstrap" \
    "HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE=existing" \
    "HETERONETWORK_DB_PROXY_BACKENDS=$new_members" \
    "HETERONETWORK_DB_CLIENT_CIDRS=$manifest_client_cidrs" \
    "HETERONETWORK_DB_EXTRA_HBA_ENTRIES=$manifest_extra_hba_entries" \
    "HETERONETWORK_DB_BUNDLE_DIR=$stage" \
    "HETERONETWORK_DB_SERVICE_NAME=$manifest_service_name" \
    "HETERONETWORK_DB_POSTGRES_PORT=$manifest_postgres_port" \
    "HETERONETWORK_DB_REST_PORT=$manifest_rest_port" \
    "HETERONETWORK_DB_TOPOLOGY_REVISION=$new_revision" \
    "HETERONETWORK_DB_NETWORK_PLANE=$manifest_network_plane" \
    "$helper" extend-bundle "$stage" >/dev/null
  printf '%s\n' "$HETERONETWORK_DB_CLUSTER_ID" >"$stage/cluster-id"
  chmod 0600 "$stage/cluster-id"
  printf '%s' "$stage"
}

reconcile_as_coordinator() {
  local local_node_id="$1"
  local local_underlay_ip="$2"
  local authoritative_digest="$3"
  configure_helper_environment \
    "$bundle_dir" "$local_node_id" "$local_underlay_ip"
  if ! systemctl is-active --quiet heteronetwork-db.service; then
    log "waiting for the coordinator database service"
    return
  fi

  local actual_dcs
  actual_dcs="$(
    run_helper_for_bundle "$bundle_dir" current-dcs-members 2>/dev/null
  )" || {
    log "waiting to read the actual DCS membership"
    return
  }
  [[ -n "$actual_dcs" ]] || {
    log "actual DCS membership is empty"
    return
  }

  load_bundle_manifest "$bundle_dir"
  if [[ "$actual_dcs" != "$manifest_dcs_bootstrap_members" ]]; then
    local membership_revision membership_stage
    membership_revision="$((10#$manifest_revision + 1))"
    membership_stage="$(stage_topology \
      "$manifest_members" "$manifest_member_identities" \
      "$manifest_dcs_members" "$actual_dcs" "$membership_revision" \
      "$local_node_id" "$local_underlay_ip")" || {
      log "waiting to persist the actual DCS membership"
      return
    }
    install_bundle_directory "$membership_stage"
    publish_bundle_archive
    log "published actual DCS membership at topology revision $membership_revision"
    return
  fi

  local expanded new_members new_member_identities new_dcs
  local members_changed=0 dcs_changed=0
  expanded="$(
    expand_members_from_snapshot \
      "$manifest_members" "$manifest_member_identities"
  )" || {
    log "database topology expansion is waiting because member identity or address drift was detected"
    return
  }
  [[ "$expanded" == *$'\n'* ]] || {
    log "database topology expansion returned an invalid member map"
    return
  }
  new_members="${expanded%%$'\n'*}"
  new_member_identities="${expanded#*$'\n'}"
  new_dcs="$manifest_dcs_members"
  if [[ "$new_members" != "$manifest_members" \
    || "$new_member_identities" != "$manifest_member_identities" ]]; then
    members_changed=1
  fi

  local dcs_count database_count
  dcs_count="$(member_count "$manifest_dcs_members")"
  database_count="$(member_count "$new_members")"
  if ((10#$dcs_count < TARGET_DCS_MEMBER_COUNT \
      && 10#$database_count >= TARGET_DCS_MEMBER_COUNT)) \
    && [[ "$actual_dcs" == "$manifest_dcs_members" ]]; then
    new_dcs="$(target_dcs_topology "$new_members")"
    dcs_changed=1
  fi
  if ((members_changed == 1 || dcs_changed == 1)); then
    local next_revision stage
    next_revision="$((10#$manifest_revision + 1))"
    stage="$(stage_topology \
      "$new_members" "$new_member_identities" \
      "$new_dcs" "$manifest_dcs_bootstrap_members" "$next_revision" \
      "$local_node_id" "$local_underlay_ip")"
    install_bundle_directory "$stage"
    publish_bundle_archive
    log "published database topology revision $next_revision"
    return
  fi

  if ! bundle_replication_quorum_reached \
      "$local_node_id" "$authoritative_digest"; then
    log "waiting for a DCS majority to acknowledge topology revision $manifest_revision"
    return
  fi

  local dcs_result
  dcs_result="$(run_helper_for_bundle "$bundle_dir" reconcile-dcs 2>&1)" || {
    log "DCS reconciliation is waiting: $dcs_result"
    return
  }
  log "$dcs_result"
  if [[ "$dcs_result" != *"already matches the requested topology."* ]]; then
    return
  fi
  run_helper_for_bundle "$bundle_dir" reconcile-patroni >/dev/null 2>&1 || true
}

reconcile_once() {
  local status identity local_vpn_ip local_node_id local_underlay_ip
  local proxy_eligible=0
  status="$(read_agent_status)" || {
    reset_convergence_state
    log "waiting for the local Agent status"
    return
  }
  identity="$(local_identity_row "$status")" || {
    reset_convergence_state
    log "waiting for a non-overlay local UDP underlay candidate"
    return
  }
  agent_status_is_direct_public "$status" && proxy_eligible=1
  IFS=$'\t' read -r local_vpn_ip local_node_id local_underlay_ip <<<"$identity"
  if unmanaged_legacy_database_exists; then
    reset_convergence_state
    log "existing database is not managed by autopilot; refusing a new bootstrap"
    return
  fi
  if ! write_registry_snapshots "$local_vpn_ip" "$local_node_id"; then
    reset_convergence_state
    log "waiting for the authenticated control-plane node registry"
    return
  fi
  if full_database_bundle_exists && ! load_bundle_manifest "$bundle_dir"; then
    reset_convergence_state
    log "existing database bundle lacks the ${DATABASE_NETWORK_PLANE} contract; refusing automatic migration"
    return
  fi
  if proxy_only_bundle_exists \
    && ! validate_proxy_bundle_directory "$bundle_dir"; then
    reset_convergence_state
    log "existing database proxy bundle is invalid"
    return
  fi
  if [[ -e "$bundle_dir" || -L "$bundle_dir" ]] \
    && ! full_database_bundle_exists \
    && ! proxy_only_bundle_exists; then
    reset_convergence_state
    log "existing database material has an unknown bundle type"
    return
  fi
  if [[ -d "$bundle_dir" ]] \
    && bundle_uses_registered_vpn_address "$bundle_dir"; then
    reset_convergence_state
    log "database bundle contains an overlay VPN address; refusing to apply it"
    return
  fi
  if full_database_bundle_exists && ! write_bundle_member_vpn_snapshot; then
    reset_convergence_state
    log "waiting to refresh the database bundle member authorization set"
    return
  fi
  if ! write_selected_snapshot; then
    reset_convergence_state
    log "waiting for the registry to include every persisted database member"
    return
  fi
  if ! snapshot_contains_node_id "$selected_path" "$local_node_id" \
    && ! bundle_contains_node_id "$local_node_id"; then
    stop_bundle_servers
    reset_convergence_state
    if ((proxy_eligible == 1)) && proxy_only_bundle_exists; then
      local outside_interface
      outside_interface="$(interface_for_address "$local_underlay_ip")" || {
        log "waiting for an unambiguous local host-underlay interface"
        return
      }
      apply_local_proxy_bundle "$local_underlay_ip" "$outside_interface" \
        || log "waiting to apply the retained database proxy bundle"
      log "node is outside the active database candidate pool; retained proxy-only services"
    elif ((proxy_eligible == 1)); then
      log "public node is waiting for a rotating candidate window to receive the database proxy bundle"
    else
      log "node is outside the active database candidate pool"
    fi
    return
  fi
  start_bundle_servers "$local_vpn_ip" "$local_node_id" "$local_underlay_ip"
  if ! download_best_bundle; then
    reset_convergence_state
    log "waiting for a valid replicated database bundle"
    return
  fi
  if ((proxy_eligible == 1)) && ! full_database_bundle_exists; then
    download_best_proxy_bundle \
      || log "waiting for a sanitized database proxy bundle"
  fi
  if full_database_bundle_exists && ! load_bundle_manifest "$bundle_dir"; then
    reset_convergence_state
    log "downloaded database bundle is invalid; refusing to apply it"
    return
  fi
  if proxy_only_bundle_exists \
    && ! validate_proxy_bundle_directory "$bundle_dir"; then
    reset_convergence_state
    log "downloaded database proxy bundle is invalid; refusing to apply it"
    return
  fi
  if [[ -d "$bundle_dir" ]] \
    && bundle_uses_registered_vpn_address "$bundle_dir"; then
    reset_convergence_state
    log "downloaded database bundle contains a registered VPN address"
    return
  fi
  if ! write_selected_snapshot; then
    reset_convergence_state
    log "waiting for the registry to include every downloaded database member"
    return
  fi
  if ! snapshot_contains_node_id "$selected_path" "$local_node_id" \
    && ! bundle_contains_node_id "$local_node_id"; then
    stop_bundle_servers
    reset_convergence_state
    if ((proxy_eligible == 1)) && proxy_only_bundle_exists; then
      local synchronized_interface
      synchronized_interface="$(interface_for_address "$local_underlay_ip")" || {
        log "waiting for an unambiguous local host-underlay interface"
        return
      }
      apply_local_proxy_bundle "$local_underlay_ip" "$synchronized_interface" \
        || log "waiting to apply the synchronized database proxy bundle"
      log "node left the candidate window after synchronizing proxy-only services"
    else
      log "node is outside the database candidate pool after bundle synchronization"
    fi
    return
  fi

  local local_underlay_interface authoritative_digest
  local_underlay_interface="$(interface_for_address "$local_underlay_ip")" || {
    reset_convergence_state
    log "waiting for an unambiguous local host-underlay interface"
    return
  }
  authoritative_digest="$(snapshot_digest "$authoritative_path")"
  if ! write_local_reachability \
      "$local_vpn_ip" "$local_node_id" "$local_underlay_ip" \
      "$local_underlay_interface" "$authoritative_digest"; then
    reset_convergence_state
    log "waiting to publish local underlay reachability evidence"
    return
  fi

  local coordinator_bundle_ready=1
  if full_database_bundle_exists; then
    publish_bundle_archive
    load_bundle_manifest "$bundle_dir"
    local coordinator_node_id
    coordinator_node_id="$(coordinator_node_id_for_bundle)" || {
      reset_convergence_state
      log "waiting for an active persisted database coordinator"
      return
    }
    if [[ "$local_node_id" != "$coordinator_node_id" ]]; then
      apply_local_bundle "$local_node_id" "$local_underlay_ip"
      reset_convergence_state
      return
    fi
    if bundle_replication_quorum_reached \
        "$local_node_id" "$authoritative_digest"; then
      apply_local_bundle "$local_node_id" "$local_underlay_ip"
    else
      coordinator_bundle_ready=0
      log "waiting for a DCS majority to persist topology revision $manifest_revision"
    fi
  elif proxy_only_bundle_exists; then
    if ((proxy_eligible == 1)); then
      apply_local_proxy_bundle "$local_underlay_ip" "$local_underlay_interface" \
        || log "waiting for the local proxy-only database service"
    fi
    reset_convergence_state
    return
  elif [[ "$local_node_id" != "$(initial_coordinator_node_id)" ]]; then
    reset_convergence_state
    log "waiting for the initial database coordinator"
    return
  fi

  if ! observe_snapshot_stability \
      "$authoritative_stability_path" "$authoritative_digest"; then
    reset_reciprocal_snapshot
    log "waiting for the authoritative peer set to remain stable for $REQUIRED_CONVERGENCE_RECONCILES reconciles"
    return
  fi
  if ! write_reciprocal_eligible_snapshot \
      "$local_node_id" "$authoritative_digest"; then
    rm -f "$eligible_path"
    log "waiting for reciprocal all-pairs underlay evidence to converge"
    return
  fi

  if ! full_database_bundle_exists; then
    local count
    count="$(eligible_count)"
    if ((10#$count < MIN_DATABASE_MEMBER_COUNT)); then
      log "waiting for $MIN_DATABASE_MEMBER_COUNT ready Linux nodes ($count ready)"
      return
    fi
    bootstrap_bundle
    publish_bundle_archive
    return
  fi

  if ((coordinator_bundle_ready == 0)); then
    return
  fi
  load_bundle_manifest "$bundle_dir"
  reconcile_as_coordinator \
    "$local_node_id" "$local_underlay_ip" "$authoritative_digest"
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
  for command in base64 cmp curl date dirname flock ip jq openssl python3 \
    sha256sum socat systemctl tar; do
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
    reconcile_once
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
  bundle_member_vpn_path="$state_dir/bundle-member-vpn.txt"
  proxy_bundle_archive="$state_dir/proxy-bundle.tar.gz"
  proxy_bundle_vpn_path="$state_dir/proxy-bundle-vpn.txt"
  eligible_path="$state_dir/eligible.tsv"
  authoritative_path="$state_dir/authoritative.tsv"
  active_path="$state_dir/active.tsv"
  registered_vpn_path="$state_dir/registered-vpn.tsv"
  vpn_cidr_path="$state_dir/vpn-cidr"
  selected_path="$state_dir/selected.tsv"
  selection_epoch_path="$state_dir/selection-epoch"
  local_reachability_path="$state_dir/local-reachability.tsv"
  authoritative_stability_path="$state_dir/authoritative-stability.tsv"
  reciprocal_stability_path="$state_dir/reciprocal-stability.tsv"
  applied_revision_path="$state_dir/applied-revision"
  configured_revision_path="$state_dir/configured-revision"
  proxy_applied_digest_path="$state_dir/proxy-applied-digest"
  underlay_health_handler="$state_dir/postgres-underlay-health.py"
  install -d -m 0700 "$state_dir"
  legacy_database_service_path="$temporary/heteronetwork-db.service"
  HETERONETWORK_DB_AUTOPILOT_BEARER_TOKEN="$(printf 'a%.0s' {1..64})"
  HETERONETWORK_DB_CLUSTER_ID="cluster-test"
  HETERONETWORK_DB_LOCAL_ROLE="worker"
  HETERONETWORK_DB_CONTROL_PLANE_URLS_B64="$(
    printf '%s' 'https://control.example.test' | base64 -w0
  )"
  HETERONETWORK_DB_CLIENT_CIDRS="192.0.2.0/24,198.51.100.10/32"
  HETERONETWORK_DB_EXTRA_HBA_ENTRIES="keycloak:keycloak:10.250.0.4/32,keycloak:keycloak:10.250.0.5/32"
  reconcile_interval_seconds=30
  validate_config
  if (
    HETERONETWORK_DB_CLIENT_CIDRS="192.0.2.0/24,"
    validate_config >/dev/null 2>&1
  ); then
    die "client CIDRs with an empty entry were accepted"
  fi
  if (
    HETERONETWORK_DB_EXTRA_HBA_ENTRIES="Keycloak:keycloak:10.250.0.4/32"
    validate_config >/dev/null 2>&1
  ); then
    die "invalid extra HBA entry was accepted"
  fi
  if (
    HETERONETWORK_DB_UNDERLAY_INTERFACE="heteronetwork0"
    validate_config >/dev/null 2>&1
  ); then
    die "overlay underlay-interface self-test unexpectedly succeeded"
  fi
  touch "$legacy_database_service_path"
  unmanaged_legacy_database_exists
  rm -f "$legacy_database_service_path"
  if unmanaged_legacy_database_exists; then
    die "legacy database guard remained active without a service"
  fi
  [[ "$(eligible_count)" == "0" ]]
  local selected_candidate candidate_fixture
  candidate_fixture='[
    {"kind":"local_udp","addr":"10.250.0.2:51820","priority":100,"cost":1},
    {"kind":"public_udp","addr":"203.0.113.20:51820","priority":90,"cost":10},
    {"kind":"local_udp","addr":"100.123.154.79:51820","priority":80,"cost":20}
  ]'
  selected_candidate="$(select_underlay_candidate \
    "$candidate_fixture" $'10.250.0.2\n10.250.0.3')"
  [[ "$selected_candidate" == "100.123.154.79" ]]
  if select_underlay_candidate \
    '[{"kind":"local_udp","addr":"10.250.0.2:51820"}]' \
    "10.250.0.2" >/dev/null; then
    die "overlay-only database candidate was accepted"
  fi
  local public_status
  public_status="$(jq -cn --arg assessed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
    node_id: "node-a",
    vpn_ip: "10.250.0.2",
    nat_classification: {
      connectivity_state: "public",
      mapping_behavior: "no_nat",
      strategy: "direct_candidate",
      local_addr: "203.0.113.10:51820",
      observed_endpoint: "203.0.113.10:51820",
      assessed_at: $assessed_at,
      observations: [{
        local_addr: "203.0.113.10:51820",
        reflexive_addr: "203.0.113.10:51820"
      }]
    }
  }')"
  agent_status_is_direct_public "$public_status"
  if agent_status_is_direct_public "$(
    jq '.nat_classification.mapping_behavior = "endpoint_independent"' \
      <<<"$public_status"
  )"; then
    die "NATed node was accepted for automatic database proxy credentials"
  fi
  local descriptor
  descriptor='{
    "node_id":"node-a",
    "underlay_ip":"100.123.154.79",
    "network_plane":"underlay-v1"
  }'
  [[ "$(underlay_from_member_descriptor "$descriptor" node-a)" == "100.123.154.79" ]]
  if underlay_from_member_descriptor "$descriptor" node-b >/dev/null 2>&1; then
    die "member descriptor with the wrong node identity was accepted"
  fi
  if underlay_from_member_descriptor \
    '{"node_id":"node-a","underlay_ip":"100.123.154.79","network_plane":"overlay"}' \
    node-a >/dev/null 2>&1; then
    die "member descriptor with the wrong network plane was accepted"
  fi
  write_bundle_handlers
  [[ "$underlay_health_handler_changed" == "1" ]]
  write_bundle_handlers
  [[ "$underlay_health_handler_changed" == "0" ]]
  printf '# stale handler\n' >"$underlay_health_handler"
  write_bundle_handlers
  [[ "$underlay_health_handler_changed" == "1" ]]
  sh -n "$state_dir/serve-bundle.sh"
  python3 -m py_compile "$underlay_health_handler"
  grep -Fq 'GET /v1/postgres-ha/member HTTP/1.1' "$state_dir/serve-bundle.sh"
  grep -Fq 'GET /v1/postgres-ha/bundle HTTP/1.1' "$state_dir/serve-bundle.sh"
  grep -Fq 'GET /v1/postgres-ha/proxy-bundle HTTP/1.1' \
    "$state_dir/serve-bundle.sh"
  grep -Fq 'grep -Fqx -- "$SOCAT_PEERADDR" "$authorization_path"' \
    "$state_dir/serve-bundle.sh"
  printf 'private-bundle' >"$state_dir/test-bundle.tar.gz"
  printf 'sanitized-proxy-bundle' >"$state_dir/test-proxy-bundle.tar.gz"
  printf '{}\n' >"$state_dir/member.json"
  printf '10.250.0.2\n' >"$bundle_member_vpn_path"
  printf '10.250.0.9\n' >"$proxy_bundle_vpn_path"
  cat >"$state_dir/test-bundle-server.env" <<EOF
BUNDLE_BEARER_TOKEN=test-bearer
BUNDLE_ARCHIVE=$state_dir/test-bundle.tar.gz
BUNDLE_MEMBER_VPN_PATH=$bundle_member_vpn_path
PROXY_BUNDLE_ARCHIVE=$state_dir/test-proxy-bundle.tar.gz
PROXY_BUNDLE_VPN_PATH=$proxy_bundle_vpn_path
MEMBER_DESCRIPTOR=$state_dir/member.json
EOF
  printf 'GET /v1/postgres-ha/bundle HTTP/1.1\r\nAuthorization: Bearer test-bearer\r\n\r\n' \
    | env \
      HETERONETWORK_DB_BUNDLE_SERVER_ENV="$state_dir/test-bundle-server.env" \
      SOCAT_PEERADDR=10.250.0.2 \
      "$state_dir/serve-bundle.sh" >"$state_dir/member-response"
  grep -Fq 'HTTP/1.1 200 OK' "$state_dir/member-response"
  grep -Fq 'private-bundle' "$state_dir/member-response"
  printf 'GET /v1/postgres-ha/bundle HTTP/1.1\r\nAuthorization: Bearer test-bearer\r\n\r\n' \
    | env \
      HETERONETWORK_DB_BUNDLE_SERVER_ENV="$state_dir/test-bundle-server.env" \
      SOCAT_PEERADDR=10.250.0.9 \
      "$state_dir/serve-bundle.sh" >"$state_dir/nonmember-response"
  grep -Fq 'HTTP/1.1 403 Forbidden' "$state_dir/nonmember-response"
  if grep -Fq 'private-bundle' "$state_dir/nonmember-response"; then
    die "nonmember source received the private database bundle"
  fi
  printf 'GET /v1/postgres-ha/proxy-bundle HTTP/1.1\r\nAuthorization: Bearer test-bearer\r\n\r\n' \
    | env \
      HETERONETWORK_DB_BUNDLE_SERVER_ENV="$state_dir/test-bundle-server.env" \
      SOCAT_PEERADDR=10.250.0.9 \
      "$state_dir/serve-bundle.sh" >"$state_dir/proxy-recipient-response"
  grep -Fq 'HTTP/1.1 200 OK' "$state_dir/proxy-recipient-response"
  grep -Fq 'sanitized-proxy-bundle' "$state_dir/proxy-recipient-response"
  if grep -Fq 'private-bundle' "$state_dir/proxy-recipient-response"; then
    die "proxy-only recipient received private database material"
  fi
  printf 'GET /v1/postgres-ha/proxy-bundle HTTP/1.1\r\nAuthorization: Bearer test-bearer\r\n\r\n' \
    | env \
      HETERONETWORK_DB_BUNDLE_SERVER_ENV="$state_dir/test-bundle-server.env" \
      SOCAT_PEERADDR=10.250.0.8 \
      "$state_dir/serve-bundle.sh" >"$state_dir/nonrecipient-response"
  grep -Fq 'HTTP/1.1 403 Forbidden' "$state_dir/nonrecipient-response"
  if grep -Fq 'GET /v1/postgres-ha/bundle HTTP/1.1' \
    "$underlay_health_handler"; then
    die "underlay health handler unexpectedly serves the private database bundle"
  fi
  if grep -Fq 'BUNDLE_BEARER_TOKEN' "$underlay_health_handler"; then
    die "underlay health handler unexpectedly exposes the bundle bearer"
  fi
  render_underlay_listener_unit \
    "underlay probe" \
    "100.123.154.79" \
    "$underlay_health_handler" \
    >"$temporary/underlay.service"
  grep -Fq 'DynamicUser=yes' "$temporary/underlay.service"
  grep -Fq -- '--listen-address 100.123.154.79' "$temporary/underlay.service"
  grep -Fq -- '--max-connections 8 --read-timeout 2' "$temporary/underlay.service"
  grep -Fq 'TasksMax=4' "$temporary/underlay.service"
  grep -Fq 'MemoryMax=64M' "$temporary/underlay.service"
  if grep -Fq 'socat' "$temporary/underlay.service"; then
    die "underlay probe unexpectedly uses a forking listener"
  fi
  if grep -Fq 'heteronetwork-agent.service' "$temporary/underlay.service"; then
    die "underlay probe unexpectedly depends on the Agent"
  fi
  render_bundle_listener_unit \
    "overlay bundle" \
    "10.250.0.2" \
    "$state_dir/serve-bundle.sh" \
    $'Requires=heteronetwork-agent.service\nAfter=heteronetwork-agent.service' \
    >"$temporary/bundle.service"
  grep -Fq 'bind=10.250.0.2' "$temporary/bundle.service"
  grep -Fq -- '-T 15' "$temporary/bundle.service"
  grep -Fq 'max-children=64' "$temporary/bundle.service"
  grep -Fq 'TasksMax=130' "$temporary/bundle.service"
  grep -Fq 'Requires=heteronetwork-agent.service' "$temporary/bundle.service"

  local registry_fixture="$state_dir/registry.json"
  read_authoritative_node_registry() {
    cat "$registry_fixture"
  }
  HETERONETWORK_DB_CANDIDATE_EPOCH=0
  python3 - "$registry_fixture" <<'PY'
import json
import sys

nodes = [
    {
        "node_id": f"node-{index:04d}",
        "vpn_ip": f"10.250.0.{index + 1}",
        "role": "worker",
        "active": True,
    }
    for index in range(64)
]
json.dump(
    {
        "cluster_id": "cluster-test",
        "vpn_cidr": "10.250.0.0/16",
        "selection_epoch": 0,
        "nodes": nodes,
    },
    open(sys.argv[1], "w"),
)
PY
  write_registry_snapshots 10.250.255.254 local-scale-test
  [[ "$(snapshot_count "$authoritative_path")" == "64" ]]
  [[ "$(snapshot_count "$active_path")" == "64" ]]
  [[ "$(snapshot_count "$registered_vpn_path")" == "65" ]]
  [[ "$(<"$vpn_cidr_path")" == "10.250.0.0/16" ]]
  write_selected_snapshot
  [[ "$(snapshot_count "$selected_path")" == "$MAX_DATABASE_CANDIDATE_COUNT" ]]
  write_proxy_bundle_vpn_snapshot
  [[ "$(snapshot_count "$proxy_bundle_vpn_path")" == \
    "$MAX_DATABASE_CANDIDATE_COUNT" ]]
  local bounded_reachability="$state_dir/bounded-reachability.tsv"
  awk -F '\t' '{
    printf "%s\t%s\t192.0.2.%d\n", $2, $1, NR
  }' "$selected_path" >"$bounded_reachability"
  validate_eligible_snapshot \
    "$bounded_reachability" "$MAX_DATABASE_CANDIDATE_COUNT"
  if validate_eligible_snapshot "$bounded_reachability"; then
    die "database member limit accepted the wider candidate reachability set"
  fi
  unset HETERONETWORK_DB_CANDIDATE_EPOCH

  cat >"$registry_fixture" <<'JSON'
{
  "cluster_id": "cluster-test",
  "vpn_cidr": "10.250.0.0/16",
  "selection_epoch": 0,
  "nodes": [
    {"node_id":"node-a","vpn_ip":"10.250.0.2","role":"worker","active":true},
    {"node_id":"node-b","vpn_ip":"10.250.0.3","role":"worker","active":true},
    {"node_id":"node-c","vpn_ip":"10.250.0.10","role":"worker","active":true},
    {"node_id":"node-down","vpn_ip":"10.250.0.20","role":"worker","active":false},
    {"node_id":"node-client","vpn_ip":"10.250.0.99","role":"client","active":true}
  ]
}
JSON
  write_registry_snapshots 10.250.0.2 node-a
  [[ "$(snapshot_count "$authoritative_path")" == "4" ]]
  [[ "$(snapshot_count "$active_path")" == "3" ]]
  [[ "$(snapshot_count "$registered_vpn_path")" == "5" ]]
  cp "$registry_fixture" "$temporary/registry-with-active.json"
  jq '(.nodes[] | select(.role != "client") | .active) = false' \
    "$registry_fixture" >"$temporary/registry-without-active.json"
  install -m 0600 "$temporary/registry-without-active.json" "$registry_fixture"
  write_registry_snapshots 10.250.0.2 node-a
  [[ "$(snapshot_count "$active_path")" == "0" ]]
  install -m 0600 "$temporary/registry-with-active.json" "$registry_fixture"
  write_registry_snapshots 10.250.0.2 node-a
  HETERONETWORK_DB_CANDIDATE_EPOCH=0
  write_selected_snapshot
  unset HETERONETWORK_DB_CANDIDATE_EPOCH
  validate_selected_snapshot "$selected_path"
  if grep -Fq 'node-down' "$selected_path"; then
    die "inactive nonmember blocked the database candidate pool"
  fi
  write_proxy_bundle_vpn_snapshot
  cmp -s "$proxy_bundle_vpn_path" <(
    printf '%s\n' 10.250.0.2 10.250.0.3 10.250.0.10
  )
  if grep -Eq '10\.250\.0\.(20|99)' "$proxy_bundle_vpn_path"; then
    die "inactive or client node received proxy bundle authorization"
  fi
  printf '%s\n' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    $'10.250.0.10\tnode-c\t163.220.236.52' \
    >"$local_reachability_path"
  validate_eligible_snapshot "$local_reachability_path"
  printf '%s\n' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.123.154.79' \
    >"$temporary/duplicate-underlay.tsv"
  if validate_eligible_snapshot "$temporary/duplicate-underlay.tsv"; then
    die "duplicate database underlay address was accepted"
  fi
  if route_output_uses_interface \
    "100.89.33.61 dev heteronetwork0 src 10.250.0.2" \
    tailscale0 100.123.154.79; then
    die "overlay-routed database underlay was accepted"
  fi
  route_output_uses_interface \
    "100.89.33.61 dev tailscale0 table 52 src 100.123.154.79" \
    tailscale0 100.123.154.79
  route_output_uses_interface \
    "100.89.33.61 from 100.123.154.79 dev tailscale0 table 52 uid 0" \
    tailscale0 100.123.154.79
  route_output_uses_interface \
    "100.89.33.61 from 100.123.154.79 dev tailscale0 table 52 src 100.123.154.79" \
    tailscale0 100.123.154.79
  if route_output_uses_interface \
    "100.89.33.61 from 100.123.154.80 dev tailscale0 table 52" \
    tailscale0 100.123.154.79; then
    die "database underlay route with the wrong from address was accepted"
  fi
  if route_output_uses_interface \
    "100.89.33.61 dev tailscale0 table 52 src 100.123.154.80" \
    tailscale0 100.123.154.79; then
    die "database underlay route with the wrong source address was accepted"
  fi
  if route_output_uses_interface \
    "100.89.33.61 from 100.123.154.79 dev tailscale0 table 52 src 100.123.154.80" \
    tailscale0 100.123.154.79; then
    die "database underlay route with conflicting source addresses was accepted"
  fi
  [[ "$(initial_coordinator_node_id)" == "node-a" ]]

  local authoritative_digest node_id underlay_ip _vpn_ip
  authoritative_digest="$(snapshot_digest "$authoritative_path")"
  while IFS=$'\t' read -r _vpn_ip node_id underlay_ip; do
    publish_member_descriptor \
      "$node_id" "$underlay_ip" "$authoritative_digest" \
      "$local_reachability_path"
    cp "$state_dir/member.json" "$state_dir/descriptor-${node_id}.json"
  done <"$local_reachability_path"
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  peer_member_descriptor() {
    cat "$state_dir/descriptor-$2.json"
  }
  printf '%s\n' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    >"$temporary/asymmetric.tsv"
  publish_member_descriptor \
    node-b 100.89.33.61 "$authoritative_digest" \
    "$temporary/asymmetric.tsv"
  cp "$state_dir/member.json" "$state_dir/descriptor-node-b.json"
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  if write_reciprocal_eligible_snapshot node-a "$authoritative_digest"; then
    die "asymmetric underlay evidence unexpectedly converged"
  fi
  [[ "$(jq -r '.count' "$reciprocal_stability_path")" == "1" ]]
  publish_member_descriptor \
    node-b 100.89.33.61 "$authoritative_digest" \
    "$local_reachability_path"
  cp "$state_dir/member.json" "$state_dir/descriptor-node-b.json"
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  rm -f "$reciprocal_stability_path" "$eligible_path"
  if write_reciprocal_eligible_snapshot node-a "$authoritative_digest"; then
    die "reciprocal evidence converged before the first stability window"
  fi
  [[ "$(jq -r '.count' "$reciprocal_stability_path")" == "1" ]]
  if write_reciprocal_eligible_snapshot node-a "$authoritative_digest"; then
    die "stale reciprocal descriptors advanced the convergence window"
  fi
  [[ "$(jq -r '.count' "$reciprocal_stability_path")" == "1" ]]
  for node_id in node-a node-b node-c; do
    jq '.observed_at += 1' \
      "$state_dir/descriptor-${node_id}.json" \
      >"$state_dir/descriptor-${node_id}.json.new"
    mv "$state_dir/descriptor-${node_id}.json.new" \
      "$state_dir/descriptor-${node_id}.json"
  done
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  if write_reciprocal_eligible_snapshot node-a "$authoritative_digest"; then
    die "reciprocal evidence converged before the second fresh generation"
  fi
  [[ "$(jq -r '.count' "$reciprocal_stability_path")" == "2" ]]
  for node_id in node-a node-b node-c; do
    jq '.observed_at += 1' \
      "$state_dir/descriptor-${node_id}.json" \
      >"$state_dir/descriptor-${node_id}.json.new"
    mv "$state_dir/descriptor-${node_id}.json.new" \
      "$state_dir/descriptor-${node_id}.json"
  done
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  write_reciprocal_eligible_snapshot node-a "$authoritative_digest"
  cmp -s "$eligible_path" "$local_reachability_path"

  local generated generated_identities
  generated="$(initial_members_from_snapshot)"
  generated_identities="$(initial_member_identities_from_snapshot)"
  [[ "$generated" == \
    "db-a=100.123.154.79,db-b=100.89.33.61,db-c=163.220.236.52" ]]
  [[ "$generated_identities" == \
    "db-a=node-a,db-b=node-b,db-c=node-c" ]]
  [[ "$generated" != *"10.250."* ]]
  [[ "$(member_name_for_index 31)" == "db-af" ]]
  bootstrap_bundle >/dev/null 2>&1
  load_bundle_manifest "$bundle_dir"
  [[ "$(member_count "$manifest_members")" == "3" ]]
  [[ "$(member_count "$manifest_member_identities")" == "3" ]]
  [[ "$(member_count "$manifest_dcs_members")" == "3" ]]
  [[ "$(member_count "$manifest_dcs_bootstrap_members")" == "3" ]]
  [[ "$manifest_revision" == "1" ]]
  [[ "$manifest_network_plane" == "$DATABASE_NETWORK_PLANE" ]]
  [[ "$manifest_client_cidrs" == \
    "192.0.2.0/24,198.51.100.10/32" ]]
  [[ "$manifest_extra_hba_entries" == \
    "keycloak:keycloak:10.250.0.4/32,keycloak:keycloak:10.250.0.5/32" ]]
  [[ -s "$proxy_bundle_archive" ]]
  local proxy_extracted="$state_dir/proxy-extracted"
  safe_extract_bundle "$proxy_bundle_archive" "$proxy_extracted"
  validate_proxy_bundle_directory "$proxy_extracted"
  [[ "$(<"$proxy_extracted/$proxy_bundle_marker_name")" == \
    "$PROXY_BUNDLE_FORMAT_VERSION" ]]
  [[ -f "$proxy_extracted/ca/ca.crt" ]]
  [[ -f "$proxy_extracted/secrets/application.password" ]]
  if [[ -e "$proxy_extracted/ca/ca.key" \
    || -e "$proxy_extracted/nodes" \
    || -e "$proxy_extracted/secrets/superuser.password" \
    || -e "$proxy_extracted/secrets/replication.password" \
    || -e "$proxy_extracted/secrets/rewind.password" \
    || -e "$proxy_extracted/secrets/rest-api.password" ]]; then
    die "proxy-only bundle contains database authority or replica credentials"
  fi
  cmp -s \
    "$bundle_dir/secrets/application.password" \
    "$proxy_extracted/secrets/application.password"
  local invalid_proxy_bundle="$state_dir/invalid-proxy-bundle"
  cp -a "$proxy_extracted" "$invalid_proxy_bundle"
  printf 'forbidden\n' >"$invalid_proxy_bundle/secrets/superuser.password"
  chmod 0600 "$invalid_proxy_bundle/secrets/superuser.password"
  if validate_proxy_bundle_directory "$invalid_proxy_bundle" >/dev/null 2>&1; then
    die "proxy bundle file allowlist accepted a superuser credential"
  fi
  rm -rf "$invalid_proxy_bundle"
  cp -a "$proxy_extracted" "$invalid_proxy_bundle"
  chmod 0644 "$invalid_proxy_bundle/secrets/application.password"
  if validate_proxy_bundle_directory "$invalid_proxy_bundle" >/dev/null 2>&1; then
    die "group/world-readable proxy application credential was accepted"
  fi
  rm -rf "$invalid_proxy_bundle"
  (
    bundle_dir="$state_dir/proxy-receiver"
    proxy_bundle_archive="$state_dir/proxy-receiver.tar.gz"
    proxy_applied_digest_path="$state_dir/proxy-receiver-applied-digest"
    curl() {
      local output=""
      while (($# > 0)); do
        if [[ "$1" == "--output" ]]; then
          shift
          output="$1"
        fi
        shift
      done
      [[ -n "$output" ]] || return 1
      cp "$state_dir/proxy-bundle.tar.gz" "$output"
    }
    download_best_proxy_bundle
    proxy_only_bundle_exists
    validate_proxy_bundle_directory "$bundle_dir"
    [[ ! -e "$bundle_dir/ca/ca.key" ]]
    bundle_routes_use_interface() {
      return 0
    }
    run_helper_for_bundle() {
      [[ "${2:-}" == "install-proxy" ]]
    }
    systemctl() {
      [[ "${1:-}" == "is-active" ]]
    }
    apply_local_proxy_bundle 100.123.154.79 tailscale0
    [[ -s "$proxy_applied_digest_path" ]]
  )
  (
    bundle_dir="$state_dir/proxy-upgrade-receiver"
    local proxy_install="$state_dir/proxy-upgrade-initial"
    local full_upgrade="$state_dir/proxy-upgrade-full"
    cp -a "$proxy_extracted" "$proxy_install"
    install_proxy_bundle_directory "$proxy_install"
    proxy_only_bundle_exists
    cp -a "$state_dir/bundle" "$full_upgrade"
    install_bundle_directory "$full_upgrade"
    full_database_bundle_exists
    if proxy_only_bundle_exists; then
      die "full database bundle upgrade retained proxy-only classification"
    fi
  )
  local empty_access_bundle="$state_dir/empty-access-bundle"
  cp -a "$bundle_dir" "$empty_access_bundle"
  sed -i \
    -e 's|^HETERONETWORK_DB_CLIENT_CIDRS=.*$|HETERONETWORK_DB_CLIENT_CIDRS=|' \
    -e 's|^HETERONETWORK_DB_EXTRA_HBA_ENTRIES=.*$|HETERONETWORK_DB_EXTRA_HBA_ENTRIES=|' \
    "$empty_access_bundle/manifest.env"
  load_bundle_manifest "$empty_access_bundle"
  [[ -z "$manifest_client_cidrs" ]]
  [[ -z "$manifest_extra_hba_entries" ]]
  validate_bundle_directory "$empty_access_bundle"
  local invalid_access_bundle="$state_dir/invalid-access-bundle"
  cp -a "$bundle_dir" "$invalid_access_bundle"
  sed -i \
    's|^HETERONETWORK_DB_CLIENT_CIDRS=.*$|HETERONETWORK_DB_CLIENT_CIDRS=192.0.2.0/33|' \
    "$invalid_access_bundle/manifest.env"
  if load_bundle_manifest "$invalid_access_bundle" >/dev/null 2>&1; then
    die "bundle manifest with an invalid client CIDR was accepted"
  fi
  rm -rf "$invalid_access_bundle"
  cp -a "$bundle_dir" "$invalid_access_bundle"
  sed -i \
    's|^HETERONETWORK_DB_EXTRA_HBA_ENTRIES=.*$|HETERONETWORK_DB_EXTRA_HBA_ENTRIES=Keycloak:keycloak:10.250.0.4/32|' \
    "$invalid_access_bundle/manifest.env"
  if load_bundle_manifest "$invalid_access_bundle" >/dev/null 2>&1; then
    die "bundle manifest with an invalid extra HBA entry was accepted"
  fi
  rm -rf "$invalid_access_bundle"
  cp -a "$bundle_dir" "$invalid_access_bundle"
  sed -i '/^HETERONETWORK_DB_CLIENT_CIDRS=/d' \
    "$invalid_access_bundle/manifest.env"
  if load_bundle_manifest "$invalid_access_bundle" >/dev/null 2>&1; then
    die "bundle manifest without a client CIDR entry was accepted"
  fi
  rm -rf "$invalid_access_bundle"
  cp -a "$bundle_dir" "$invalid_access_bundle"
  printf '%s\n' 'HETERONETWORK_DB_CLIENT_CIDRS=203.0.113.0/24' \
    >>"$invalid_access_bundle/manifest.env"
  if load_bundle_manifest "$invalid_access_bundle" >/dev/null 2>&1; then
    die "bundle manifest with duplicate client CIDR entries was accepted"
  fi
  rm -rf "$empty_access_bundle" "$invalid_access_bundle"
  load_bundle_manifest "$bundle_dir"
  cmp -s "$bundle_member_vpn_path" <(
    printf '%s\n' 10.250.0.2 10.250.0.3 10.250.0.10
  )
  if grep -Fqx '10.250.0.20' "$bundle_member_vpn_path"; then
    die "nonmember database candidate was authorized to download the private bundle"
  fi
  for node_id in node-a node-b node-c; do
    underlay_ip="$(awk -F '\t' -v node_id="$node_id" '
      $2 == node_id { print $3 }
    ' "$local_reachability_path")"
    publish_member_descriptor \
      "$node_id" "$underlay_ip" "$authoritative_digest" \
      "$local_reachability_path"
    cp "$state_dir/member.json" "$state_dir/descriptor-${node_id}.json"
  done
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  bundle_replication_quorum_reached node-a "$authoritative_digest"
  for node_id in node-b node-c; do
    jq '.bundle_digest = ("0" * 64)' \
      "$state_dir/descriptor-${node_id}.json" \
      >"$state_dir/descriptor-${node_id}.json.new"
    mv "$state_dir/descriptor-${node_id}.json.new" \
      "$state_dir/descriptor-${node_id}.json"
  done
  if bundle_replication_quorum_reached \
      node-a "$authoritative_digest"; then
    die "database bundle quorum accepted divergent member digests"
  fi
  for node_id in node-b node-c; do
    underlay_ip="$(awk -F '\t' -v node_id="$node_id" '
      $2 == node_id { print $3 }
    ' "$local_reachability_path")"
    publish_member_descriptor \
      "$node_id" "$underlay_ip" "$authoritative_digest" \
      "$local_reachability_path"
    cp "$state_dir/member.json" "$state_dir/descriptor-${node_id}.json"
  done
  cp "$state_dir/descriptor-node-a.json" "$state_dir/member.json"
  cp "$authoritative_path" "$temporary/authoritative-with-members.tsv"
  awk -F '\t' '$1 != "node-b"' \
    "$authoritative_path" >"$temporary/authoritative-without-node-b.tsv"
  install -m 0600 \
    "$temporary/authoritative-without-node-b.tsv" "$authoritative_path"
  write_bundle_member_vpn_snapshot
  if grep -Fqx '10.250.0.3' "$bundle_member_vpn_path"; then
    die "removed database member retained private bundle authorization"
  fi
  grep -Fqx '10.250.0.2' "$bundle_member_vpn_path"
  install -m 0600 \
    "$temporary/authoritative-with-members.tsv" "$authoritative_path"
  write_bundle_member_vpn_snapshot
  if bundle_uses_registered_vpn_address "$bundle_dir"; then
    die "underlay database bundle was classified as overlay-dependent"
  fi
  local vpn_bundle="$state_dir/vpn-bundle"
  cp -a "$bundle_dir" "$vpn_bundle"
  sed -i \
    's/db-c=163.220.236.52/db-c=10.250.0.99/' \
    "$vpn_bundle/manifest.env"
  if ! bundle_uses_registered_vpn_address "$vpn_bundle"; then
    die "bundle containing an excluded registered VPN address was accepted"
  fi
  local original_digest changed_digest digest_bundle="$state_dir/digest-bundle"
  original_digest="$(bundle_content_digest "$bundle_dir")"
  cp -a "$bundle_dir" "$digest_bundle"
  printf 'changed\n' >>"$digest_bundle/secrets/application.password"
  changed_digest="$(bundle_content_digest "$digest_bundle")"
  [[ "$original_digest" != "$changed_digest" ]]
  local divergent_archive="$state_dir/divergent-bundle.tar.gz"
  tar --format=ustar --create --gzip --file "$divergent_archive" \
    --directory "$digest_bundle" .
  if (
    curl() {
      local output=""
      while (($# > 0)); do
        if [[ "$1" == "--output" ]]; then
          shift
          output="$1"
        fi
        shift
      done
      [[ -n "$output" ]] || return 1
      cp "$divergent_archive" "$output"
    }
    download_best_bundle >/dev/null 2>&1
  ); then
    die "equal-revision divergent database bundle was accepted"
  fi

  printf '%s\n' \
    $'10.250.0.2\tnode-a' \
    $'10.250.0.3\tnode-b' \
    $'10.250.0.4\tnode-d' \
    $'10.250.0.5\tnode-e' \
    $'10.250.0.10\tnode-c' \
    $'10.250.0.99\tnode-client' \
    >"$registered_vpn_path"
  validate_registered_vpn_snapshot "$registered_vpn_path"
  printf '%s\n' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    $'10.250.0.10\tnode-c\t163.220.236.52' \
    $'10.250.0.4\tnode-d\t163.220.236.51' \
    $'10.250.0.5\tnode-e\t100.94.130.38' \
    >"$eligible_path"
  validate_eligible_snapshot "$eligible_path"
  local expanded
  expanded="$(
    expand_members_from_snapshot \
      "$manifest_members" "$manifest_member_identities"
  )"
  generated="${expanded%%$'\n'*}"
  generated_identities="${expanded#*$'\n'}"
  [[ "$(member_count "$generated")" == "5" ]]
  [[ "$(member_count "$generated_identities")" == "5" ]]
  [[ "$generated" != *"10.250."* ]]
  cp "$eligible_path" "$temporary/eligible-before-legacy-expansion.tsv"
  printf '%s\n' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    $'10.250.0.10\tnode-c\t163.220.236.52' \
    $'10.250.0.4\tnode-d\t163.220.236.51' \
    $'10.250.0.5\tnode-e\t100.94.130.38' \
    $'10.250.0.6\tnode-f\t192.0.2.50' \
    $'10.250.0.2\tnode-a\t100.123.154.79' \
    >"$eligible_path"
  local legacy_expanded legacy_members legacy_identities
  legacy_expanded="$(
    expand_members_from_snapshot \
      "db-b=100.89.33.61,db-c=163.220.236.52,db-d=163.220.236.51,db-e=100.94.130.38,db-f=192.0.2.50" \
      "db-b=node-b,db-c=node-c,db-d=node-d,db-e=node-e,db-f=node-f"
  )"
  legacy_members="${legacy_expanded%%$'\n'*}"
  legacy_identities="${legacy_expanded#*$'\n'}"
  [[ "$legacy_members" == \
    "db-b=100.89.33.61,db-c=163.220.236.52,db-d=163.220.236.51,db-e=100.94.130.38,db-f=192.0.2.50,db-a=100.123.154.79" ]]
  [[ "$legacy_identities" == \
    "db-b=node-b,db-c=node-c,db-d=node-d,db-e=node-e,db-f=node-f,db-a=node-a" ]]
  cp "$temporary/eligible-before-legacy-expansion.tsv" "$eligible_path"
  cp "$eligible_path" "$temporary/eligible-good.tsv"
  sed -i \
    's/100.123.154.79/100.123.154.80/' \
    "$eligible_path"
  if expand_members_from_snapshot \
      "$manifest_members" "$manifest_member_identities" >/dev/null 2>&1; then
    die "underlay address drift for an existing node was accepted"
  fi
  cp "$temporary/eligible-good.tsv" "$eligible_path"
  local dcs_five staged_five
  dcs_five="$(target_dcs_topology "$generated")"
  [[ "$(member_count "$dcs_five")" == "5" ]]
  HETERONETWORK_DB_INTERFACE=tailscale0
  staged_five="$(stage_topology \
    "$generated" "$generated_identities" \
    "$dcs_five" "$manifest_dcs_bootstrap_members" 2 \
    node-a 100.123.154.79)"
  load_bundle_manifest "$staged_five"
  [[ "$(member_count "$manifest_dcs_members")" == "5" ]]
  [[ "$(member_count "$manifest_dcs_bootstrap_members")" == "3" ]]
  [[ "$manifest_revision" == "2" ]]
  [[ "$manifest_client_cidrs" == \
    "192.0.2.0/24,198.51.100.10/32" ]]
  [[ "$manifest_extra_hba_entries" == \
    "keycloak:keycloak:10.250.0.4/32,keycloak:keycloak:10.250.0.5/32" ]]
  load_bundle_manifest "$bundle_dir"
  [[ "$(member_count "$manifest_dcs_members")" == "3" ]]
  rm -rf "$staged_five"
  local dcs_four staged_four
  dcs_four="$(first_members "$generated" 4)"
  staged_four="$(stage_topology \
    "$generated" "$generated_identities" \
    "$dcs_five" "$dcs_four" 3 \
    node-a 100.123.154.79)"
  load_bundle_manifest "$staged_four"
  [[ "$(member_count "$manifest_dcs_members")" == "5" ]]
  [[ "$(member_count "$manifest_dcs_bootstrap_members")" == "4" ]]
  [[ "$manifest_revision" == "3" ]]
  [[ "$manifest_client_cidrs" == \
    "192.0.2.0/24,198.51.100.10/32" ]]
  [[ "$manifest_extra_hba_entries" == \
    "keycloak:keycloak:10.250.0.4/32,keycloak:keycloak:10.250.0.5/32" ]]
  rm -rf "$staged_four"
  load_bundle_manifest "$bundle_dir"
  local capture_helper="$temporary/capture-helper.sh"
  cat >"$capture_helper" <<EOF
#!/usr/bin/env bash
env | LC_ALL=C sort >"$temporary/applied-helper.env"
EOF
  chmod 0700 "$capture_helper"
  (
    helper="$capture_helper"
    configure_helper_environment() {
      HETERONETWORK_DB_NODE_NAME="db-a"
      HETERONETWORK_DB_NODE_ADDRESS="100.123.154.79"
      HETERONETWORK_DB_INTERFACE="tailscale0"
      export HETERONETWORK_DB_NODE_NAME
      export HETERONETWORK_DB_NODE_ADDRESS
      export HETERONETWORK_DB_INTERFACE
    }
    systemctl() {
      return 1
    }
    apply_local_bundle node-a 100.123.154.79 >/dev/null
  )
  grep -Fxq \
    'HETERONETWORK_DB_CLIENT_CIDRS=192.0.2.0/24,198.51.100.10/32' \
    "$temporary/applied-helper.env"
  grep -Fxq \
    'HETERONETWORK_DB_EXTRA_HBA_ENTRIES=keycloak:keycloak:10.250.0.4/32,keycloak:keycloak:10.250.0.5/32' \
    "$temporary/applied-helper.env"
  rm -f "$applied_revision_path" "$configured_revision_path"
  local unhealthy_helper="$temporary/unhealthy-helper.sh"
  cat >"$unhealthy_helper" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${1:-}" >>"${HETERONETWORK_DB_TEST_HELPER_LOG:?}"
[[ "${1:-}" != "verify" ]]
EOF
  chmod 0700 "$unhealthy_helper"
  local unhealthy_helper_log="$temporary/unhealthy-helper.log"
  (
    helper="$unhealthy_helper"
    HETERONETWORK_DB_TEST_HELPER_LOG="$unhealthy_helper_log"
    export HETERONETWORK_DB_TEST_HELPER_LOG
    configure_helper_environment() {
      HETERONETWORK_DB_NODE_NAME="db-a"
      HETERONETWORK_DB_NODE_ADDRESS="100.123.154.79"
      HETERONETWORK_DB_INTERFACE="tailscale0"
      export HETERONETWORK_DB_NODE_NAME
      export HETERONETWORK_DB_NODE_ADDRESS
      export HETERONETWORK_DB_INTERFACE
    }
    systemctl() {
      [[ -f "$temporary/database-active" ]]
    }
    sleep() {
      return 0
    }
    apply_local_bundle node-a 100.123.154.79 >/dev/null
    touch "$temporary/database-active"
    apply_local_bundle node-a 100.123.154.79 >/dev/null
  )
  [[ ! -e "$applied_revision_path" ]]
  [[ "$(<"$configured_revision_path")" == "$manifest_revision" ]]
  [[ "$(grep -c '^reconfigure-node$' "$unhealthy_helper_log")" == "1" ]]
  [[ "$(grep -c '^verify$' "$unhealthy_helper_log")" == \
    "$((BUNDLE_HEALTH_RETRY_ATTEMPTS * 2))" ]]

  printf '%s\n' \
    $'node-b\t10.250.0.3' \
    $'node-c\t10.250.0.10' \
    >"$active_path"
  [[ "$(coordinator_node_id_for_bundle)" == "node-b" ]]
  printf '%s\n' \
    $'10.250.0.3\tnode-b\t100.89.33.61' \
    $'10.250.0.10\tnode-c\t163.220.236.52' \
    >"$local_reachability_path"
  for node_id in node-b node-c; do
    underlay_ip="$(awk -F '\t' -v node_id="$node_id" '
      $2 == node_id { print $3 }
    ' "$local_reachability_path")"
    publish_member_descriptor \
      "$node_id" "$underlay_ip" "$authoritative_digest" \
      "$local_reachability_path"
    cp "$state_dir/member.json" "$state_dir/descriptor-${node_id}.json"
  done
  cp "$state_dir/descriptor-node-b.json" "$state_dir/member.json"
  rm -f "$reciprocal_stability_path" "$eligible_path"
  if write_reciprocal_eligible_snapshot node-b "$authoritative_digest"; then
    die "failover reciprocal evidence converged before its stability window"
  fi
  for expected_count in 2 3; do
    for node_id in node-b node-c; do
      jq '.observed_at += 1' \
        "$state_dir/descriptor-${node_id}.json" \
        >"$state_dir/descriptor-${node_id}.json.new"
      mv "$state_dir/descriptor-${node_id}.json.new" \
        "$state_dir/descriptor-${node_id}.json"
    done
    cp "$state_dir/descriptor-node-b.json" "$state_dir/member.json"
    if ((expected_count < REQUIRED_CONVERGENCE_RECONCILES)); then
      if write_reciprocal_eligible_snapshot \
          node-b "$authoritative_digest"; then
        die "failover reciprocal evidence converged too early"
      fi
    else
      write_reciprocal_eligible_snapshot node-b "$authoritative_digest"
    fi
    [[ "$(jq -r '.count' "$reciprocal_stability_path")" == "$expected_count" ]]
  done
  [[ "$(snapshot_count "$eligible_path")" == "2" ]]
  if grep -Fq 'node-a' "$eligible_path"; then
    die "inactive failed coordinator remained mandatory for reciprocal convergence"
  fi
  printf '%s\n' \
    $'node-a\t10.250.0.2' \
    $'node-b\t10.250.0.3' \
    $'node-c\t10.250.0.10' \
    >"$active_path"
  cp "$temporary/eligible-good.tsv" "$local_reachability_path"

  publish_bundle_archive
  local extracted="$state_dir/extracted"
  safe_extract_bundle "$bundle_archive" "$extracted"
  validate_bundle_directory "$extracted"
  local legacy_bundle="$state_dir/legacy-bundle"
  cp -a "$extracted" "$legacy_bundle"
  sed -i '/^HETERONETWORK_DB_NETWORK_PLANE=/d' "$legacy_bundle/manifest.env"
  if validate_bundle_directory "$legacy_bundle" >/dev/null 2>&1; then
    die "database bundle without an underlay contract was accepted"
  fi
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
  local oversized="$state_dir/oversized.tar.gz"
  python3 - "$oversized" "$((MAX_BUNDLE_FILE_BYTES + 1))" <<'PY'
import io
import sys
import tarfile

size = int(sys.argv[2])
with tarfile.open(sys.argv[1], "w:gz") as archive:
    entry = tarfile.TarInfo("./oversized")
    entry.size = size
    archive.addfile(entry, io.BytesIO(b"\0" * size))
PY
  if safe_extract_bundle \
      "$oversized" "$state_dir/oversized-extracted" >/dev/null 2>&1; then
    die "oversized expanded database bundle was accepted"
  fi
  local exchange_candidate="$state_dir/exchange-candidate"
  cp -a "$bundle_dir" "$exchange_candidate"
  printf 'new\n' >"$exchange_candidate/exchange-marker"
  install_bundle_directory "$exchange_candidate"
  [[ "$(<"$bundle_dir/exchange-marker")" == "new" ]]
  [[ ! -e "$exchange_candidate" ]]
  rm -rf "$temporary"
  trap - RETURN
  log "autopilot self-test passed"
}

case "${1:-}" in
  run) run_autopilot ;;
  self-test) self_test ;;
  *) printf 'Usage: postgres-ha-autopilot.sh {run|self-test}\n' >&2; exit 2 ;;
esac
