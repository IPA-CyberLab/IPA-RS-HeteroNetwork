#!/usr/bin/env bash
set -euo pipefail

# Generate a Compose override that moves selected workload services into the
# agent namespace and moves their published ports to the agent boundary.

docker_bin="${DOCKER:-docker}"
project_name="ipars"
agent_service="agent"
output_path=""
config_json=""
compose_files=()
workload_services=()
tmp_dir=""

usage() {
  cat >&2 <<'EOF'
usage: rootless-compose-attach.sh [options]

Generate a Compose override for an existing rootless route-provider agent.

Options:
  --compose-file PATH       Compose file; may be repeated (default: docker/compose.yaml)
  --project-name NAME       Compose project name (default: ipars)
  --agent-service NAME      Route-provider service (default: agent)
  --workload-service NAME   Service to attach; may be repeated
  --config-json PATH        Use rendered `docker compose config --format json` instead
  --output PATH              Generated override path (required)
  -h, --help                Show this help

The generated file is intended to be passed after the rootless route-provider
overlays. Services with published ports move those ports to the agent so
rootlesskit's host port forwarding remains available.
EOF
}

fail() {
  echo "rootless Compose attach: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is not available"
}

validate_service_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
    fail "service name '$value' contains unsupported YAML characters"
}

validate_output_path() {
  local path="$1"
  [[ -n "$path" ]] || fail "--output is required"
  [[ "$path" != */ ]] || fail "--output must be a file path"
  if [[ -L "$path" ]]; then
    fail "--output must not be a symlink"
  fi
  local parent
  parent="$(dirname -- "$path")"
  [[ -d "$parent" ]] || fail "output directory '$parent' does not exist"
  [[ -w "$parent" ]] || fail "output directory '$parent' is not writable"
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$tmp_dir" ]]; then
    rm -rf -- "$tmp_dir"
  fi
  exit "$status"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compose-file)
      [[ $# -ge 2 ]] || fail "--compose-file requires a value"
      compose_files+=("$2")
      shift 2
      ;;
    --project-name)
      [[ $# -ge 2 ]] || fail "--project-name requires a value"
      project_name="$2"
      shift 2
      ;;
    --agent-service)
      [[ $# -ge 2 ]] || fail "--agent-service requires a value"
      agent_service="$2"
      shift 2
      ;;
    --workload-service)
      [[ $# -ge 2 ]] || fail "--workload-service requires a value"
      workload_services+=("$2")
      shift 2
      ;;
    --config-json)
      [[ $# -ge 2 ]] || fail "--config-json requires a value"
      config_json="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || fail "--output requires a value"
      output_path="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      fail "unknown argument '$1'"
      ;;
  esac
done

require_command jq
validate_service_name "$agent_service"
validate_output_path "$output_path"
[[ ${#workload_services[@]} -gt 0 ]] || fail "at least one --workload-service is required"
if [[ -n "$config_json" && ${#compose_files[@]} -gt 0 ]]; then
  fail "--config-json cannot be combined with --compose-file"
fi

for service in "${workload_services[@]}"; do
  validate_service_name "$service"
done

umask 077
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ipars-rootless-compose-attach.XXXXXX")"
trap cleanup EXIT
rendered_config="$tmp_dir/config.json"

if [[ -n "$config_json" ]]; then
  [[ -f "$config_json" && ! -L "$config_json" ]] ||
    fail "--config-json must be a non-symlink regular file"
  [[ "$(wc -c <"$config_json")" -le 16777216 ]] ||
    fail "--config-json exceeds 16 MiB"
  cp -- "$config_json" "$rendered_config"
else
  if [[ ${#compose_files[@]} -eq 0 ]]; then
    compose_files=("docker/compose.yaml")
  fi
  compose_args=("compose" "-p" "$project_name")
  for compose_file in "${compose_files[@]}"; do
    [[ -f "$compose_file" && ! -L "$compose_file" ]] ||
      fail "Compose file '$compose_file' must be a non-symlink regular file"
    compose_args+=("-f" "$compose_file")
  done
  "${docker_bin}" "${compose_args[@]}" config --format json >"$rendered_config" ||
    fail "docker compose config failed"
fi

jq -e 'type == "object" and (.services | type == "object")' "$rendered_config" >/dev/null ||
  fail "rendered Compose config must contain an object-valued services map"

jq -e --arg service "$agent_service" '.services[$service] != null' "$rendered_config" >/dev/null ||
  fail "agent service '$agent_service' was not found in rendered Compose config"

declare -A seen_services=()
for service in "${workload_services[@]}"; do
  [[ -z "${seen_services[$service]+present}" ]] || fail "workload service '$service' was repeated"
  seen_services["$service"]=1
  [[ "$service" != "$agent_service" ]] || fail "agent service cannot also be a workload service"
  jq -e --arg service "$service" '.services[$service] != null' "$rendered_config" >/dev/null ||
    fail "workload service '$service' was not found in rendered Compose config"
  network_mode="$(jq -r --arg service "$service" '.services[$service].network_mode // empty' "$rendered_config")"
  if [[ -n "$network_mode" && "$network_mode" != "service:$agent_service" ]]; then
    fail "workload service '$service' already has incompatible network_mode '$network_mode'"
  fi
done

declare -a agent_port_records=()
declare -a moved_port_records=()
declare -A target_keys=()
declare -A published_keys=()
empty_field="__IPARS_EMPTY_FIELD__"

add_port_records() {
  local service="$1"
  local source="$2"
  local target published protocol host_ip mode
  while IFS=$'\t' read -r target published protocol host_ip mode; do
    [[ "$target" != "$empty_field" ]] || target=""
    [[ "$published" != "$empty_field" ]] || published=""
    [[ "$protocol" != "$empty_field" ]] || protocol=""
    [[ "$host_ip" != "$empty_field" ]] || host_ip=""
    [[ "$mode" != "$empty_field" ]] || mode=""
    [[ -n "$target" ]] || fail "$source service '$service' has a port without a target"
    [[ "$target" =~ ^[0-9]+$ && "$target" -ge 1 && "$target" -le 65535 ]] ||
      fail "$source service '$service' has invalid target port '$target'"
    [[ -n "$published" ]] ||
      fail "$source service '$service' has a port without a published host port; set it explicitly before sharing the namespace"
    [[ "$published" =~ ^[0-9]+$ && "$published" -ge 1 && "$published" -le 65535 ]] ||
      fail "$source service '$service' has invalid published port '$published'"
    case "$protocol" in
      tcp|udp) ;;
      *) fail "$source service '$service' has unsupported port protocol '$protocol'" ;;
    esac
    [[ "$host_ip" != *$'\n'* && "$host_ip" != *'|'* ]] ||
      fail "$source service '$service' has an unsafe host IP"
    [[ "$mode" == "" || "$mode" == "host" || "$mode" == "ingress" ]] ||
      fail "$source service '$service' has unsupported port mode '$mode'"

    local target_key="${target}/${protocol}"
    local published_key="${published}/${protocol}"
    [[ -z "${target_keys[$target_key]+present}" ]] ||
      fail "shared namespace has duplicate target port $target/$protocol (service '$service')"
    [[ -z "${published_keys[$published_key]+present}" ]] ||
      fail "shared namespace has duplicate published port $published/$protocol"
    target_keys["$target_key"]="$service"
    published_keys["$published_key"]="$service"
    local record="$target|$published|$protocol|$host_ip|$mode"
    if [[ "$source" == "agent" ]]; then
      agent_port_records+=("$record")
    else
      moved_port_records+=("$record")
    fi
  done < <(
    jq -r --arg service "$service" '
      (.services[$service].ports // [])[] |
      [(.target // ""), (.published // ""), (.protocol // "tcp"), (.host_ip // ""), (.mode // "")] |
      map(if . == "" then "__IPARS_EMPTY_FIELD__" else tostring end) | @tsv
    ' "$rendered_config"
  )
}

add_port_records "$agent_service" "agent"
for service in "${workload_services[@]}"; do
  add_port_records "$service" "workload"
done

yaml_quote() {
  jq -Rn --arg value "$1" '$value'
}

emit_port_record() {
  local record="$1"
  local target published protocol host_ip mode
  IFS='|' read -r target published protocol host_ip mode <<<"$record"
  printf '      - target: %s\n' "$target"
  printf '        published: %s\n' "$published"
  printf '        protocol: %s\n' "$protocol"
  if [[ -n "$host_ip" ]]; then
    printf '        host_ip: %s\n' "$(yaml_quote "$host_ip")"
  fi
  if [[ -n "$mode" ]]; then
    printf '        mode: %s\n' "$mode"
  fi
}

output_tmp="$tmp_dir/override.yaml"
{
  printf 'services:\n'
  if [[ ${#moved_port_records[@]} -gt 0 ]]; then
    printf '  %s:\n' "$agent_service"
    printf '    ports: !override\n'
    for record in "${agent_port_records[@]}" "${moved_port_records[@]}"; do
      emit_port_record "$record"
    done
  fi
  for service in "${workload_services[@]}"; do
    printf '  %s:\n' "$service"
    printf '    network_mode: service:%s\n' "$agent_service"
    printf '    networks: !reset []\n'
    printf '    depends_on:\n'
    printf '      %s:\n' "$agent_service"
    dependency_condition="$(jq -r --arg service "$service" --arg agent "$agent_service" \
      '.services[$service].depends_on[$agent].condition // "service_started"' "$rendered_config")"
    case "$dependency_condition" in
      service_started|service_healthy|service_completed_successfully) ;;
      *) fail "workload service '$service' has unsupported dependency condition '$dependency_condition' for '$agent_service'" ;;
    esac
    printf '        condition: %s\n' "$dependency_condition"
    if jq -e --arg service "$service" '(.services[$service].ports // []) | length > 0' "$rendered_config" >/dev/null; then
      printf '    ports: !reset []\n'
    fi
  done
} >"$output_tmp"

mv -- "$output_tmp" "$output_path"
echo "generated rootless Compose namespace override at $output_path"
echo "attached workload services: ${workload_services[*]}"
if [[ ${#moved_port_records[@]} -gt 0 ]]; then
  echo "moved published workload ports to agent service: ${#moved_port_records[@]}"
fi
