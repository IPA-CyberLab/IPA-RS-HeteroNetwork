#!/usr/bin/env bash
set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly DEFAULT_FLOW_REPOSITORY="$(cd -- "${REPOSITORY_ROOT}/../IPA-RS-HeteroCloud-Flow" 2>/dev/null && pwd || true)"
readonly CONFIRMATION="two-node-fault"

execute=false
baseline_only=false
resume_dir=""
output_dir=""
pair_filter=""
seed="${HETERONETWORK_CHAOS_SEED:-$(date +%s)}"
reboot_delay_seconds="${HETERONETWORK_CHAOS_REBOOT_DELAY_SECONDS:-180}"
fault_observation_timeout_seconds="${HETERONETWORK_CHAOS_FAULT_OBSERVATION_TIMEOUT_SECONDS:-120}"
recovery_timeout_seconds="${HETERONETWORK_CHAOS_RECOVERY_TIMEOUT_SECONDS:-900}"
ssh_user="${HETERONETWORK_CHAOS_SSH_USER:-mizuame}"
ssh_key="${HETERONETWORK_CHAOS_SSH_KEY:-${REPOSITORY_ROOT}/.key}"
flow_repository="${HETERONETWORK_CHAOS_FLOW_REPOSITORY:-${DEFAULT_FLOW_REPOSITORY}}"
playwright_module="${HETERONETWORK_CHAOS_PLAYWRIGHT_MODULE:-${REPOSITORY_ROOT}/node_modules/playwright}"
sudo_password="${HETERONETWORK_CHAOS_SUDO_PASSWORD:-}"

readonly -a NODE_NAMES=(
  ichikawap1
  mizuame-nucboxg5
  uc-k8s3p
  uc-k8sp1
  uc-k8sp2
  uc-k8sv1
)
readonly -a DIRECT_NODE_NAMES=(ichikawap1 uc-k8s3p uc-k8sp1 uc-k8sp2)
readonly -a DATABASE_NODE_NAMES=(
  ichikawap1
  uc-k8s3p
  uc-k8sp1
  uc-k8sp2
  mizuame-nucboxg5
)

declare -Ar VPN_ADDRESS=(
  [ichikawap1]="10.250.0.10"
  [mizuame-nucboxg5]="10.250.0.3"
  [uc-k8s3p]="10.250.0.6"
  [uc-k8sp1]="10.250.0.4"
  [uc-k8sp2]="10.250.0.5"
  [uc-k8sv1]="10.250.0.8"
)
declare -Ar MANAGEMENT_ADDRESS=(
  [ichikawap1]="100.65.54.75"
  [mizuame-nucboxg5]=""
  [uc-k8s3p]="100.68.203.27"
  [uc-k8sp1]="100.92.62.45"
  [uc-k8sp2]="100.94.130.38"
  [uc-k8sv1]=""
)
active_jump=""
active_fault_a=""
active_fault_b=""
known_hosts=""
run_log=""
results_file=""
order_file=""
external_monitor_pid=""
external_monitor_stop=""
baseline_control_plane_count=0
baseline_database_member_count=0

usage() {
  cat <<'EOF'
Usage: two-node-chaos.sh [OPTIONS]

Runs every two-node failure combination in a deterministic shuffled order. Each
target is armed with an automatic reboot timer before kubelet, containerd,
HeteroNetwork, PostgreSQL, and the overlay interface are stopped.

Options:
  --execute                  Inject faults. Without this flag, print the order only.
  --baseline-only            Run all non-destructive health checks and exit.
  --pair NODE_A,NODE_B       Run only one pair.
  --seed INTEGER             Shuffle seed. Default: current Unix time.
  --output-dir DIR           New result directory.
  --resume DIR               Continue an existing result directory.
  --reboot-delay SECONDS     Automatic reboot delay. Default: 180.
  --fault-timeout SECONDS    Maximum wait for both nodes to become NotReady. Default: 120.
  --recovery-timeout SECONDS Maximum convergence wait per pair. Default: 900.
  -h, --help                 Show this help.

Execution requires:
  HETERONETWORK_CHAOS_CONFIRM=two-node-fault
  HETERONETWORK_CHAOS_SUDO_PASSWORD, or an interactive password prompt

The current inventory contains the six Ready nodes from the 2026-08 cluster.
The unavailable mizuame node is intentionally excluded.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s %s\n' "$timestamp" "$*" | tee -a "$run_log"
}

validate_positive_integer() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ && "$value" -gt 0 ]] \
    || die "$label must be a positive integer: $value"
}

node_exists() {
  local candidate="$1"
  local node
  for node in "${NODE_NAMES[@]}"; do
    [[ "$node" == "$candidate" ]] && return 0
  done
  return 1
}

parse_pair() {
  local value="$1"
  [[ "$value" == *,* ]] || die "pair must use NODE_A,NODE_B"
  local first="${value%%,*}"
  local second="${value#*,}"
  [[ "$second" != *,* && -n "$first" && -n "$second" ]] \
    || die "pair must contain exactly two node names"
  node_exists "$first" || die "unknown node in pair: $first"
  node_exists "$second" || die "unknown node in pair: $second"
  [[ "$first" != "$second" ]] || die "pair nodes must be different"
  printf '%s+%s\n' "$first" "$second"
}

while (($# > 0)); do
  case "$1" in
    --execute)
      execute=true
      shift
      ;;
    --baseline-only)
      baseline_only=true
      shift
      ;;
    --pair)
      (($# >= 2)) || die "--pair requires a value"
      pair_filter="$(parse_pair "$2")"
      shift 2
      ;;
    --seed)
      (($# >= 2)) || die "--seed requires a value"
      seed="$2"
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || die "--output-dir requires a value"
      output_dir="$2"
      shift 2
      ;;
    --resume)
      (($# >= 2)) || die "--resume requires a value"
      resume_dir="$2"
      shift 2
      ;;
    --reboot-delay)
      (($# >= 2)) || die "--reboot-delay requires a value"
      reboot_delay_seconds="$2"
      shift 2
      ;;
    --recovery-timeout)
      (($# >= 2)) || die "--recovery-timeout requires a value"
      recovery_timeout_seconds="$2"
      shift 2
      ;;
    --fault-timeout)
      (($# >= 2)) || die "--fault-timeout requires a value"
      fault_observation_timeout_seconds="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

validate_positive_integer seed "$seed"
validate_positive_integer reboot-delay "$reboot_delay_seconds"
validate_positive_integer fault-timeout "$fault_observation_timeout_seconds"
validate_positive_integer recovery-timeout "$recovery_timeout_seconds"
((reboot_delay_seconds >= 90)) || die "reboot delay must be at least 90 seconds"
((fault_observation_timeout_seconds >= 60)) \
  || die "fault observation timeout must be at least 60 seconds"
((recovery_timeout_seconds >= 180)) || die "recovery timeout must be at least 180 seconds"
[[ -z "$resume_dir" || -z "$output_dir" ]] \
  || die "--resume and --output-dir cannot be used together"

for command in ssh curl jq python3 base64 timeout; do
  command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: $command"
done
[[ -f "$ssh_key" ]] || die "SSH key does not exist: $ssh_key"
[[ -f "$flow_repository/scripts/flow-e2e.mjs" ]] \
  || die "Flow E2E script does not exist: $flow_repository/scripts/flow-e2e.mjs"
[[ -f "$playwright_module/package.json" ]] \
  || die "Playwright module does not exist: $playwright_module"

if [[ -n "$resume_dir" ]]; then
  output_dir="$resume_dir"
  [[ -d "$output_dir" ]] || die "resume directory does not exist: $output_dir"
else
  output_dir="${output_dir:-${REPOSITORY_ROOT}/artifacts/chaos/two-node-$(date -u +%Y%m%dT%H%M%SZ)}"
  mkdir -p "$output_dir"
fi
output_dir="$(cd -- "$output_dir" && pwd)"
known_hosts="$output_dir/known_hosts"
run_log="$output_dir/run.log"
results_file="$output_dir/results.tsv"
order_file="$output_dir/order.tsv"
seed_file="$output_dir/seed"
touch "$known_hosts" "$run_log"
chmod 600 "$known_hosts"

if [[ -f "$seed_file" ]]; then
  seed="$(<"$seed_file")"
  validate_positive_integer stored-seed "$seed"
else
  printf '%s\n' "$seed" >"$seed_file"
fi

if [[ ! -f "$order_file" ]]; then
  pairs=""
  for ((left = 0; left < ${#NODE_NAMES[@]}; left += 1)); do
    for ((right = left + 1; right < ${#NODE_NAMES[@]}; right += 1)); do
      pairs+="${NODE_NAMES[$left]}+${NODE_NAMES[$right]}"$'\n'
    done
  done
  PAIRS="$pairs" SEED="$seed" python3 - <<'PY' >"$order_file"
import os
import random

pairs = [line for line in os.environ["PAIRS"].splitlines() if line]
random.Random(int(os.environ["SEED"])).shuffle(pairs)
for index, pair in enumerate(pairs, 1):
    print(f"{index}\t{pair}")
PY
fi

if [[ ! -f "$results_file" ]]; then
  printf 'order\tpair\tstarted_at\tfault_observed\tkubernetes\tvpn_mesh\tpatroni\tdb_write\toidc\tflow_api\tflow_normal\tflow_relay\trecovery\texternal_failures\tduration_seconds\n' \
    >"$results_file"
fi

if [[ "$execute" == "true" ]]; then
  [[ "${HETERONETWORK_CHAOS_CONFIRM:-}" == "$CONFIRMATION" ]] \
    || die "set HETERONETWORK_CHAOS_CONFIRM=$CONFIRMATION before fault injection"
fi
if [[ "$execute" == "true" || "$baseline_only" == "true" ]]; then
  if [[ -z "$sudo_password" ]]; then
    [[ -t 0 ]] || die "set HETERONETWORK_CHAOS_SUDO_PASSWORD for non-interactive execution"
    read -r -s -p 'Remote sudo password: ' sudo_password
    printf '\n' >&2
  fi
fi

select_jump() {
  local excluded_a="${1:-}"
  local excluded_b="${2:-}"
  local node
  for node in "${DIRECT_NODE_NAMES[@]}"; do
    if [[ "$node" != "$excluded_a" && "$node" != "$excluded_b" ]]; then
      printf '%s\n' "$node"
      return 0
    fi
  done
  return 1
}

ssh_node() {
  local node="$1"
  local remote_command="$2"
  local address="${MANAGEMENT_ADDRESS[$node]}"
  local -a arguments=(
    ssh
    -n
    -i "$ssh_key"
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ConnectionAttempts=1
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=2
    -o StrictHostKeyChecking=no
    -o "UserKnownHostsFile=$known_hosts"
    -o LogLevel=ERROR
  )
  if [[ -z "$address" ]]; then
    [[ -n "$active_jump" ]] || die "no active jump host for $node"
    local jump_address="${MANAGEMENT_ADDRESS[$active_jump]}"
    local proxy
    printf -v proxy \
      'ssh -i %q -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=%q -o LogLevel=ERROR -W %%h:%%p %q' \
      "$ssh_key" "$known_hosts" "${ssh_user}@${jump_address}"
    arguments+=(-o "ProxyCommand=$proxy")
    address="${VPN_ADDRESS[$node]}"
  fi
  arguments+=("${ssh_user}@${address}" "$remote_command")
  "${arguments[@]}"
}

root_node() {
  local node="$1"
  local script="$2"
  local encoded encoded_password remote_command
  encoded="$(printf '%s' "$script" | base64 -w0)"
  encoded_password="$(printf '%s' "$sudo_password" | base64 -w0)"
  remote_command="{ printf '%s' '$encoded_password' | base64 -d; printf '\\n'; } | sudo -S -p '' bash -c \"\$(printf '%s' '$encoded' | base64 -d)\""
  ssh_node "$node" "$remote_command"
}

kubernetes_root_node() {
  local node="$1"
  local script="$2"
  local pod_name encoded host_command overrides quoted_overrides remote_script
  pod_name="hn-chaos-root-$(date +%s)-$RANDOM"
  encoded="$(printf '%s' "$script" | base64 -w0)"
  host_command="printf '%s' '$encoded' | base64 -d | bash"
  overrides="$(jq -nc \
    --arg node "$node" \
    --arg name "$pod_name" \
    --arg command "$host_command" \
    '{spec:{
      nodeName:$node,
      hostPID:true,
      hostNetwork:true,
      restartPolicy:"Never",
      tolerations:[{operator:"Exists"}],
      containers:[{
        name:$name,
        image:"alpine:3.20",
        imagePullPolicy:"IfNotPresent",
        securityContext:{privileged:true},
        command:["nsenter","-t","1","-m","-u","-i","-n","-p","--","bash","-c",$command]
      }]
    }}')"
  printf -v quoted_overrides '%q' "$overrides"
  remote_script="set -eu
kubectl -n default delete pod '$pod_name' --ignore-not-found=true --wait=false >/dev/null
kubectl -n default run '$pod_name' --image=alpine:3.20 --restart=Never --overrides=$quoted_overrides >/dev/null
if ! kubectl -n default wait --for=jsonpath='{.status.phase}'=Succeeded pod/'$pod_name' --timeout=90s >/dev/null; then
  kubectl -n default describe pod '$pod_name' >&2 || true
  kubectl -n default logs '$pod_name' >&2 || true
  kubectl -n default delete pod '$pod_name' --wait=false >/dev/null 2>&1 || true
  exit 1
fi
kubectl -n default logs '$pod_name'
kubectl -n default delete pod '$pod_name' --wait=false >/dev/null
"
  root_node "$active_jump" "$remote_script"
}

host_root_node() {
  local node="$1"
  local script="$2"
  if [[ "$node" == "mizuame-nucboxg5" ]]; then
    kubernetes_root_node "$node" "$script"
    return
  fi
  if root_node "$node" "$script"; then
    return 0
  fi
  return 1
}

select_database_observer() {
  local node
  for node in "${DATABASE_NODE_NAMES[@]}"; do
    if [[ "$node" != "$active_fault_a" && "$node" != "$active_fault_b" ]]; then
      printf '%s\n' "$node"
      return 0
    fi
  done
  return 1
}

fetch_nodes_json() {
  local observer="$1"
  root_node "$observer" 'timeout 20 kubectl get nodes -o json'
}

fetch_workloads_json() {
  local observer="$1"
  root_node "$observer" 'timeout 25 kubectl get deployments,statefulsets,daemonsets -A -o json'
}

api_ready() {
  local observer="$1"
  root_node "$observer" 'timeout 20 kubectl get --raw=/readyz >/dev/null'
}

target_ready_count() {
  local document="$1"
  local json_names
  json_names="$(printf '%s\n' "${NODE_NAMES[@]}" | jq -R . | jq -s .)"
  jq --argjson names "$json_names" '[
      .items[]
      | select(.metadata.name as $name | $names | index($name))
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
    ] | length' <<<"$document"
}

control_plane_ready_count() {
  jq '[
      .items[]
      | select(.metadata.labels["node-role.kubernetes.io/control-plane"] != null)
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
    ] | length' <<<"$1"
}

fault_nodes_not_ready() {
  local document="$1"
  local first="$2"
  local second="$3"
  jq -e --arg first "$first" --arg second "$second" '
    all(.items[] | select(.metadata.name == $first or .metadata.name == $second);
      (any(.status.conditions[]?; .type == "Ready" and .status != "True")) or
      (any(.status.conditions[]?; .type == "Ready") | not)
    )' <<<"$document" >/dev/null
}

workloads_fully_ready() {
  jq -e 'all(.items[];
      if .kind == "Deployment" then
        ((.status.availableReplicas // 0) >= (.spec.replicas // 1))
      elif .kind == "StatefulSet" then
        ((.status.readyReplicas // 0) >= (.spec.replicas // 1))
      elif .kind == "DaemonSet" then
        ((.status.numberReady // 0) >= (.status.desiredNumberScheduled // 0))
      else false end
    )' <<<"$1" >/dev/null
}

degraded_services_available() {
  local observer="$1"
  local expected_survivors="$2"
  root_node "$observer" 'expected_survivors='"$expected_survivors"'
set -u
status=0
available() {
  namespace="$1"
  kind="$2"
  name="$3"
  minimum="$4"
  value="$(kubectl -n "$namespace" get "$kind" "$name" -o jsonpath="{.status.availableReplicas}" 2>/dev/null || true)"
  if [ "$kind" = statefulset ]; then
    value="$(kubectl -n "$namespace" get "$kind" "$name" -o jsonpath="{.status.readyReplicas}" 2>/dev/null || true)"
  fi
  if [ "${value:-0}" -ge "$minimum" ]; then
    result=PASS
  else
    result=FAIL
    status=1
  fi
  printf "%s/%s %s %s/%s %s\n" "$namespace" "$kind" "$name" "${value:-0}" "$minimum" "$result"
}
daemon_available() {
  namespace="$1"
  name="$2"
  minimum="$3"
  value="$(kubectl -n "$namespace" get daemonset "$name" -o jsonpath="{.status.numberReady}" 2>/dev/null || true)"
  if [ "${value:-0}" -ge "$minimum" ]; then
    result=PASS
  else
    result=FAIL
    status=1
  fi
  printf "%s/daemonset %s %s/%s %s\n" "$namespace" "$name" "${value:-0}" "$minimum" "$result"
}
available kube-system deployment coredns 1
available heterocloud-dns deployment heterocloud-dns 1
available heterocloud deployment heterocloud-heterocloud 1
available heterocloud-flow deployment heterocloud-flow-api 1
available heterocloud-flow deployment heterocloud-flow-signaling 1
available heterocloud-flow deployment heterocloud-flow-livekit 1
available heterocloud-flow statefulset heterocloud-flow-redis-node 3
available heterocloud-flow deployment heterocloud-flow-coturn 1
daemon_available kube-flannel kube-flannel-ds "$expected_survivors"
daemon_available kube-system kube-proxy "$expected_survivors"
daemon_available kube-system node-local-dns "$expected_survivors"
daemon_available kube-system kubernetes-service-route "$expected_survivors"
exit "$status"
'
}

wait_for_fault_state() {
  local observer="$1"
  local first="$2"
  local second="$3"
  local deadline=$((SECONDS + fault_observation_timeout_seconds))
  local document ready_count
  while ((SECONDS < deadline)); do
    document="$(fetch_nodes_json "$observer" 2>/dev/null || true)"
    if [[ -n "$document" ]]; then
      ready_count="$(target_ready_count "$document" 2>/dev/null || printf 0)"
      if [[ "$ready_count" == "$((${#NODE_NAMES[@]} - 2))" ]] \
        && fault_nodes_not_ready "$document" "$first" "$second"; then
        return 0
      fi
    fi
    sleep 3
  done
  return 1
}

wait_for_full_recovery() {
  local observer="$1"
  local deadline="${2:-$((SECONDS + recovery_timeout_seconds))}"
  local next_log=$SECONDS
  local document workloads ready_count control_planes
  while ((SECONDS < deadline)); do
    document="$(fetch_nodes_json "$observer" 2>/dev/null || true)"
    workloads="$(fetch_workloads_json "$observer" 2>/dev/null || true)"
    if [[ -n "$document" && -n "$workloads" ]]; then
      ready_count="$(target_ready_count "$document" 2>/dev/null || printf 0)"
      control_planes="$(control_plane_ready_count "$document" 2>/dev/null || printf 0)"
      if [[ "$ready_count" == "${#NODE_NAMES[@]}" \
        && "$control_planes" == "$baseline_control_plane_count" ]] \
        && workloads_fully_ready "$workloads" \
        && api_ready "$observer" >/dev/null 2>&1 \
        && patroni_cluster_fully_ready \
        && database_write_probe \
        && keycloak_oidc_probe "$observer" \
        && flow_api_write_probe; then
        return 0
      fi
      if ((SECONDS >= next_log)); then
        log "recovery pending: ready=${ready_count}/${#NODE_NAMES[@]} control-planes=${control_planes}/${baseline_control_plane_count}"
        next_log=$((SECONDS + 30))
      fi
    elif ((SECONDS >= next_log)); then
      log "recovery pending: Kubernetes API is not queryable"
      next_log=$((SECONDS + 30))
    fi
    sleep 5
  done
  return 1
}

wait_for_data_plane_recovery() {
  local label="$1"
  local deadline="$2"
  local attempt=0
  local vpn_ready pod_network_ready
  while ((SECONDS < deadline)); do
    attempt=$((attempt + 1))
    if vpn_mesh "${label}-attempt-${attempt}" "${NODE_NAMES[@]}"; then
      vpn_ready=PASS
    else
      vpn_ready=FAIL
    fi
    if pod_network_mesh "${label}-attempt-${attempt}" "${NODE_NAMES[@]}"; then
      pod_network_ready=PASS
    else
      pod_network_ready=FAIL
    fi
    if [[ "$vpn_ready" == PASS && "$pod_network_ready" == PASS ]]; then
      return 0
    fi
    log "recovery data plane pending: attempt=$attempt vpn=$vpn_ready pod-network=$pod_network_ready"
    sleep 10
  done
  return 1
}

vpn_mesh() {
  local label="$1"
  shift
  local -a sources=("$@")
  local target source target_list="" command status=0
  local -a pids=()
  local -a logs=()
  for target in "${sources[@]}"; do
    target_list+=" ${VPN_ADDRESS[$target]}"
  done
  for source in "${sources[@]}"; do
    local source_log="$output_dir/${label}-${source}.log"
    logs+=("$source_log")
    printf -v command 'status=0; for address in %s; do reached=0; for attempt in 1 2 3 4 5; do if ping -c 1 -W 2 "$address" >/dev/null 2>&1; then reached=1; break; fi; sleep 1; done; if [ "$reached" -eq 1 ]; then printf "%%s -> %%s PASS\\n" %q "$address"; else printf "%%s -> %%s FAIL\\n" %q "$address"; status=1; fi; done; exit "$status"' \
      "$target_list" "$source" "$source"
    (ssh_node "$source" "$command" >"$source_log" 2>&1) &
    pids+=("$!")
  done
  for target in "${pids[@]}"; do
    wait "$target" || status=1
  done
  return "$status"
}

pod_network_mesh() {
  local label="$1"
  shift
  local -a nodes=("$@")
  local run_id manifest="" index=0 node pod_name encoded_manifest remote_script
  run_id="$(printf '%s-%s-%s' "$label" "$$" "$RANDOM" | tr -cd '[:alnum:]-' | tr '[:upper:]' '[:lower:]' | cut -c1-40)"
  for node in "${nodes[@]}"; do
    index=$((index + 1))
    pod_name="hn-chaos-net-${run_id}-${index}"
    manifest+="apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
  namespace: default
  labels:
    heteronetwork.io/chaos-network-run: ${run_id}
spec:
  nodeName: ${node}
  restartPolicy: Never
  tolerations:
    - operator: Exists
  containers:
    - name: probe
      image: alpine:3.20
      imagePullPolicy: IfNotPresent
      command: [\"sh\", \"-c\", \"sleep 300\"]
---
"
  done
  encoded_manifest="$(printf '%s' "$manifest" | base64 -w0)"
  remote_script="set -eu
cleanup() {
  kubectl -n default delete pod -l 'heteronetwork.io/chaos-network-run=${run_id}' --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
printf '%s' '${encoded_manifest}' | base64 -d | kubectl apply -f - >/dev/null
if ! kubectl -n default wait --for=condition=Ready pod -l 'heteronetwork.io/chaos-network-run=${run_id}' --timeout=90s; then
  kubectl -n default get pod -l 'heteronetwork.io/chaos-network-run=${run_id}' -o wide || true
  kubectl -n default describe pod -l 'heteronetwork.io/chaos-network-run=${run_id}' || true
  exit 1
fi
pods=\"\$(kubectl -n default get pods -l 'heteronetwork.io/chaos-network-run=${run_id}' -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}')\"
addresses=\"\$(kubectl -n default get pods -l 'heteronetwork.io/chaos-network-run=${run_id}' -o jsonpath='{range .items[*]}{.status.podIP}{\"\\n\"}{end}')\"
[ \"\$(printf '%s\\n' \"\$pods\" | sed '/^$/d' | wc -l)\" -eq '${#nodes[@]}' ]
[ \"\$(printf '%s\\n' \"\$addresses\" | sed '/^$/d' | wc -l)\" -eq '${#nodes[@]}' ]
status=0
for source in \$pods; do
  source_node=\"\$(kubectl -n default get pod \"\$source\" -o jsonpath='{.spec.nodeName}')\"
  for address in \$addresses; do
    reached=0
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      if kubectl -n default exec \"\$source\" -- ping -c 1 -W 2 \"\$address\" >/dev/null 2>&1; then
        reached=1
        break
      fi
      sleep 1
    done
    if [ \"\$reached\" -eq 1 ]; then
      printf '%s -> %s PASS\\n' \"\$source_node\" \"\$address\"
    else
      printf '%s -> %s FAIL\\n' \"\$source_node\" \"\$address\"
      status=1
    fi
  done
done
exit \"\$status\"
"
  root_node "$active_jump" "$remote_script" >"$output_dir/${label}-pod-mesh.log" 2>&1
}

keycloak_oidc_probe() {
  local observer="$1"
  local internal='http://console.heteronetwork.internal:18079/realms/heteronetwork/.well-known/openid-configuration'
  ssh_node "$observer" "curl -fsS --max-time 15 '$internal' | jq -e '.issuer | contains(\"/realms/heteronetwork\")' >/dev/null" \
    || return 1
  local code
  code="$(curl -sS -o /dev/null --max-time 20 -w '%{http_code}' \
    'https://heterocloud.mizuame.app/api/v1/auth/oidc/start' || true)"
  [[ "$code" =~ ^30[12378]$ ]]
}

external_baseline_probe() {
  baseline_endpoint_available 200 'https://flow.heterocloud.mizuame.app/openapi.json' \
    && baseline_endpoint_available 200 'https://heterocloud.mizuame.app/' \
    && baseline_endpoint_available redirect 'https://heterocloud.mizuame.app/api/v1/auth/oidc/start'
}

baseline_endpoint_available() {
  local expected="$1"
  local url="$2"
  local code attempt
  for attempt in 1 2 3 4 5; do
    code="$(curl -sS -o /dev/null --connect-timeout 5 --max-time 15 -w '%{http_code}' "$url" 2>/dev/null || true)"
    if [[ "$expected" == redirect && "$code" =~ ^30[12378]$ ]] \
      || [[ "$code" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

patroni_document() {
  local observer
  observer="$(select_database_observer)" || return 1
  host_root_node "$observer" \
    'timeout 20 /opt/heteronetwork/postgres-ha/patroni/bin/patronictl -c /etc/heteronetwork/postgres-ha/patroni.yml list -f json'
}

patroni_has_leader() {
  local document
  document="$(patroni_document 2>/dev/null)" || return 1
  jq -e '[.[] | select((.Role | ascii_downcase) == "leader" or (.Role | ascii_downcase) == "primary") | select((.State | ascii_downcase) == "running")] | length == 1' \
    <<<"$document" >/dev/null
}

patroni_healthy_member_count() {
  local document
  document="$(patroni_document 2>/dev/null)" || return 1
  jq '[
    .[]
    | ((.State // "") | ascii_downcase) as $state
    | select($state == "running" or $state == "streaming")
  ] | length' <<<"$document"
}

patroni_cluster_fully_ready() {
  local document
  document="$(patroni_document 2>/dev/null)" || return 1
  jq -e --argjson expected "$baseline_database_member_count" '
    ([.[]
      | ((.State // "") | ascii_downcase) as $state
      | select($state == "running" or $state == "streaming")
    ] | length) >= $expected
    and
    ([.[]
      | select((.Role | ascii_downcase) == "leader" or (.Role | ascii_downcase) == "primary")
      | select(((.State // "") | ascii_downcase) == "running")
    ] | length) == 1
  ' <<<"$document" >/dev/null
}

prepare_database_probe() {
  local observer
  observer="$(select_database_observer)" || return 1
  host_root_node "$observer" \
    "PGPASSWORD=\$(cat /etc/heteronetwork/postgres-ha/secrets/superuser.password) PGSSLMODE=verify-full PGSSLROOTCERT=/etc/heteronetwork/postgres-ha/pki/ca.crt timeout 30 psql -U postgres -h postgres.heteronetwork.internal -p 25432 -d postgres -v ON_ERROR_STOP=1 -qAtc 'CREATE TABLE IF NOT EXISTS public.heteronetwork_chaos_probe (id uuid PRIMARY KEY, observed_at timestamptz NOT NULL)'"
}

database_write_probe() {
  local observer probe_id
  observer="$(select_database_observer)" || return 1
  probe_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  host_root_node "$observer" \
    "PGPASSWORD=\$(cat /etc/heteronetwork/postgres-ha/secrets/superuser.password) PGSSLMODE=verify-full PGSSLROOTCERT=/etc/heteronetwork/postgres-ha/pki/ca.crt timeout 25 psql -U postgres -h postgres.heteronetwork.internal -p 25432 -d postgres -v ON_ERROR_STOP=1 -qAtc \"BEGIN; INSERT INTO public.heteronetwork_chaos_probe VALUES ('$probe_id', now()); DELETE FROM public.heteronetwork_chaos_probe WHERE id = '$probe_id'; COMMIT\""
}

cleanup_database_probe() {
  local observer
  observer="$(select_database_observer 2>/dev/null)" || return 0
  host_root_node "$observer" \
    "PGPASSWORD=\$(cat /etc/heteronetwork/postgres-ha/secrets/superuser.password) PGSSLMODE=verify-full PGSSLROOTCERT=/etc/heteronetwork/postgres-ha/pki/ca.crt timeout 30 psql -U postgres -h postgres.heteronetwork.internal -p 25432 -d postgres -qAtc 'DROP TABLE IF EXISTS public.heteronetwork_chaos_probe'" \
    >/dev/null 2>&1 || true
}

flow_context() {
  local observer ids secret query quoted_query
  observer="$(select_database_observer)" || return 1
  query="SELECT organization_id, project_id, id FROM flow_service_instances WHERE status->>'phase' = 'ready' ORDER BY created_at DESC LIMIT 1"
  printf -v quoted_query '%q' "$query"
  ids="$(host_root_node "$observer" "timeout 20 runuser -u postgres -- psql -h /run/postgresql -p 55432 -d heterocloud_flow -v ON_ERROR_STOP=1 -qAtF '|' -c $quoted_query" 2>/dev/null)" \
    || return 1
  [[ "$ids" == *'|'*'|'* ]] || return 1
  secret="$(host_root_node "$observer" 'timeout 20 kubectl -n heterocloud-flow get secret heterocloud-flow-secrets -o jsonpath="{.data.flow-principal-context-hmac-secret}"' 2>/dev/null)" \
    || return 1
  [[ -n "$secret" ]] || return 1
  FLOW_IDS="$ids" FLOW_SECRET_B64="$secret" python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import os
import time
import uuid

organization_id, project_id, service_instance_id = os.environ["FLOW_IDS"].strip().split("|")
issued_at = int(time.time())
payload = {
    "issuer": "heterocloud",
    "audience": "heterocloud-flow-data",
    "organization_id": organization_id,
    "project_id": project_id,
    "service_instance_id": service_instance_id,
    "principal_id": str(uuid.uuid4()),
    "permissions": ["flow.*"],
    "issued_at": issued_at,
    "expires_at": issued_at + 300,
    "context_id": str(uuid.uuid4()),
}
encoded = base64.urlsafe_b64encode(
    json.dumps(payload, separators=(",", ":")).encode()
).rstrip(b"=").decode()
timestamp = str(issued_at)
secret = base64.b64decode(os.environ["FLOW_SECRET_B64"])
signature = base64.urlsafe_b64encode(
    hmac.new(secret, f"{timestamp}.{encoded}".encode(), hashlib.sha256).digest()
).rstrip(b"=").decode()
print(json.dumps({
    "x-flow-principal": encoded,
    "x-flow-timestamp": timestamp,
    "x-flow-signature": signature,
}, separators=(",", ":")))
PY
}

flow_api_write_probe() {
  local context principal timestamp signature body response code attempt
  context="$(flow_context)" || return 1
  jq -e '
    type == "object"
    and (."x-flow-principal" | type == "string" and length > 0)
    and (."x-flow-timestamp" | type == "string" and length > 0)
    and (."x-flow-signature" | type == "string" and length > 0)
  ' <<<"$context" >/dev/null || return 1
  principal="$(jq -er '."x-flow-principal"' <<<"$context")" || return 1
  timestamp="$(jq -er '."x-flow-timestamp"' <<<"$context")" || return 1
  signature="$(jq -er '."x-flow-signature"' <<<"$context")" || return 1
  for attempt in 1 2 3 4 5 6 7 8; do
    body="$(jq -nc --arg name "chaos-api-$(date +%s%N)-$attempt" \
      '{mode:"p2p",name:$name,max_participants:2,metadata:{test:"two-node-chaos"}}')"
    response="$(curl -sS --connect-timeout 3 --max-time 12 \
      -H "x-flow-principal: $principal" \
      -H "x-flow-timestamp: $timestamp" \
      -H "x-flow-signature: $signature" \
      -H 'content-type: application/json' \
      -d "$body" -w $'\n%{http_code}' \
      'https://flow.heterocloud.mizuame.app/v1/rooms' 2>/dev/null || true)"
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    if [[ "$code" =~ ^20[01]$ ]] && jq -e '.id != null' <<<"$body" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

flow_e2e_probe() {
  local mode="$1"
  local destination="$2"
  local context
  context="$(flow_context)" || return 1
  timeout 140 env \
    FLOW_CHAOS_CONTEXT="$context" \
    FLOW_CONTEXT_COMMAND='printf "%s" "$FLOW_CHAOS_CONTEXT"' \
    FLOW_DURATION_SECONDS=10 \
    FLOW_INTERVAL_SECONDS=5 \
    FLOW_REQUEST_TIMEOUT_MS=20000 \
    FLOW_CONNECTION_ATTEMPTS=3 \
    FLOW_CONNECTION_RETRY_DELAY_MS=1000 \
    FLOW_ICE_TRANSPORT_POLICY="$mode" \
    PLAYWRIGHT_MODULE="$playwright_module" \
    node "$flow_repository/scripts/flow-e2e.mjs" >"$destination" 2>&1
}

start_external_monitor() {
  local case_directory="$1"
  external_monitor_stop="$case_directory/external.stop"
  rm -f "$external_monitor_stop"
  (
    local code expected label url
    while [[ ! -e "$external_monitor_stop" ]]; do
      while IFS='|' read -r label expected url; do
        if ! code="$(curl -sS -o /dev/null --max-time 8 -w '%{http_code}' "$url" 2>/dev/null)"; then
          code=000
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$label" "$expected" "$code" "$url"
      done <<'ENDPOINTS'
flow-openapi|200|https://flow.heterocloud.mizuame.app/openapi.json
heterocloud-console|200|https://heterocloud.mizuame.app/
heterocloud-oidc|303|https://heterocloud.mizuame.app/api/v1/auth/oidc/start
ENDPOINTS
      sleep 2
    done
  ) >"$case_directory/external.tsv" 2>&1 &
  external_monitor_pid="$!"
}

stop_external_monitor() {
  if [[ -n "$external_monitor_pid" ]]; then
    touch "$external_monitor_stop"
    wait "$external_monitor_pid" 2>/dev/null || true
    external_monitor_pid=""
  fi
}

external_failure_count() {
  local document="$1"
  [[ -f "$document" ]] || {
    printf '0\n'
    return
  }
  awk -F '\t' '$4 != $3 {count += 1} END {print count + 0}' "$document"
}

arm_reboot() {
  local node="$1"
  local unit="$2"
  host_root_node "$node" "set -eu
systemctl stop '${unit}.timer' '${unit}.service' >/dev/null 2>&1 || true
reboot_at=\$((\$(date +%s) + ${reboot_delay_seconds}))
systemd-run --quiet --unit='$unit' --on-calendar=\"@\$reboot_at\" --timer-property=AccuracySec=1s /usr/bin/systemctl reboot --force
systemctl is-active --quiet '${unit}.timer'
"
}

fault_node() {
  local node="$1"
  local unit="$2"
  local fault_script encoded
  fault_script='set +e
systemctl stop \
  kubelet.service \
  containerd.service \
  heteronetwork-keycloak-backchannel.service \
  heteronetwork-keycloak-edge-proxy.service \
  heteronetwork-keycloak.service \
  heteronetwork-db-proxy.service \
  heteronetwork-db.service \
  heteronetwork-db-dcs.service \
  heteronetwork-control-plane.service \
  heteronetwork-signal.service \
  heteronetwork-stun.service \
  heteronetwork-relay.service \
  heteronetwork-gateway.service \
  heteronetwork-agent.service >/dev/null 2>&1
printf "FAULT_APPLIED\n"
sync
sleep 1
ip link set dev heteronetwork0 down >/dev/null 2>&1
exit 0
'
  encoded="$(printf '%s' "$fault_script" | base64 -w0)"
  host_root_node "$node" "set -eu
systemctl stop '${unit}.timer' '${unit}.service' >/dev/null 2>&1 || true
systemd-run --quiet --unit='$unit' --on-active=5s --timer-property=AccuracySec=1s /bin/bash -c \"\$(printf '%s' '$encoded' | base64 -d)\"
systemctl is-active --quiet '${unit}.timer'
"
}

run_baseline() {
  local observer document workloads ready_count control_planes
  observer="$(select_jump)" || die "no direct observer is available"
  active_jump="$observer"
  log "baseline observer=$observer"
  document="$(fetch_nodes_json "$observer")" || die "cannot query Kubernetes nodes"
  ready_count="$(target_ready_count "$document")"
  control_planes="$(control_plane_ready_count "$document")"
  baseline_control_plane_count="$control_planes"
  [[ "$ready_count" == "${#NODE_NAMES[@]}" ]] \
    || die "baseline requires ${#NODE_NAMES[@]} Ready target nodes; found $ready_count"
  ((control_planes >= 5)) || die "baseline requires at least five Ready control planes; found $control_planes"
  api_ready "$observer" || die "Kubernetes /readyz failed"
  workloads="$(fetch_workloads_json "$observer")" || die "cannot query Kubernetes workloads"
  workloads_fully_ready "$workloads" || die "not all Deployments and StatefulSets are Ready"
  patroni_has_leader || die "Patroni does not have exactly one running leader"
  baseline_database_member_count="$(patroni_healthy_member_count)" \
    || die "cannot count healthy Patroni members"
  ((baseline_database_member_count >= 5)) \
    || die "baseline requires at least five healthy Patroni members; found $baseline_database_member_count"
  prepare_database_probe || die "database write probe could not be prepared"
  database_write_probe || die "baseline synchronous database write failed"
  vpn_mesh baseline "${NODE_NAMES[@]}" || die "baseline VPN all-to-all mesh failed"
  pod_network_mesh baseline "${NODE_NAMES[@]}" \
    || die "baseline Pod-network all-to-all mesh failed; see $output_dir/baseline-pod-mesh.log"
  keycloak_oidc_probe "$observer" || die "baseline Keycloak/OIDC probe failed"
  external_baseline_probe || die "baseline public endpoint probe failed"
  flow_api_write_probe || die "baseline Flow room creation failed"
  flow_e2e_probe all "$output_dir/baseline-flow-normal.log" \
    || die "baseline Flow normal WebRTC E2E failed; see $output_dir/baseline-flow-normal.log"
  flow_e2e_probe relay "$output_dir/baseline-flow-relay.log" \
    || die "baseline Flow relay WebRTC E2E failed; see $output_dir/baseline-flow-relay.log"
  log "baseline passed: ready=$ready_count control-planes=$control_planes VPN/Pod mesh and Flow normal/relay E2E passed"
}

status_word() {
  if "$@"; then
    printf 'PASS\n'
  else
    printf 'FAIL\n'
  fi
}

run_pair() {
  local order="$1"
  local pair="$2"
  local first="${pair%%+*}"
  local second="${pair#*+}"
  local observer case_directory unit_prefix started_at started_epoch duration recovery_deadline
  local fault_observed kubernetes vpn pod_network patroni db_write oidc flow_api flow_normal flow_relay recovery
  local external_failures

  active_fault_a="$first"
  active_fault_b="$second"
  active_jump="$(select_jump "$first" "$second")" \
    || die "no surviving direct jump host for pair $pair"
  observer="$active_jump"
  case_directory="$output_dir/case-$(printf '%02d' "$order")-${pair//+/-}"
  mkdir -p "$case_directory"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  started_epoch="$(date +%s)"
  unit_prefix="hn-chaos-${order}-$(date +%s)"
  log "case $order/15 pair=$pair observer=$observer: arming automatic recovery"

  arm_reboot "$first" "${unit_prefix}-a" >"$case_directory/arm-${first}.log" 2>&1 \
    || die "failed to arm automatic reboot on $first"
  arm_reboot "$second" "${unit_prefix}-b" >"$case_directory/arm-${second}.log" 2>&1 \
    || die "failed to arm automatic reboot on $second"

  start_external_monitor "$case_directory"
  log "case $order pair=$pair: injecting both faults"
  fault_node "$first" "${unit_prefix}-fault-a" >"$case_directory/fault-${first}.log" 2>&1 &
  local first_pid="$!"
  fault_node "$second" "${unit_prefix}-fault-b" >"$case_directory/fault-${second}.log" 2>&1 &
  local second_pid="$!"
  wait "$first_pid" 2>/dev/null || true
  wait "$second_pid" 2>/dev/null || true

  if wait_for_fault_state "$observer" "$first" "$second"; then
    fault_observed=PASS
  else
    fault_observed=FAIL
  fi
  log "case $order pair=$pair: simultaneous NotReady observation=$fault_observed"

  local -a survivors=()
  local node
  for node in "${NODE_NAMES[@]}"; do
    if [[ "$node" != "$first" && "$node" != "$second" ]]; then
      survivors+=("$node")
    fi
  done
  vpn="$(status_word vpn_mesh "case-${order}-degraded" "${survivors[@]}")"
  pod_network="$(status_word pod_network_mesh "case-${order}-degraded" "${survivors[@]}")"
  if api_ready "$observer" >"$case_directory/kubernetes-api.log" 2>&1 \
    && degraded_services_available "$observer" "${#survivors[@]}" \
      >"$case_directory/kubernetes-services.log" 2>&1 \
    && [[ "$pod_network" == PASS ]]; then
    kubernetes=PASS
  else
    kubernetes=FAIL
  fi
  patroni="$(status_word patroni_has_leader)"
  db_write="$(status_word database_write_probe)"
  oidc="$(status_word keycloak_oidc_probe "$observer")"
  flow_api="$(status_word flow_api_write_probe)"
  flow_normal="$(status_word flow_e2e_probe all "$case_directory/flow-normal.log")"
  flow_relay="$(status_word flow_e2e_probe relay "$case_directory/flow-relay.log")"
  log "case $order degraded: k8s=$kubernetes vpn=$vpn pod-network=$pod_network patroni=$patroni db-write=$db_write oidc=$oidc flow-api=$flow_api normal=$flow_normal relay=$flow_relay"

  recovery_deadline=$((SECONDS + recovery_timeout_seconds))
  if wait_for_full_recovery "$observer" "$recovery_deadline" \
    && wait_for_data_plane_recovery "case-${order}-recovered" "$recovery_deadline"; then
    recovery=PASS
  else
    recovery=FAIL
  fi
  stop_external_monitor
  external_failures="$(external_failure_count "$case_directory/external.tsv")"
  duration=$(($(date +%s) - started_epoch))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$order" "$pair" "$started_at" "$fault_observed" "$kubernetes" "$vpn" "$patroni" "$db_write" \
    "$oidc" "$flow_api" "$flow_normal" "$flow_relay" "$recovery" "$external_failures" "$duration" \
    >>"$results_file"
  log "case $order pair=$pair complete: recovery=$recovery external-failed-samples=$external_failures duration=${duration}s"
  [[ "$recovery" == PASS ]] || die "pair $pair did not recover; stop before injecting another fault"
}

trap 'stop_external_monitor' EXIT
trap 'stop_external_monitor; exit 130' INT
trap 'stop_external_monitor; exit 143' TERM

log "two-node chaos seed=$seed output=$output_dir execute=$execute"
if [[ "$execute" != "true" && "$baseline_only" != "true" ]]; then
  if [[ -n "$pair_filter" ]]; then
    filter_first="${pair_filter%%+*}"
    filter_second="${pair_filter#*+}"
    awk -F '\t' -v direct="$pair_filter" -v reverse="$filter_second+$filter_first" \
      '$2 == direct || $2 == reverse' "$order_file"
  else
    cat "$order_file"
  fi
  log "dry run only; pass --execute with the confirmation environment variable to inject faults"
  exit 0
fi

run_baseline
if [[ "$baseline_only" == "true" ]]; then
  cleanup_database_probe
  log "baseline-only run complete"
  exit 0
fi

while IFS=$'\t' read -r order pair; do
  [[ -n "$order" && -n "$pair" ]] || continue
  if [[ -n "$pair_filter" ]]; then
    first="${pair_filter%%+*}"
    second="${pair_filter#*+}"
    [[ "$pair" == "$pair_filter" || "$pair" == "$second+$first" ]] || continue
  fi
  if awk -F '\t' -v pair="$pair" 'NR > 1 && $2 == pair && $13 == "PASS" {found=1} END {exit !found}' "$results_file"; then
    log "case $order pair=$pair already recovered; skipping"
    continue
  fi
  run_pair "$order" "$pair"
done <"$order_file"

cleanup_database_probe
continuity_failures="$(awk -F '\t' 'NR > 1 {
  for (column = 4; column <= 12; column += 1) if ($column != "PASS") failures += 1
} END {print failures + 0}' "$results_file")"
recovery_failures="$(awk -F '\t' 'NR > 1 && $13 != "PASS" {failures += 1} END {print failures + 0}' "$results_file")"
completed_cases="$(awk 'END {print NR - 1}' "$results_file")"
log "matrix complete: cases=$completed_cases continuity-failures=$continuity_failures recovery-failures=$recovery_failures"
((recovery_failures == 0)) || exit 1
((continuity_failures == 0)) || exit 2
