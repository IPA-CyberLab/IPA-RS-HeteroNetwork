#!/usr/bin/env bash
# Five real Agents, WireGuard interfaces and a disposable control plane.
# The bridge and synthetic public addresses are isolated from production.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ipars="${HETERONETWORK_E2E_IPARS:-${root}/target/debug/ipars}"
iparsd="${HETERONETWORK_E2E_IPARSD:-${root}/target/debug/iparsd}"
work="$(mktemp -d "${TMPDIR:-/tmp}/hn-strict-e2e.XXXXXX")"
chmod 700 "$work"
suffix="$$"
bridge="hns$((suffix % 1000000))"
subnet="11.254.$((100 + suffix % 100))"
control_ip="${subnet}.1"
port_base=$((20000 + (suffix % 1000) * 8))
declare -a namespaces=() agents=() daemons=()

cleanup() {
  local status=$?
  set +e
  # Reap managed wireguard-go children while their Agent is still alive.
  local pid child name
  for pid in "${agents[@]}"; do
    for child in $(pgrep -P "$pid" 2>/dev/null); do
      name="$(ps -p "$child" -o comm= 2>/dev/null | tr -d ' ')"
      [[ "$name" == wireguard-go ]] && kill "$child" 2>/dev/null
    done
  done
  for _ in 1 2 3 4; do
    local remaining=0
    for pid in "${agents[@]}"; do
      for child in $(pgrep -P "$pid" 2>/dev/null); do
        name="$(ps -p "$child" -o comm= 2>/dev/null | tr -d ' ')"
        [[ "$name" == wireguard-go ]] && remaining=1
      done
    done
    (( remaining == 0 )) && break
    sleep 0.5
  done
  for pid in "${agents[@]}" "${daemons[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${agents[@]}" "${daemons[@]}"; do wait "$pid" 2>/dev/null; done
  for ns in "${namespaces[@]}"; do ip netns del "$ns" 2>/dev/null; done
  ip link del "$bridge" 2>/dev/null
  if (( status != 0 )) && [[ "${HETERONETWORK_E2E_KEEP_FAILURE:-0}" == 1 ]]; then
    echo "isolated E2E diagnostics retained at $work" >&2
  else
    rm -rf -- "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

for command in ip wg curl jq python3 iptables ping; do command -v "$command" >/dev/null; done
[[ "$(id -u)" == 0 && -x "$ipars" && -x "$iparsd" ]]
python3 -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey'
if ip -4 route show exact "${subnet}.0/24" | grep -q .; then
  echo "isolated underlay subnet already exists" >&2
  exit 1
fi

ip link add "$bridge" type bridge
ip addr add "${control_ip}/24" dev "$bridge"
ip link set "$bridge" up
for i in 1 2 3 4 5; do
  ns="hn-strict-${suffix}-${i}"
  host_if="hs$((suffix % 100000))${i}"
  peer_if="hp$((suffix % 100000))${i}"
  ip netns add "$ns"
  namespaces+=("$ns")
  ip link add "$host_if" type veth peer name "$peer_if"
  ip link set "$host_if" master "$bridge"
  ip link set "$host_if" up
  ip link set "$peer_if" netns "$ns"
  ip -n "$ns" link set lo up
  ip -n "$ns" addr add "${subnet}.$((i + 1))/24" dev "$peer_if"
  ip -n "$ns" link set "$peer_if" up
  ip -n "$ns" route replace default via "$control_ip" dev "$peer_if"
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  # Conntrack hooks are enabled per network namespace when a stateful rule is
  # installed. An unconditional ACCEPT does not activate tracking on a clean
  # Actions VM, so the detector would receive no workload events at all.
  ip netns exec "$ns" iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
done

wireguard_backend=command
if ip -n "${namespaces[0]}" link add testwg type wireguard 2>/dev/null; then
  ip -n "${namespaces[0]}" link del testwg
else
  command -v wireguard-go >/dev/null || { echo "kernel WireGuard or wireguard-go is required" >&2; exit 1; }
  wireguard_backend=userspace-command
fi

agent_preload=()
if [[ "${HETERONETWORK_E2E_REJECT_CONNTRACK_DUMPS:-0}" == 1 ]]; then
  command -v cc >/dev/null
  cat >"$work/reject-conntrack-dump.c" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

ssize_t send(int fd, const void *buffer, size_t size, int flags) {
  static ssize_t (*actual_send)(int, const void *, size_t, int);
  if (!actual_send) actual_send = dlsym(RTLD_NEXT, "send");
  if (size >= sizeof(struct nlmsghdr)) {
    struct nlmsghdr header;
    int domain = 0, protocol = 0;
    socklen_t length = sizeof(int);
    memcpy(&header, buffer, sizeof(header));
    if (header.nlmsg_type == 0x101 && (header.nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP &&
        getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) == 0 &&
        getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &length) == 0 &&
        domain == AF_NETLINK && protocol == NETLINK_NETFILTER) {
      errno = EINVAL;
      return -1;
    }
  }
  return actual_send(fd, buffer, size, flags);
}
C
  cc -shared -fPIC -O2 -o "$work/reject-conntrack-dump.so" "$work/reject-conntrack-dump.c" -ldl
  agent_preload=("LD_PRELOAD=$work/reject-conntrack-dump.so")
fi

mkdir -m 700 "$work/bootstrap"
token="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
printf '%s\n' "$token" >"$work/operator-token"
printf 'header = "Authorization: Bearer %s"\n' "$token" >"$work/curl.conf"
chmod 600 "$work/operator-token" "$work/curl.conf"
unset token

"$ipars" init \
  --public-endpoint "${control_ip}:$((port_base + 5))" \
  --default-role worker --tag kubernetes-control-plane --unlimited-uses \
  --disable-relay --spawn-daemons --daemon-binary "$iparsd" \
  --daemon-state-dir "$work/bootstrap" --daemon-ready-timeout-seconds 30 \
  --control-plane-listen "${control_ip}:${port_base}" \
  --signal-listen "${control_ip}:$((port_base + 1))" \
  --stun-listen "${control_ip}:$((port_base + 2))" \
  --stun-alternate-listen "${control_ip}:$((port_base + 3))" \
  --stun-http-listen "${control_ip}:$((port_base + 4))" \
  --control-plane-operator-api-bearer-token-path "$work/operator-token" \
  --token-ttl-seconds 3600 >"$work/init.json" 2>"$work/init.log"
mapfile -t daemons < <(jq -r '.daemon_processes[].pid' "$work/init.json")
jq -c '.join_token' "$work/init.json" >"$work/join-token"
chmod 600 "$work/init.json" "$work/join-token"

for i in 1 2 3 4 5; do
  ns="${namespaces[i - 1]}"
  agent_ip="${subnet}.$((i + 1))"
  interface="hw$((suffix % 100000))${i}"
  backend_args=(--wireguard-backend "$wireguard_backend" --wireguard-interface "$interface")
  if [[ "$wireguard_backend" == userspace-command ]]; then
    backend_args+=(--userspace-wireguard-command "$(command -v wireguard-go)" \
      --userspace-wireguard-arg=-f --userspace-wireguard-arg "$interface")
  fi
  ip netns exec "$ns" env "${agent_preload[@]}" HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_ENABLED=false "$iparsd" agent \
    --listen 127.0.0.1:9780 --state-path "$work/agent-${i}.json" \
    --join-token-path "$work/join-token" \
    --control-plane-url "http://${control_ip}:${port_base}" \
    --signal-url "http://${control_ip}:$((port_base + 1))" \
    --stun-server "${control_ip}:$((port_base + 2)),${control_ip}:$((port_base + 3))" \
    --stun-bind "${agent_ip}:51820" --wireguard-listen-port 51820 \
    "${backend_args[@]}" --route-backend command --runtime-backend linux-command \
    --disable-public-services-autopromotion \
    --apply-peer-map --peer-map-poll-interval-seconds 2 --heartbeat-interval-seconds 2 \
    --signal-registration-interval-seconds 2 --signal-path-interval-seconds 2 \
    --peer-probe-sample-count 3 --peer-probe-response-timeout-millis 500 \
    --peer-probe-sample-interval-millis 100 \
    --packet-flow-detector "${HETERONETWORK_E2E_PACKET_FLOW_DETECTOR:-conntrack-netlink-events}" \
    --packet-flow-poll-interval-seconds 1 >"$work/agent-${i}.log" 2>&1 &
  agents+=("$!")
done

if [[ "$wireguard_backend" == userspace-command ]]; then
  for i in 1 2 3 4 5; do
    interface="hw$((suffix % 100000))${i}"
    for _ in $(seq 1 30); do
      if ip -n "${namespaces[i - 1]}" link set "$interface" up 2>/dev/null; then break; fi
      sleep 1
    done
    ip -n "${namespaces[i - 1]}" link show "$interface" >/dev/null
  done
fi

for i in 1 2 3 4 5; do
  ready=0
  for _ in $(seq 1 90); do
    if ip netns exec "${namespaces[i - 1]}" curl -fsS --max-time 2 \
      http://127.0.0.1:9780/v1/status >"$work/status-${i}.json" 2>/dev/null \
      && jq -e '.vpn_ip != null' "$work/status-${i}.json" >/dev/null; then
      ready=1
      break
    fi
    kill -0 "${agents[i - 1]}" 2>/dev/null || break
    sleep 1
  done
  [[ "$ready" == 1 ]] || { echo "agent $i did not join" >&2; exit 1; }
done
control_url="http://${control_ip}:${port_base}"
for _ in $(seq 1 60); do
  if curl --config "$work/curl.conf" -fsS --max-time 3 "$control_url/v1/admin/topology" \
      >"$work/topology.json" && jq -e '.node_count == 5' "$work/topology.json" >/dev/null; then
    break
  fi
  sleep 1
done
jq -e '.node_count == 5' "$work/topology.json" >/dev/null

curl --config "$work/curl.conf" -fsS "$control_url/v1/admin/policy" \
  | jq '.cluster_policy.overlay_strict_hierarchy = true | {cluster_policy}' >"$work/policy.json"
enabled=0
for _ in $(seq 1 45); do
  if curl --config "$work/curl.conf" -fsS -X PUT -H 'Content-Type: application/json' \
      --data-binary @"$work/policy.json" "$control_url/v1/admin/policy" >/dev/null 2>"$work/policy-error"; then
    enabled=1
    break
  fi
  sleep 1
done
[[ "$enabled" == 1 ]] || { echo "compatible Agent heartbeats did not arrive" >&2; exit 1; }

for i in 1 2 3 4 5; do
  ready=0
  node_id="$(jq -r '.node_id' "$work/status-${i}.json")"
  degree="$(jq -r --arg id "$node_id" '.nodes[] | select(.node_id == $id) | .degree' "$work/topology.json")"
  [[ "$degree" =~ ^[0-9]+$ ]]
  for _ in $(seq 1 60); do
    if ip netns exec "${namespaces[i - 1]}" curl -fsS --max-time 2 \
      http://127.0.0.1:9780/v1/metrics >"$work/metrics-${i}.json" 2>/dev/null \
      && jq -e --argjson degree "$degree" '.peer_map_synced and .peer_map_peer_count <= $degree' "$work/metrics-${i}.json" >/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { echo "agent $i did not converge to bounded peers" >&2; exit 1; }
done

curl --config "$work/curl.conf" -fsS "$control_url/v1/admin/topology" >"$work/topology.json"
mapfile -t pair < <(python3 - "$work" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
nodes = [json.loads((root / f'status-{i}.json').read_text()) for i in range(1, 6)]
topology = json.loads((root / 'topology.json').read_text())
edges = {frozenset((edge['source'], edge['target'])) for edge in topology['edges']}
for a, source in enumerate(nodes):
    for b, target in enumerate(nodes):
        if a != b and frozenset((source['node_id'], target['node_id'])) not in edges:
            print(a + 1); print(b + 1); print(target['vpn_ip']); sys.exit(0)
raise SystemExit('no non-neighbor pair')
PY
)
source="${pair[0]}"
target="${pair[1]}"
target_vpn="${pair[2]}"
echo "testing on-demand traffic between non-neighbor Agents"
if [[ "${HETERONETWORK_E2E_MANUAL_FLOW:-0}" == 1 ]]; then
  echo "injecting a flow observation because this kernel lacks conntrack events"
  ip netns exec "${namespaces[source - 1]}" curl -fsS -X POST \
    -H 'Content-Type: application/json' \
    --data "{\"destination\":\"${target_vpn}\"}" \
    http://127.0.0.1:9780/v1/packet-flow >/dev/null
fi
reachable=0
for _ in $(seq 1 90); do
  if ip netns exec "${namespaces[source - 1]}" ping -n -q -c 1 -W 1 "$target_vpn" >/dev/null 2>&1; then
    reachable=1
    break
  fi
  sleep 1
done
if [[ "$reachable" != 1 ]]; then
  echo "on-demand multi-hop WireGuard traffic failed; collecting non-secret detector diagnostics" >&2
  ip -n "${namespaces[source - 1]}" route get "$target_vpn" >&2 || true
  ip netns exec "${namespaces[source - 1]}" curl -fsS --max-time 3 \
    http://127.0.0.1:9780/v1/metrics 2>/dev/null | jq -c \
    '{peer_map_synced,packet_flow_observation_count,packet_flow_match_count,packet_flow_unmatched_count,packet_flow_filtered_count,packet_flow_filtered_reason_counts}' >&2 || true
  python3 - "$work/agent-${source}.log" <<'PY'
import pathlib, re, sys
lines = pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines()
for phrase in ('failed to open conntrack netlink event socket',
               'conntrack netlink event detector failed',
               'conntrack snapshot unavailable',
               'failed to apply peer map'):
    matching = [line for line in lines if phrase in line]
    print(f'{phrase}: {len(matching)} occurrence(s)', file=sys.stderr)
    if matching:
        # Netlink errors contain only OS error details; do not print arbitrary logs.
        match = re.search(r'(?:Operation not permitted|Invalid argument|No such file or directory|Permission denied)', matching[-1])
        if match: print(f'  OS error: {match.group(0)}', file=sys.stderr)
PY
  exit 1
fi
if [[ "${HETERONETWORK_E2E_REJECT_CONNTRACK_DUMPS:-0}" == 1 ]]; then
  grep -q 'conntrack snapshot unavailable.*failed to send conntrack netlink dump request' "$work/agent-${source}.log" || {
    echo "the injected conntrack dump failure was not observed" >&2
    exit 1
  }
  if [[ "${HETERONETWORK_E2E_MANUAL_FLOW:-0}" == 1 ]]; then
    echo "verified injected snapshot failure with manually observed traffic"
  else
    echo "verified automatic flow detection while conntrack snapshots fail"
  fi
fi

target_key="$(jq -r '.wireguard_public_key' "$work/status-${target}.json")"
source_interface="hw$((suffix % 100000))${source}"
endpoint="$(ip netns exec "${namespaces[source - 1]}" wg show "$source_interface" endpoints \
  | awk -v key="$target_key" '$1 == key { print $2 }')"
[[ "$endpoint" == 127.* ]] || { echo "non-neighbor endpoint bypassed the overlay" >&2; exit 1; }

if [[ "${HETERONETWORK_E2E_SKIP_NETEM:-0}" != 1 ]]; then
  command -v tc >/dev/null
  source_underlay="hp$((suffix % 100000))${source}"
  ip netns exec "${namespaces[source - 1]}" tc qdisc add dev "$source_underlay" root netem delay 700ms 30ms
  reachable=0
  for _ in $(seq 1 8); do
    if ip netns exec "${namespaces[source - 1]}" ping -n -q -c 1 -W 4 "$target_vpn" >/dev/null 2>&1; then
      reachable=1
      break
    fi
  done
  ip netns exec "${namespaces[source - 1]}" tc qdisc del dev "$source_underlay" root
  [[ "$reachable" == 1 ]] || { echo "delayed multi-hop route failed" >&2; exit 1; }
  echo "verified a 700 ms delayed underlay"
else
  echo "skipping underlay delay injection on this kernel"
fi

# Query the same signed path the Agent uses, then drop its first physical hop.
python3 - "$work/agent-${source}.json" "$target_vpn" "$work/path-query.json" <<'PY'
import base64, datetime, json, os, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
state = json.loads(pathlib.Path(sys.argv[1]).read_text())
nonce = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip('=')
now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
body = {'source': state['node_id'], 'destination': sys.argv[2], 'signed_at': now, 'nonce': nonce}
key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(state['identity_private_key_b64']))
signature = base64.b64encode(key.sign(json.dumps(body, separators=(',', ':')).encode())).decode()
request = {'source': state['node_id'], 'destination': sys.argv[2],
           'source_identity_proof': {'signed_at': now, 'nonce': nonce, 'signature': signature}}
pathlib.Path(sys.argv[3]).write_text(json.dumps(request))
PY
chmod 600 "$work/path-query.json"
curl -fsS -H 'Content-Type: application/json' --data-binary @"$work/path-query.json" \
  "$control_url/v1/overlay-paths/query" >"$work/path.json"
jq -e '(.ordered_nodes | length) >= 3 and (.secondary_ordered_nodes | length) >= 3' "$work/path.json" >/dev/null
next_node="$(jq -r '.ordered_nodes[1]' "$work/path.json")"
next_index="$(python3 - "$work" "$next_node" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for index in range(1, 6):
    if json.loads((root / f'status-{index}.json').read_text())['node_id'] == sys.argv[2]:
        print(index); break
else:
    raise SystemExit('unknown first hop')
PY
)"
ip netns exec "${namespaces[source - 1]}" iptables -I OUTPUT 1 \
  -d "${subnet}.$((next_index + 1))" -p udp --dport 51820 \
  -m comment --comment hns-failover-e2e -j DROP
reachable=0
for _ in $(seq 1 45); do
  if ip netns exec "${namespaces[source - 1]}" ping -n -q -c 1 -W 2 "$target_vpn" >/dev/null 2>&1; then
    drops="$(ip netns exec "${namespaces[source - 1]}" iptables -nvx -L OUTPUT \
      | awk '/hns-failover-e2e/ {print $1; exit}')"
    if [[ "${drops:-0}" =~ ^[0-9]+$ ]] && (( drops > 0 )); then
      reachable=1
      break
    fi
  fi
  sleep 1
done
[[ "$reachable" == 1 ]] || { echo "alternate route failed or the selected hop did not receive any packets" >&2; exit 1; }
ip netns exec "${namespaces[source - 1]}" iptables -D OUTPUT \
  -d "${subnet}.$((next_index + 1))" -p udp --dport 51820 \
  -m comment --comment hns-failover-e2e -j DROP

# A native Agent joining after strict mode is active must bootstrap without
# downloading every existing native peer, then acquire bounded neighbors.
i=6
ns="hn-strict-${suffix}-${i}"
host_if="hs$((suffix % 100000))${i}"
peer_if="hp$((suffix % 100000))${i}"
interface="hw$((suffix % 100000))${i}"
agent_ip="${subnet}.$((i + 1))"
ip netns add "$ns"
namespaces+=("$ns")
ip link add "$host_if" type veth peer name "$peer_if"
ip link set "$host_if" master "$bridge"
ip link set "$host_if" up
ip link set "$peer_if" netns "$ns"
ip -n "$ns" link set lo up
ip -n "$ns" addr add "${agent_ip}/24" dev "$peer_if"
ip -n "$ns" link set "$peer_if" up
ip -n "$ns" route replace default via "$control_ip" dev "$peer_if"
ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$ns" iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
backend_args=(--wireguard-backend "$wireguard_backend" --wireguard-interface "$interface")
if [[ "$wireguard_backend" == userspace-command ]]; then
  backend_args+=(--userspace-wireguard-command "$(command -v wireguard-go)" \
    --userspace-wireguard-arg=-f --userspace-wireguard-arg "$interface")
fi
ip netns exec "$ns" env "${agent_preload[@]}" HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_ENABLED=false "$iparsd" agent \
  --listen 127.0.0.1:9780 --state-path "$work/agent-${i}.json" --join-token-path "$work/join-token" \
  --control-plane-url "$control_url" --signal-url "http://${control_ip}:$((port_base + 1))" \
  --stun-server "${control_ip}:$((port_base + 2)),${control_ip}:$((port_base + 3))" \
  --stun-bind "${agent_ip}:51820" --wireguard-listen-port 51820 \
  "${backend_args[@]}" --route-backend command --runtime-backend linux-command \
  --disable-public-services-autopromotion --apply-peer-map --peer-map-poll-interval-seconds 2 \
  --heartbeat-interval-seconds 2 --signal-registration-interval-seconds 2 --signal-path-interval-seconds 2 \
  --peer-probe-sample-count 3 --peer-probe-response-timeout-millis 500 --peer-probe-sample-interval-millis 100 \
  --packet-flow-detector "${HETERONETWORK_E2E_PACKET_FLOW_DETECTOR:-conntrack-netlink-events}" \
  --packet-flow-poll-interval-seconds 1 >"$work/agent-${i}.log" 2>&1 &
agents+=("$!")
if [[ "$wireguard_backend" == userspace-command ]]; then
  for _ in $(seq 1 30); do
    if ip -n "$ns" link set "$interface" up 2>/dev/null; then break; fi
    sleep 1
  done
fi
ready=0
for _ in $(seq 1 90); do
  if ip netns exec "$ns" curl -fsS --max-time 2 http://127.0.0.1:9780/v1/metrics >"$work/metrics-6.json" 2>/dev/null \
      && jq -e '.peer_map_synced and .peer_map_peer_count <= 4' "$work/metrics-6.json" >/dev/null \
      && grep -q 'peer_count=0' "$work/agent-6.log"; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "new Agent did not join with a bounded initial map; non-secret diagnostics:" >&2
  if kill -0 "${agents[5]}" 2>/dev/null; then echo "agent process: running" >&2; else echo "agent process: exited" >&2; fi
  if [[ -s "$work/metrics-6.json" ]]; then
    jq -c '{peer_map_synced,peer_map_peer_count,peer_map_route_count}' "$work/metrics-6.json" >&2 || true
  else
    echo "agent metrics endpoint: unavailable" >&2
  fi
  python3 - "$work/agent-6.log" <<'PY'
import pathlib, re, sys
lines = pathlib.Path(sys.argv[1]).read_text(errors='replace').splitlines()
registered = [line for line in lines if 'registered agent with control plane' in line]
print(f'registration log entries: {len(registered)}', file=sys.stderr)
if registered:
    match = re.search(r'peer_count=(\d+)', registered[-1])
    print(f'initial peer count: {match.group(1) if match else "unavailable"}', file=sys.stderr)
for phrase in ('failed to register agent', 'failed to apply peer map', 'failed to fetch peer map'):
    print(f'{phrase}: {sum(phrase in line for line in lines)} occurrence(s)', file=sys.stderr)
PY
  exit 1
fi
echo "strict hierarchy E2E passed: real WireGuard, on-demand path, first-hop failure and bounded new-node join"
