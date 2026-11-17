#!/usr/bin/env bash
# Exercise the deployed etcd version in two disposable network namespaces.
set -euo pipefail
[[ "${HNN_ETCD_PARTITION_E2E:-}" == isolated-only && "$(id -u)" == 0 && $# == 2 ]]
etcd="$(realpath "$1")"
etcdctl="$(realpath "$2")"
[[ -x "$etcd" && -x "$etcdctl" ]]
for command in ip iptables timeout python3; do command -v "$command" >/dev/null; done
work="$(mktemp -d /tmp/hnn-dcs-e2e.XXXXXX)"
chmod 700 "$work"
suffix="$$"
bridge="hnd$((suffix % 1000000))"
subnet="198.18.$((suffix % 200 + 20))"
declare -a namespaces=() pids=()
cleanup() {
  local result=$?
  set +e
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  for ns in "${namespaces[@]}"; do ip netns del "$ns" 2>/dev/null; done
  ip link del "$bridge" 2>/dev/null
  if (( result != 0 )); then
    for log in "$work"/*.log; do [[ -f "$log" ]] && tail -n 15 "$log" >&2; done
  fi
  python3 - "$work" <<'PY'
import pathlib, shutil, sys
p = pathlib.Path(sys.argv[1]).resolve()
if p.parent == pathlib.Path('/tmp') and p.name.startswith('hnn-dcs-e2e.'):
    shutil.rmtree(p)
PY
  exit "$result"
}
trap cleanup EXIT
if ip -4 route show exact "${subnet}.0/24" | grep -q .; then
  echo 'isolated DCS test subnet already exists' >&2
  exit 1
fi
ip link add "$bridge" type bridge
ip addr add "${subnet}.1/24" dev "$bridge"
ip link set "$bridge" up
for i in 1 2; do
  ns="hn-dcs-${suffix}-${i}"
  host_if="hd$((suffix % 100000))${i}"
  peer_if="dp$((suffix % 100000))${i}"
  ip netns add "$ns"
  namespaces+=("$ns")
  ip link add "$host_if" type veth peer name "$peer_if"
  ip link set "$host_if" master "$bridge"
  ip link set "$host_if" up
  ip link set "$peer_if" netns "$ns"
  ip -n "$ns" link set lo up
  ip -n "$ns" addr add "${subnet}.$((i + 1))/24" dev "$peer_if"
  ip -n "$ns" link set "$peer_if" up
done
cluster="a=http://${subnet}.2:2380,b=http://${subnet}.3:2380"
for i in 1 2; do
  name=a; (( i == 2 )) && name=b
  ip netns exec "${namespaces[i - 1]}" "$etcd" \
    --name "$name" --data-dir "$work/$name" \
    --listen-peer-urls "http://${subnet}.$((i + 1)):2380" \
    --initial-advertise-peer-urls "http://${subnet}.$((i + 1)):2380" \
    --listen-client-urls "http://${subnet}.$((i + 1)):2379" \
    --advertise-client-urls "http://${subnet}.$((i + 1)):2379" \
    --initial-cluster "$cluster" --initial-cluster-state new \
    --initial-cluster-token "hnn-dcs-e2e-${suffix}" --log-level warn >"$work/$name.log" 2>&1 &
  pids+=("$!")
done
ctl() {
  ETCDCTL_API=3 "$etcdctl" --endpoints "$1" --dial-timeout=2s --command-timeout=5s "${@:2}"
}
endpoints="http://${subnet}.2:2379,http://${subnet}.3:2379"
ready=0
for _ in $(seq 1 45); do
  if ctl "$endpoints" endpoint health >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'isolated DCS did not form quorum' >&2; exit 1; }
ctl "$endpoints" put site-partition-check before >/dev/null
for i in 1 2; do
  other=3; (( i == 2 )) && other=2
  # etcd uses long-lived bidirectional peer streams, including replies from
  # source port 2380 to an ephemeral destination port. Block every TCP packet
  # between voters rather than only packets addressed to port 2380.
  ip netns exec "${namespaces[i - 1]}" iptables -I OUTPUT 1 -p tcp \
    -d "${subnet}.${other}" -m comment --comment hnn-dcs-partition -j DROP
done
sleep 3
blocked=0
for i in 1 2; do
  count="$(ip netns exec "${namespaces[i - 1]}" iptables -nvx -L OUTPUT \
    | awk '/hnn-dcs-partition/ {sum += $1} END {print sum+0}')"
  blocked=$((blocked + count))
done
(( blocked > 0 )) || { echo 'the DCS partition rules did not block peer traffic' >&2; exit 1; }
for i in 1 2; do
  if ctl "http://${subnet}.$((i + 1)):2379" put site-partition-check "unsafe-${i}" >/dev/null 2>&1; then
    echo "isolated DCS member $i accepted a write without quorum" >&2; exit 1
  fi
done
for i in 1 2; do
  other=3; (( i == 2 )) && other=2
  ip netns exec "${namespaces[i - 1]}" iptables -D OUTPUT -p tcp \
    -d "${subnet}.${other}" -m comment --comment hnn-dcs-partition -j DROP
done
ready=0
for _ in $(seq 1 45); do
  if ctl "$endpoints" endpoint health >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'isolated DCS quorum did not recover' >&2; exit 1; }
for i in 1 2; do
  [[ "$(ctl "http://${subnet}.$((i + 1)):2379" get site-partition-check --print-value-only)" == before ]] \
    || { echo 'the pre-partition value changed' >&2; exit 1; }
done
ctl "$endpoints" put site-partition-check after >/dev/null
[[ "$(ctl "$endpoints" get site-partition-check --print-value-only)" == after ]]
echo 'two-voter DCS partition E2E passed: neither side accepted writes without quorum; quorum and writes recovered'
