#!/usr/bin/env bash
# Sourced only by strict-hierarchy-netns-e2e.sh after it creates disposable
# namespaces and a private control plane; never target production interfaces.

run_strict_site_partition_e2e() {
  local i j pair src dst vpn old_epoch changed ready count
  local -a site_pairs=()
  for i in 1 2 3 4 5 6; do
    ip netns exec "${namespaces[i - 1]}" curl -fsS --max-time 3 \
      http://127.0.0.1:9780/v1/status >"$work/status-${i}.json"
  done
  curl --config "$work/curl.conf" -fsS "$control_url/v1/admin/topology" >"$work/site-before.json"
  old_epoch="$(jq -r '.topology_epoch' "$work/site-before.json")"
  curl --config "$work/curl.conf" -fsS "$control_url/v1/admin/policy" >"$work/site-policy.json"
  python3 - "$work" <<'PY'
import datetime, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
policy = json.loads((root / 'site-policy.json').read_text())['cluster_policy']
localities = {}
for index in range(1, 7):
    node = json.loads((root / f'status-{index}.json').read_text())['node_id']
    localities[node] = {'region': 'east' if index <= 3 else 'west',
                        'zone': 'site-a' if index <= 3 else 'site-b'}
policy['overlay_node_localities'] = localities
(root / 'site-policy.json').write_text(json.dumps({'cluster_policy': policy}))
(root / 'site-started-at').write_text(datetime.datetime.now(datetime.timezone.utc).isoformat())
PY
  chmod 600 "$work/site-policy.json"
  curl --config "$work/curl.conf" -fsS -X PUT -H 'Content-Type: application/json' \
    --data-binary @"$work/site-policy.json" "$control_url/v1/admin/policy" >"$work/site-policy-result.json"
  jq -e '.cluster_policy.overlay_strict_hierarchy and (.cluster_policy.overlay_node_localities | length) == 6' \
    "$work/site-policy-result.json" >/dev/null
  changed=0
  for _ in $(seq 1 60); do
    if curl --config "$work/curl.conf" -fsS --max-time 3 "$control_url/v1/admin/topology" >"$work/site-topology.json" \
      && jq -e --arg old "$old_epoch" '.node_count == 6 and .topology_epoch != $old and .max_observed_degree <= .max_degree' \
        "$work/site-topology.json" >/dev/null; then
      changed=1
      break
    fi
    sleep 1
  done
  [[ "$changed" == 1 ]] || { echo 'site locality policy did not converge to a new topology' >&2; return 1; }
  for i in 1 2 3 4 5 6; do
    ready=0
    for _ in $(seq 1 75); do
      if ip netns exec "${namespaces[i - 1]}" curl -fsS --max-time 2 \
        http://127.0.0.1:9780/v1/metrics >"$work/site-metrics-${i}.json" 2>/dev/null \
        && python3 - "$work/site-metrics-${i}.json" "$work/site-started-at" <<'PY'
import datetime, json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
value = data.get('peer_map_generated_at')
start = datetime.datetime.fromisoformat(pathlib.Path(sys.argv[2]).read_text())
raise SystemExit(0 if data.get('peer_map_synced') and value and
                 datetime.datetime.fromisoformat(value.replace('Z', '+00:00')) > start else 1)
PY
      then
        ready=1
        break
      fi
      sleep 1
    done
    [[ "$ready" == 1 ]] || { echo "agent $i did not synchronize site-aware topology" >&2; return 1; }
  done

  # Choose real topology edges within each site and across sites. This checks
  # intra-site communication without relying on a path through the other site.
  mapfile -t site_pairs < <(python3 - "$work" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
ids = {json.loads((root / f'status-{i}.json').read_text())['node_id']: i for i in range(1, 7)}
edges = [(ids[e['source']], ids[e['target']]) for e in json.loads((root / 'site-topology.json').read_text())['edges']]
for predicate in (lambda a,b: a <= 3 and b <= 3,
                  lambda a,b: a > 3 and b > 3,
                  lambda a,b: (a <= 3) != (b <= 3)):
    edge = next(((a,b) for a,b in edges if predicate(a,b)), None)
    if edge is None:
        raise SystemExit('site-aware topology lacks a required physical edge')
    print(*edge)
PY
  )
  [[ ${#site_pairs[@]} == 3 ]] || return 1
  for pair in "${site_pairs[@]}"; do
    read -r src dst <<<"$pair"
    vpn="$(jq -r '.vpn_ip' "$work/status-${dst}.json")"
    ready=0
    for _ in $(seq 1 30); do
      if ip netns exec "${namespaces[src - 1]}" ping -n -q -c 1 -W 2 "$vpn" >/dev/null 2>&1; then
        ready=1; break
      fi
      sleep 1
    done
    [[ "$ready" == 1 ]] || { echo 'baseline site connection failed' >&2; return 1; }
  done
  for i in 1 2 3 4 5 6; do
    for j in 1 2 3 4 5 6; do
      if (( (i <= 3 && j > 3) || (i > 3 && j <= 3) )); then
        ip netns exec "${namespaces[i - 1]}" iptables -I OUTPUT 1 \
          -d "${subnet}.$((j + 1))" -p udp --dport 51820 \
          -m comment --comment hns-site-partition-e2e -j DROP
      fi
    done
  done
  for pair in "${site_pairs[0]}" "${site_pairs[1]}"; do
    read -r src dst <<<"$pair"
    vpn="$(jq -r '.vpn_ip' "$work/status-${dst}.json")"
    ip netns exec "${namespaces[src - 1]}" ping -n -q -c 2 -W 2 "$vpn" >/dev/null \
      || { echo 'intra-site communication failed during partition' >&2; return 1; }
  done
  read -r src dst <<<"${site_pairs[2]}"
  vpn="$(jq -r '.vpn_ip' "$work/status-${dst}.json")"
  if ip netns exec "${namespaces[src - 1]}" ping -n -q -c 3 -W 1 "$vpn" >/dev/null 2>&1; then
    echo 'cross-site traffic unexpectedly passed the simulated partition' >&2; return 1
  fi
  count="$(ip netns exec "${namespaces[src - 1]}" iptables -nvx -L OUTPUT \
    | awk '/hns-site-partition-e2e/ {sum += $1} END {print sum+0}')"
  (( count > 0 )) || { echo 'the cross-site drop rule saw no traffic' >&2; return 1; }
  for i in 1 2 3 4 5 6; do
    for j in 1 2 3 4 5 6; do
      if (( (i <= 3 && j > 3) || (i > 3 && j <= 3) )); then
        ip netns exec "${namespaces[i - 1]}" iptables -D OUTPUT \
          -d "${subnet}.$((j + 1))" -p udp --dport 51820 \
          -m comment --comment hns-site-partition-e2e -j DROP
      fi
    done
  done
  ready=0
  for _ in $(seq 1 60); do
    if ip netns exec "${namespaces[src - 1]}" ping -n -q -c 1 -W 2 "$vpn" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { echo 'cross-site traffic did not recover after partition healed' >&2; return 1; }
  echo 'site partition E2E passed: real WireGuard, intra-site continuity, blocked inter-site traffic, and recovery'
}
