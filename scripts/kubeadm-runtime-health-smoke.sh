#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Isolate the probe: no runtime, systemd or Kubernetes changes are performed.
source <(sed -n '/^container_runtime_healthy() {$/,/^}$/p' "$root/scripts/kubeadm-ha-node.sh")
timeout() { shift 2; "$@"; }
crictl() {
  [[ "$1" == --runtime-endpoint && "$2" == unix:///run/containerd/containerd.sock ]]
  [[ "$3" == --timeout && "$4" == 10s ]]
  case "$5" in
    info) printf '%s\n' "$probe_output" ;;
    pods) [[ "$list_failure" != pods ]] ;;
    ps) [[ "$list_failure" != ps ]] ;;
    *) return 99 ;;
  esac
}
list_failure=""
probe_output='{"status":{"conditions":[{"type":"RuntimeReady","status":true}]}}'
container_runtime_healthy
for list_failure in pods ps; do
  if container_runtime_healthy; then
    printf 'unhealthy %s list was accepted\n' "$list_failure" >&2
    exit 1
  fi
done
list_failure=""
for probe_output in \
  '{"status":{"conditions":[{"type":"RuntimeReady","status":false}]}}' \
  '{"status":{"conditions":[]}}' \
  '{"status":{"conditions":[{"type":"RuntimeReady","status":"true"}]}}' \
  'invalid-json'; do
  if container_runtime_healthy; then
    printf 'unhealthy runtime status was accepted\n' >&2
    exit 1
  fi
done
probe_output='{"status":{"conditions":[{"type":"RuntimeReady","status":true},{"type":"NetworkReady","status":false}]}}'
container_runtime_healthy
timeout() { return 124; }
if container_runtime_healthy; then
  printf 'timed-out runtime was accepted\n' >&2
  exit 1
fi
printf 'runtime health smoke: passed\n'
