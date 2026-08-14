#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DEFAULT_INTERFACE="heteronetwork0"
readonly DEFAULT_API_NAME="k8s-api.heteronetwork.internal"
readonly DEFAULT_OVERLAY_DNS_ZONE="heteronetwork.internal"
readonly DEFAULT_API_PROXY_PORT="7443"
readonly DEFAULT_POD_CIDR="10.244.0.0/16"
readonly DEFAULT_SERVICE_CIDR="10.96.0.0/12"
readonly DEFAULT_KUBERNETES_MINOR="v1.36"
readonly DEFAULT_MAX_PODS="240"
readonly DEFAULT_STATE_DIR="/etc/heteronetwork/kubernetes"
readonly DEFAULT_AGENT_STATE_PATH="/var/lib/heteronetwork/agent.json"
readonly KUBELET_RESOLV_CONF="/etc/kubernetes/resolv.conf"
readonly NODE_MONITOR_GRACE_PERIOD="20s"
readonly FLANNEL_VERSION="v0.28.4"
readonly FLANNEL_VXLAN_IPV4_OVERHEAD="50"
readonly MIN_IPV4_MTU="576"
readonly POD_CIDR_POLICY_PRIORITY="50"
readonly FLANNEL_MANIFEST_SHA256="d078019743c5e0194ce965125fc80ef00af0c1661ec9e12396311f1cfec860a2"
readonly FLANNEL_MANIFEST_URL="https://github.com/flannel-io/flannel/releases/download/${FLANNEL_VERSION}/kube-flannel.yml"

interface="${HETERONETWORK_KUBEADM_INTERFACE:-$DEFAULT_INTERFACE}"
node_ip="${HETERONETWORK_KUBEADM_NODE_IP:-}"
node_name="${HETERONETWORK_KUBEADM_NODE_NAME:-}"
control_plane_backends="${HETERONETWORK_KUBEADM_CONTROL_PLANES:-}"
preferred_control_plane="${HETERONETWORK_KUBEADM_PREFERRED_CONTROL_PLANE:-}"
apiserver_etcd_backends="${HETERONETWORK_KUBEADM_APISERVER_ETCD_ENDPOINTS:-}"
api_name="${HETERONETWORK_KUBEADM_API_NAME:-$DEFAULT_API_NAME}"
api_proxy_port="${HETERONETWORK_KUBEADM_API_PROXY_PORT:-$DEFAULT_API_PROXY_PORT}"
pod_cidr="${HETERONETWORK_KUBEADM_POD_CIDR:-$DEFAULT_POD_CIDR}"
service_cidr="${HETERONETWORK_KUBEADM_SERVICE_CIDR:-$DEFAULT_SERVICE_CIDR}"
kubernetes_minor="${HETERONETWORK_KUBEADM_KUBERNETES_MINOR:-$DEFAULT_KUBERNETES_MINOR}"
max_pods="${HETERONETWORK_KUBEADM_MAX_PODS:-$DEFAULT_MAX_PODS}"
state_dir="${HETERONETWORK_KUBEADM_STATE_DIR:-$DEFAULT_STATE_DIR}"
agent_state_path="${HETERONETWORK_AGENT_STATE_PATH:-$DEFAULT_AGENT_STATE_PATH}"
agent_api_token_path="${HETERONETWORK_KUBEADM_AGENT_API_TOKEN_PATH:-$state_dir/agent-api-token}"

usage() {
  cat <<'EOF'
Usage: kubeadm-ha-node.sh COMMAND

Commands:
  prepare               Install and configure this Kubernetes host
  configure-overlay-dns Configure persistent host split DNS for the private zone
  init                   Initialize the first stacked-etcd control-plane node
  refresh-join-bundle    Rotate the short-lived kubeadm join credentials
  refresh-worker-join-bundle
                         Rotate worker-only kubeadm join credentials
  join-control-plane     Join this host as another stacked-etcd control-plane node
  promote-control-plane  Reset an existing worker and rejoin it as a control plane
  join-worker            Join this host as a regular worker node
  reconcile-control-plane-backends
                         Update the local API proxy and split-DNS control-plane set
  reconcile-apiserver-etcd
                         Point the local API server at selected stacked-etcd members
  reconcile-pod-routing Reconcile host-network traffic routing to the Flannel Pod CIDR
  install-flannel        Install pinned Flannel on the initialized cluster
  finalize               Allow workloads on control-plane nodes and wait for readiness
  verify-host            Verify the local HeteroNetwork and Kubernetes prerequisites
  verify-cluster         Verify nodes, control planes, Flannel, DNS, and cross-node Pod traffic
  configure-api-ha       Reconcile API health checks and kubelet HA endpoint
  reconcile-kubelet-api  Route kubelet through the local HA API proxy
  reconcile-kubelet-dns  Limit kubelet's upstream resolver list to three stable entries
  self-test              Run non-privileged renderer and validation checks

Required environment for prepare/init/join:
  HETERONETWORK_KUBEADM_NODE_IP
  HETERONETWORK_KUBEADM_CONTROL_PLANES   Comma-separated HeteroNetwork IPv4 addresses

Optional environment:
  HETERONETWORK_KUBEADM_INTERFACE        Default: heteronetwork0
  HETERONETWORK_KUBEADM_NODE_NAME        Default: normalized short hostname
  HETERONETWORK_KUBEADM_PREFERRED_CONTROL_PLANE
                                         API backend preferred by every local proxy
  HETERONETWORK_KUBEADM_API_NAME         Default: k8s-api.heteronetwork.internal
  HETERONETWORK_KUBEADM_API_PROXY_PORT   Default: 7443
  HETERONETWORK_KUBEADM_POD_CIDR         Default: 10.244.0.0/16
  HETERONETWORK_KUBEADM_SERVICE_CIDR     Default: 10.96.0.0/12
  HETERONETWORK_KUBEADM_KUBERNETES_MINOR Default: v1.36
  HETERONETWORK_KUBEADM_MAX_PODS          Default: 240 (must fit the CNI node CIDR)
  HETERONETWORK_KUBEADM_APISERVER_ETCD_ENDPOINTS
                                         Comma-separated control-plane VPN IPv4 addresses
  HETERONETWORK_KUBEADM_JOIN_BUNDLE      Default: state-dir/join-bundle.json
  HETERONETWORK_KUBEADM_WORKER_JOIN_BUNDLE
                                         Default: state-dir/worker-join-bundle.json
  HETERONETWORK_KUBEADM_AGENT_API_TOKEN_PATH
                                         Default: state-dir/agent-api-token
  HETERONETWORK_AGENT_STATE_PATH          Default: /var/lib/heteronetwork/agent.json
  HETERONETWORK_KUBEADM_PROMOTE_EXISTING_WORKER
                                         Must be 1 for promote-control-plane

The join bundle contains credentials. Keep it root-owned with mode 0600 and transfer it
over an authenticated channel. Commands do not print tokens or certificate keys.
For join-worker, the node IP must not be in HETERONETWORK_KUBEADM_CONTROL_PLANES.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' is not available"
}

validate_interface_name() {
  [[ "$1" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "invalid Linux interface name: $1"
}

validate_dns_name() {
  local value="$1"
  [[ ${#value} -le 253 && "$value" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] \
    || die "invalid lowercase DNS name: $value"
  [[ "$value" != *..* ]] || die "DNS name contains an empty label: $value"
}

validate_node_name() {
  local value="$1"
  [[ ${#value} -le 63 && "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] \
    || die "invalid Kubernetes node name: $value"
}

validate_port() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]] || die "invalid TCP port: $value"
  ((10#$value >= 1 && 10#$value <= 65535)) || die "TCP port is out of range: $value"
}

validate_ipv4() {
  local value="$1"
  local a b c d extra
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && -n "${a:-}" && -n "${b:-}" && -n "${c:-}" && -n "${d:-}" ]] \
    || die "invalid IPv4 address: $value"
  local octet
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || die "invalid IPv4 address: $value"
    ((10#$octet <= 255)) || die "invalid IPv4 address: $value"
  done
}

validate_cidr_literal() {
  [[ "$1" =~ ^[0-9a-fA-F:.]+/[0-9]{1,3}$ ]] || die "invalid CIDR literal: $1"
}

normalized_hostname() {
  hostname -s \
    | tr '[:upper:]_' '[:lower:]-' \
    | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//; s/-+/-/g' \
    | cut -c1-63
}

resolve_node_name() {
  if [[ -z "$node_name" ]]; then
    node_name="$(normalized_hostname)"
  fi
  validate_node_name "$node_name"
}

backend_addresses() {
  local raw
  local -a values
  IFS=, read -r -a values <<<"$control_plane_backends"
  ((${#values[@]} >= 3)) || die "at least three control-plane addresses are required"

  local -A seen=()
  for raw in "${values[@]}"; do
    [[ "$raw" == "${raw//[[:space:]]/}" ]] || die "control-plane addresses must not contain whitespace"
    validate_ipv4 "$raw"
    [[ -z "${seen[$raw]:-}" ]] || die "duplicate control-plane address: $raw"
    seen[$raw]=1
    printf '%s\n' "$raw"
  done
}

apiserver_etcd_addresses() {
  [[ -n "$apiserver_etcd_backends" ]] \
    || die "at least three API server etcd endpoints are required"

  local raw backend
  local -a values
  local -A control_planes=()
  local -A seen=()
  while IFS= read -r backend; do
    control_planes[$backend]=1
  done < <(backend_addresses)
  IFS=, read -r -a values <<<"$apiserver_etcd_backends"
  ((${#values[@]} >= 3)) || die "at least three API server etcd endpoints are required"

  for raw in "${values[@]}"; do
    [[ "$raw" == "${raw//[[:space:]]/}" ]] \
      || die "API server etcd endpoints must not contain whitespace"
    validate_ipv4 "$raw"
    [[ -n "${control_planes[$raw]:-}" ]] \
      || die "API server etcd endpoint is not a control-plane address: $raw"
    [[ -z "${seen[$raw]:-}" ]] || die "duplicate API server etcd endpoint: $raw"
    seen[$raw]=1
    printf '%s\n' "$raw"
  done
}

render_apiserver_etcd_servers() {
  local address rendered=""
  while IFS= read -r address; do
    rendered="${rendered:+${rendered},}https://${address}:2379"
  done < <(apiserver_etcd_addresses)
  printf '%s\n' "$rendered"
}

validate_common_config() {
  validate_interface_name "$interface"
  validate_ipv4 "$node_ip"
  validate_dns_name "$api_name"
  validate_port "$api_proxy_port"
  validate_cidr_literal "$pod_cidr"
  validate_cidr_literal "$service_cidr"
  [[ "$kubernetes_minor" =~ ^v[0-9]+\.[0-9]+$ ]] \
    || die "Kubernetes minor must look like v1.36: $kubernetes_minor"
  [[ "$max_pods" =~ ^[0-9]+$ ]] || die "max Pods must be an integer: $max_pods"
  ((10#$max_pods >= 1 && 10#$max_pods <= 240)) \
    || die "max Pods must be between 1 and 240 for the default Flannel /24 node CIDR: $max_pods"
  [[ "$state_dir" == /* ]] || die "state directory must be absolute"
  [[ "$agent_api_token_path" == /* ]] || die "Agent API token path must be absolute"
  resolve_node_name
  backend_addresses >/dev/null
  if [[ -n "$preferred_control_plane" ]]; then
    validate_ipv4 "$preferred_control_plane"
    backend_addresses | grep -Fx "$preferred_control_plane" >/dev/null \
      || die "preferred control plane is not present in the backend list: $preferred_control_plane"
  fi
}

validate_overlay_dns_config() {
  validate_interface_name "$interface"
  validate_ipv4 "$node_ip"
  validate_dns_name "$DEFAULT_OVERLAY_DNS_ZONE"
  [[ "$state_dir" == /* ]] || die "state directory must be absolute"
  backend_addresses >/dev/null
}

node_is_control_plane_backend() {
  local found=0
  local backend
  while IFS= read -r backend; do
    [[ "$backend" == "$node_ip" ]] && found=1
  done < <(backend_addresses)
  ((found == 1))
}

validate_control_plane_config() {
  validate_common_config
  node_is_control_plane_backend \
    || die "node IP $node_ip is not present in the control-plane backend list"
}

validate_worker_config() {
  validate_common_config
  if node_is_control_plane_backend; then
    die "worker node IP $node_ip must not be present in the control-plane backend list"
  fi
}

validate_worker_enrollment() {
  require_command jq
  [[ "$agent_state_path" == /* ]] || die "HeteroNetwork Agent state path must be absolute"
  [[ -f "$agent_state_path" && ! -L "$agent_state_path" ]] \
    || die "HeteroNetwork Agent state is missing or is a symlink: $agent_state_path"
  jq -e --arg node_ip "$node_ip" '
    (.registered_node | type == "object")
    and (.registered_node.vpn_ip == $node_ip)
    and (.registered_node.tags | type == "array")
    and all(.registered_node.tags[]; type == "string")
  ' "$agent_state_path" >/dev/null \
    || die "HeteroNetwork Agent registration does not match worker node IP $node_ip"
  if jq -e '
    any(
      .registered_node.tags[];
      . == "kubernetes-control-plane" or startswith("kubernetes-ha-")
    )
  ' "$agent_state_path" >/dev/null; then
    die "worker enrollment carries Kubernetes HA control-plane tags; re-enroll this HeteroNetwork node as network-only before joining it as a worker"
  fi
}

verify_interface_address() {
  require_command ip
  ip link show dev "$interface" >/dev/null 2>&1 \
    || die "HeteroNetwork interface $interface does not exist"
  ip -o -4 address show dev "$interface" \
    | awk '{print $4}' \
    | cut -d/ -f1 \
    | grep -Fxq "$node_ip" \
    || die "$node_ip is not assigned to $interface"

  local mtu
  mtu="$(ip -o link show dev "$interface" | sed -nE 's/.* mtu ([0-9]+).*/\1/p')"
  [[ "$mtu" =~ ^[0-9]+$ && "$mtu" -ge "$MIN_IPV4_MTU" ]] \
    || die "$interface MTU is unavailable or below $MIN_IPV4_MTU"
}

render_haproxy_config() {
  cat <<EOF
global
    log stdout format raw local0
    maxconn 4096

defaults
    log global
    mode tcp
    option tcplog
    option dontlog-normal
    option redispatch
    retries 2
    timeout connect 5s
    timeout check 5s
    timeout client 1m
    timeout server 1m

frontend kubernetes_api
    bind 127.0.0.1:${api_proxy_port}
    default_backend kubernetes_control_planes

backend kubernetes_control_planes
    option httpchk GET /readyz
    http-check expect status 200
    default-server check check-ssl verify none inter 2s fastinter 1s downinter 2s fall 2 rise 2 on-marked-down shutdown-sessions
EOF
  local backend backup preferred_backend
  if [[ -n "$preferred_control_plane" ]]; then
    preferred_backend="$preferred_control_plane"
  elif node_is_control_plane_backend; then
    preferred_backend="$node_ip"
  else
    preferred_backend="$(backend_addresses | sed -n '1p')"
  fi
  local index=0
  while IFS= read -r backend; do
    index=$((index + 1))
    backup=""
    [[ "$backend" == "$preferred_backend" ]] || backup=" backup"
    printf '    server control-plane-%d %s:6443%s\n' "$index" "$backend" "$backup"
  done < <(backend_addresses)
}

render_haproxy_service() {
  cat <<'EOF'
[Unit]
Description=HeteroNetwork Kubernetes API load balancer
Wants=network-online.target heteronetwork-agent.service
After=network-online.target heteronetwork-agent.service

[Service]
Type=notify
RuntimeDirectory=heteronetwork-kube-apiserver-lb
ExecStart=/usr/sbin/haproxy -Ws -f /etc/heteronetwork/kubernetes/haproxy.cfg -p /run/heteronetwork-kube-apiserver-lb/haproxy.pid
ExecReload=/bin/kill -USR2 $MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
}

render_kubelet_dropin() {
  cat <<'EOF'
[Unit]
Wants=network-online.target heteronetwork-agent.service heteronetwork-overlay-dns.service heteronetwork-kube-apiserver-lb.service
After=network-online.target heteronetwork-agent.service heteronetwork-overlay-dns.service heteronetwork-kube-apiserver-lb.service
EOF
}

render_pod_cidr_routing_helper() {
  cat <<'EOF'
#!/bin/sh
set -eu

action="${1:-}"
pod_cidr="${2:-}"
priority="${3:-}"

[ -n "$pod_cidr" ] || {
  echo "missing Pod CIDR" >&2
  exit 2
}
case "$priority" in
  ''|*[!0-9]*)
    echo "invalid policy-routing priority" >&2
    exit 2
    ;;
esac

remove_rule() {
  while /usr/sbin/ip -4 rule delete \
    priority "$priority" to "$pod_cidr" lookup main 2>/dev/null; do
    :
  done
}

case "$action" in
  apply)
    remove_rule
    /usr/sbin/ip -4 rule add priority "$priority" to "$pod_cidr" lookup main
    /usr/sbin/ip -4 route flush cache
    ;;
  remove)
    remove_rule
    /usr/sbin/ip -4 route flush cache
    ;;
  *)
    echo "Usage: $0 apply|remove POD_CIDR PRIORITY" >&2
    exit 2
    ;;
esac
EOF
}

render_pod_cidr_routing_service() {
  cat <<EOF
[Unit]
Description=HeteroNetwork Kubernetes Pod CIDR policy routing
After=network-pre.target
Before=kubelet.service

[Service]
Type=oneshot
ExecStart=/opt/heteronetwork/libexec/kubernetes-pod-cidr-routing apply ${pod_cidr} ${POD_CIDR_POLICY_PRIORITY}
ExecStop=/opt/heteronetwork/libexec/kubernetes-pod-cidr-routing remove ${pod_cidr} ${POD_CIDR_POLICY_PRIORITY}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

render_overlay_dns_helper() {
  cat <<'EOF'
#!/bin/sh
set -eu

action="${1:-}"
: "${HETERONETWORK_OVERLAY_DNS_INTERFACE:?missing overlay DNS interface}"
: "${HETERONETWORK_OVERLAY_DNS_LOCAL_ADDRESS:?missing overlay DNS local address}"
: "${HETERONETWORK_OVERLAY_DNS_SERVERS:?missing overlay DNS servers}"
: "${HETERONETWORK_OVERLAY_DNS_ZONE:?missing overlay DNS zone}"

revert() {
  /usr/bin/resolvectl revert "$HETERONETWORK_OVERLAY_DNS_INTERFACE" >/dev/null 2>&1 || true
  /usr/bin/resolvectl flush-caches >/dev/null 2>&1 || true
}

case "$action" in
  apply)
    ready=0
    attempt=0
    while [ "$attempt" -lt 30 ]; do
      if /usr/sbin/ip -o -4 address show dev "$HETERONETWORK_OVERLAY_DNS_INTERFACE" \
        | /usr/bin/awk '{print $4}' \
        | /usr/bin/cut -d/ -f1 \
        | /usr/bin/grep -Fxq "$HETERONETWORK_OVERLAY_DNS_LOCAL_ADDRESS"; then
        ready=1
        break
      fi
      attempt=$((attempt + 1))
      sleep 1
    done
    if [ "$ready" -ne 1 ]; then
      echo "HeteroNetwork interface did not expose the configured DNS address" >&2
      exit 1
    fi

    trap revert EXIT HUP INT TERM
    dns_servers=$(printf '%s' "$HETERONETWORK_OVERLAY_DNS_SERVERS" | /usr/bin/tr ',' ' ')
    set -- $dns_servers
    [ "$#" -ge 3 ] || {
      echo "HeteroNetwork split DNS requires at least three servers" >&2
      exit 1
    }
    /usr/bin/resolvectl dns "$HETERONETWORK_OVERLAY_DNS_INTERFACE" "$@"
    /usr/bin/resolvectl domain \
      "$HETERONETWORK_OVERLAY_DNS_INTERFACE" \
      "~$HETERONETWORK_OVERLAY_DNS_ZONE"
    /usr/bin/resolvectl default-route "$HETERONETWORK_OVERLAY_DNS_INTERFACE" no
    /usr/bin/resolvectl flush-caches

    attempt=0
    while [ "$attempt" -lt 30 ]; do
      if /usr/bin/resolvectl query \
        "console.$HETERONETWORK_OVERLAY_DNS_ZONE" >/dev/null 2>&1; then
        trap - EXIT HUP INT TERM
        exit 0
      fi
      attempt=$((attempt + 1))
      sleep 1
    done
    echo "HeteroNetwork split-DNS health query failed" >&2
    exit 1
    ;;
  revert)
    revert
    ;;
  *)
    echo "Usage: $0 apply|revert" >&2
    exit 2
    ;;
esac
EOF
}

render_overlay_dns_service() {
  cat <<'EOF'
[Unit]
Description=HeteroNetwork private-zone split DNS
Requires=systemd-resolved.service
BindsTo=heteronetwork-agent.service
After=systemd-resolved.service heteronetwork-agent.service
PartOf=heteronetwork-agent.service
ConditionPathExists=/usr/bin/resolvectl

[Service]
Type=oneshot
EnvironmentFile=/etc/heteronetwork/kubernetes/overlay-dns.env
ExecStart=/opt/heteronetwork/libexec/overlay-dns-resolved apply
ExecStop=/opt/heteronetwork/libexec/overlay-dns-resolved revert
RemainAfterExit=yes
Restart=on-failure
RestartSec=5s
TimeoutStartSec=75s
TimeoutStopSec=10s

[Install]
WantedBy=multi-user.target heteronetwork-agent.service
EOF
}

render_containerd_apparmor_profile() {
  cat <<'EOF'
# Managed by HeteroNetwork for containerd versions older than 1.7.32.
abi <abi/3.0>,
#include <tunables/global>

profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network,
  capability,
  file,
  umount,

  # Host runtime processes and container processes may signal the container.
  signal (receive) peer=unconfined,
  signal (receive) peer=runc,
  signal (receive) peer=crun,
  signal (send,receive) peer=cri-containerd.apparmor.d,

  deny @{PROC}/* w,
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/devices/virtual/powercap/** rwklx,
  deny /sys/kernel/security/** rwklx,

  ptrace (trace,tracedby,read,readby) peer=cri-containerd.apparmor.d,
}
EOF
}

configure_containerd_apparmor() {
  [[ -d /sys/kernel/security/apparmor ]] || return
  command -v apparmor_parser >/dev/null 2>&1 || return
  [[ -f /etc/apparmor.d/abi/3.0 ]] || return
  require_command dpkg

  local containerd_version
  containerd_version="$(containerd --version | awk 'NR == 1 {print $3}')"
  containerd_version="${containerd_version#v}"
  [[ "$containerd_version" =~ ^[0-9]+(\.[0-9]+){1,2}([~+.-].*)?$ ]] \
    || die "unable to parse the installed containerd version"
  if dpkg --compare-versions "$containerd_version" ge 1.7.32; then
    return
  fi

  local profile=/etc/apparmor.d/cri-containerd.apparmor.d
  render_containerd_apparmor_profile | install_from_stdin "$profile" 0644
  apparmor_parser -Kr "$profile"
  grep -Fq 'cri-containerd.apparmor.d (enforce)' /sys/kernel/security/apparmor/profiles \
    || die "containerd AppArmor profile did not enter enforce mode"
}

render_init_config() {
  local kubernetes_version="$1"
  cat <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: "${node_ip}"
  bindPort: 6443
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  ignorePreflightErrors:
  - Swap
  name: "${node_name}"
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
clusterName: "heteronetwork"
controlPlaneEndpoint: "${api_name}:${api_proxy_port}"
kubernetesVersion: "${kubernetes_version}"
networking:
  dnsDomain: "cluster.local"
  podSubnet: "${pod_cidr}"
  serviceSubnet: "${service_cidr}"
apiServer:
  certSANs:
  - "${api_name}"
EOF
  local backend
  while IFS= read -r backend; do
    printf '  - "%s"\n' "$backend"
  done < <(backend_addresses)
  cat <<EOF
controllerManager:
  extraArgs:
  - name: "node-monitor-grace-period"
    value: "${NODE_MONITOR_GRACE_PERIOD}"
etcd:
  local:
    dataDir: "/var/lib/etcd"
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
failSwapOn: false
memorySwap:
  swapBehavior: NoSwap
resolvConf: "${KUBELET_RESOLV_CONF}"
EOF
}

read_join_discovery_bundle() {
  local bundle="$1"
  require_command jq
  [[ -f "$bundle" && ! -L "$bundle" ]] || die "join bundle is missing or is a symlink: $bundle"
  local mode
  mode="$(stat -c '%a' "$bundle")"
  [[ "$mode" == "600" || "$mode" == "400" ]] \
    || die "join bundle must have mode 0600 or 0400: $bundle has $mode"

  join_endpoint="$(jq -er '.apiServerEndpoint | strings | select(length > 0)' "$bundle")" \
    || die "join bundle has an invalid API server endpoint"
  join_token="$(jq -er '.token | strings | select(test("^[a-z0-9]{6}\\.[a-z0-9]{16}$"))' "$bundle")" \
    || die "join bundle has an invalid bootstrap token"
  join_ca_hash="$(jq -er '.caCertHash | strings | select(test("^sha256:[a-f0-9]{64}$"))' "$bundle")" \
    || die "join bundle has an invalid CA certificate hash"
  [[ "$join_endpoint" == "${api_name}:${api_proxy_port}" ]] \
    || die "join bundle endpoint does not match the configured local API endpoint"
}

read_join_bundle() {
  local bundle="$1"
  read_join_discovery_bundle "$bundle"
  join_certificate_key="$(jq -er '.certificateKey | strings | select(test("^[a-f0-9]{64}$"))' "$bundle")" \
    || die "join bundle has an invalid control-plane certificate key"
}

render_join_config() {
  local bundle="$1"
  read_join_bundle "$bundle"
  cat <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
controlPlane:
  certificateKey: "${join_certificate_key}"
  localAPIEndpoint:
    advertiseAddress: "${node_ip}"
    bindPort: 6443
discovery:
  bootstrapToken:
    apiServerEndpoint: "${join_endpoint}"
    caCertHashes:
    - "${join_ca_hash}"
    token: "${join_token}"
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  ignorePreflightErrors:
  - Swap
  name: "${node_name}"
EOF
}

render_worker_join_config() {
  local bundle="$1"
  read_join_discovery_bundle "$bundle"
  jq -e '(keys | sort) == ["apiServerEndpoint", "caCertHash", "token"]' "$bundle" >/dev/null \
    || die "worker join bundle must contain only discovery credentials"
  cat <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: "${join_endpoint}"
    caCertHashes:
    - "${join_ca_hash}"
    token: "${join_token}"
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  ignorePreflightErrors:
  - Swap
  kubeletExtraArgs:
  - name: "hostname-override"
    value: "${node_name}"
  - name: "node-ip"
    value: "${node_ip}"
  name: "${node_name}"
EOF
}

render_flannel_mtu_patch() {
  local underlay_mtu="$1"
  [[ "$underlay_mtu" =~ ^[0-9]+$ ]] \
    || die "invalid HeteroNetwork underlay MTU: $underlay_mtu"
  ((10#$underlay_mtu - FLANNEL_VXLAN_IPV4_OVERHEAD >= MIN_IPV4_MTU)) \
    || die "HeteroNetwork underlay MTU $underlay_mtu is too small for Flannel VXLAN"
  jq -n \
    --arg underlay_mtu "$underlay_mtu" \
    --arg interface "$interface" \
    --arg image "ghcr.io/flannel-io/flannel:${FLANNEL_VERSION}" \
    --argjson overhead "$FLANNEL_VXLAN_IPV4_OVERHEAD" \
    '{
    spec: {
      template: {
        metadata: {
          annotations: {
            "heteronetwork.io/underlay-mtu": $underlay_mtu
          }
        },
        spec: {
          initContainers: [
            {
              name: "heteronetwork-mtu",
              image: $image,
              imagePullPolicy: "IfNotPresent",
              command: ["/bin/sh", "-ec"],
              args: [
                "underlay_mtu=$(cat /sys/class/net/${HETERONETWORK_INTERFACE}/mtu)\nexpected_mtu=$((underlay_mtu - FLANNEL_OVERHEAD))\n[ \"$expected_mtu\" -ge 576 ]\nif ip link show dev flannel.1 >/dev/null 2>&1; then\n  ip link delete dev flannel.1\nfi\nif ip link show dev cni0 >/dev/null 2>&1; then\n  ip link set dev cni0 mtu \"$expected_mtu\"\n  ip -o link show master cni0 | while IFS=: read -r _ raw_name _; do\n    name=${raw_name# }\n    name=${name%%@*}\n    ip link set dev \"$name\" mtu \"$expected_mtu\"\n  done\nfi\n"
              ],
              env: [
                {name: "HETERONETWORK_INTERFACE", value: $interface},
                {name: "FLANNEL_OVERHEAD", value: ($overhead | tostring)}
              ],
              securityContext: {
                allowPrivilegeEscalation: false,
                capabilities: {drop: ["ALL"], add: ["NET_ADMIN"]},
                readOnlyRootFilesystem: true
              }
            }
          ]
        }
      }
    }
  }'
}

install_from_stdin() {
  local destination="$1"
  local mode="$2"
  local temporary
  temporary="$(mktemp)"
  cat >"$temporary"
  install -D -o root -g root -m "$mode" "$temporary" "$destination"
  rm -f "$temporary"
}

ensure_nss_resolve() {
  require_command apt-get
  require_command dpkg-query
  if dpkg-query -W -f='${db:Status-Abbrev}' libnss-resolve 2>/dev/null \
    | grep -Fq 'ii '; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y libnss-resolve
}

configure_nss_resolve() {
  local temporary
  temporary="$(mktemp)"
  if ! awk '
    /^[[:space:]]*hosts:[[:space:]]*/ {
      if ($0 ~ /(^|[[:space:]])resolve([[:space:]]|$)/) {
        print
        found = 1
        next
      }
      line = $0
      sub(/^[[:space:]]*hosts:[[:space:]]*/, "", line)
      if (line ~ /^files([[:space:]]|$)/) {
        sub(/^files[[:space:]]*/, "", line)
        print "hosts:          files resolve [!UNAVAIL=return] " line
      } else {
        print "hosts:          resolve [!UNAVAIL=return] " line
      }
      found = 1
      next
    }
    { print }
    END { if (!found) exit 42 }
  ' /etc/nsswitch.conf >"$temporary"; then
    rm -f "$temporary"
    die "failed to update the hosts database in /etc/nsswitch.conf"
  fi
  install -o root -g root -m 0644 "$temporary" /etc/nsswitch.conf
  rm -f "$temporary"
}

configure_overlay_dns() {
  require_root
  validate_overlay_dns_config
  verify_interface_address
  require_command resolvectl
  require_command systemctl
  ensure_nss_resolve
  configure_nss_resolve
  systemctl is-active --quiet heteronetwork-agent.service \
    || die "heteronetwork-agent.service must be active for HeteroNetwork split DNS"
  systemctl is-active --quiet systemd-resolved.service \
    || die "systemd-resolved.service must be active for HeteroNetwork split DNS"

  install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
  install -d -o root -g root -m 0700 "$state_dir"
  render_overlay_dns_helper \
    | install_from_stdin /opt/heteronetwork/libexec/overlay-dns-resolved 0755
  render_overlay_dns_service \
    | install_from_stdin /etc/systemd/system/heteronetwork-overlay-dns.service 0644
  local dns_servers
  dns_servers="$(backend_addresses | paste -sd, -)"
  cat <<EOF | install_from_stdin "$state_dir/overlay-dns.env" 0600
HETERONETWORK_OVERLAY_DNS_INTERFACE=${interface}
HETERONETWORK_OVERLAY_DNS_LOCAL_ADDRESS=${node_ip}
HETERONETWORK_OVERLAY_DNS_SERVERS=${dns_servers}
HETERONETWORK_OVERLAY_DNS_ZONE=${DEFAULT_OVERLAY_DNS_ZONE}
EOF

  systemctl daemon-reload
  systemctl enable heteronetwork-overlay-dns.service >/dev/null
  systemctl restart heteronetwork-overlay-dns.service
  systemctl is-active --quiet heteronetwork-overlay-dns.service \
    || die "HeteroNetwork split DNS did not become active"
  getent ahosts "console.${DEFAULT_OVERLAY_DNS_ZONE}" >/dev/null \
    || die "the host resolver did not use HeteroNetwork split DNS"
}

render_cloud_init_hosts_config() {
  cat <<'EOF'
# Managed by HeteroNetwork. The kubelet API endpoint is pinned to the local
# HAProxy in /etc/hosts and must survive cloud-init's per-boot reconciliation.
manage_etc_hosts: false
EOF
}

configure_hosts_entry() {
  local temporary
  if [[ -d /etc/cloud/cloud.cfg.d ]]; then
    render_cloud_init_hosts_config \
      | install_from_stdin /etc/cloud/cloud.cfg.d/99-heteronetwork-hosts.cfg 0644
  fi
  temporary="$(mktemp)"
  awk '$0 != "127.0.0.1 k8s-api.heteronetwork.internal # heteronetwork-kubeadm" && $0 !~ / # heteronetwork-kubeadm$/' /etc/hosts >"$temporary"
  printf '127.0.0.1 %s # heteronetwork-kubeadm\n' "$api_name" >>"$temporary"
  install -o root -g root -m 0644 "$temporary" /etc/hosts
  rm -f "$temporary"
}

configure_containerd() {
  install -d -o root -g root -m 0755 /etc/containerd
  local config=/etc/containerd/config.toml
  if [[ -s "$config" && ! -e "${config}.pre-heteronetwork" ]]; then
    install -o root -g root -m 0600 "$config" "${config}.pre-heteronetwork"
  fi

  local temporary pause_image kubernetes_version
  temporary="$(mktemp)"
  if [[ -s "$config" ]]; then
    if grep -Eq '^[[:space:]]*SystemdCgroup[[:space:]]*=' "$config"; then
      cp "$config" "$temporary"
    else
      local unknown_config
      unknown_config="$(
        sed -E \
          -e '/^[[:space:]]*(#|$)/d' \
          -e 's/^[[:space:]]+//' \
          -e 's/[[:space:]]+$//' \
          "$config" \
          | grep -Ev '^((disabled_plugins[[:space:]]*=[[:space:]]*\["cri"\])|(version[[:space:]]*=[[:space:]]*2)|(\[plugins\])|(\[plugins\."io\.containerd\.grpc\.v1\.cri"\])|(\[plugins\."io\.containerd\.grpc\.v1\.cri"\.cni\])|(bin_dir[[:space:]]*=[[:space:]]*"/usr/lib/cni")|(conf_dir[[:space:]]*=[[:space:]]*"/etc/cni/net\.d")|(\[plugins\."io\.containerd\.internal\.v1\.opt"\])|(path[[:space:]]*=[[:space:]]*"/var/lib/containerd/opt"))$' \
          || true
      )"
      [[ -z "$unknown_config" ]] \
        || die "existing containerd config has custom settings but no SystemdCgroup field; inspect ${config}.pre-heteronetwork"
      containerd config default >"$temporary"
    fi
  else
    containerd config default >"$temporary"
  fi
  sed -i -E 's/^(disabled_plugins[[:space:]]*=[[:space:]]*)\["cri"\]/\1[]/' "$temporary"
  sed -i -E 's/^([[:space:]]*SystemdCgroup[[:space:]]*=[[:space:]]*)false/\1true/' "$temporary"
  sed -i 's#/usr/lib/cni#/opt/cni/bin#g' "$temporary"
  kubernetes_version="$(kubeadm version -o short)"
  pause_image="$(kubeadm config images list --kubernetes-version "$kubernetes_version" \
    | sed -nE '\#/pause:[^[:space:]]+$# {p;q}')"
  [[ -n "$pause_image" ]] || die "failed to determine the kubeadm pause image"
  sed -i -E \
    -e "s#^([[:space:]]*sandbox_image[[:space:]]*=[[:space:]]*)['\"][^'\"]+['\"]#\1\"${pause_image}\"#" \
    -e "s#^([[:space:]]*sandbox[[:space:]]*=[[:space:]]*)['\"][^'\"]+['\"]#\1\"${pause_image}\"#" \
    "$temporary"
  grep -Eq '^[[:space:]]*SystemdCgroup[[:space:]]*=[[:space:]]*true' "$temporary" \
    || die "containerd config does not expose a SystemdCgroup setting that can be enabled safely"
  grep -Eq "^[[:space:]]*bin_dirs?[[:space:]]*=.*['\"]?/opt/cni/bin['\"]?" "$temporary" \
    || die "containerd CNI plugin path is not /opt/cni/bin"
  grep -Fq "$pause_image" "$temporary" \
    || die "containerd sandbox image does not match kubeadm"
  if grep -Eq '^disabled_plugins[[:space:]]*=.*"cri"' "$temporary"; then
    die "containerd CRI remains disabled after configuration"
  fi
  install -d -o root -g root -m 0755 /opt/cni/bin
  install -o root -g root -m 0644 "$temporary" "$config"
  rm -f "$temporary"
  configure_containerd_apparmor
  systemctl enable --now containerd
  systemctl restart containerd
  systemctl is-active --quiet containerd || die "containerd did not become active"
}

configure_kernel() {
  modprobe overlay
  modprobe br_netfilter
  cat <<'EOF' | install_from_stdin /etc/modules-load.d/heteronetwork-kubernetes.conf 0644
overlay
br_netfilter
EOF
  cat <<'EOF' | install_from_stdin /etc/sysctl.d/99-heteronetwork-kubernetes.conf 0644
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
  sysctl --system >/dev/null
}

verify_pod_cidr_policy_rule() {
  ip -4 rule show | awk -v priority="${POD_CIDR_POLICY_PRIORITY}:" -v pod_cidr="$pod_cidr" '
    $1 == priority {
      for (field = 1; field < NF; field++) {
        if ($field == "to" && $(field + 1) == pod_cidr && $(NF - 1) == "lookup" && $NF == "main") {
          found = 1
        }
      }
    }
    END { exit(found ? 0 : 1) }
  ' || die "Pod CIDR $pod_cidr is not pinned to the main routing table at priority $POD_CIDR_POLICY_PRIORITY"
}

configure_pod_cidr_routing() {
  require_root
  require_command ip
  require_command systemctl
  install -d -o root -g root -m 0755 /opt/heteronetwork/libexec
  render_pod_cidr_routing_helper \
    | install_from_stdin /opt/heteronetwork/libexec/kubernetes-pod-cidr-routing 0755
  render_pod_cidr_routing_service \
    | install_from_stdin /etc/systemd/system/heteronetwork-kubernetes-pod-routing.service 0644
  systemctl daemon-reload
  systemctl enable heteronetwork-kubernetes-pod-routing.service >/dev/null
  systemctl restart heteronetwork-kubernetes-pod-routing.service
  systemctl is-active --quiet heteronetwork-kubernetes-pod-routing.service \
    || die "Kubernetes Pod CIDR policy routing did not become active"
  verify_pod_cidr_policy_rule
}

reconcile_pod_cidr_routing() {
  require_root
  validate_common_config
  configure_pod_cidr_routing
  printf 'Pod CIDR policy routing reconciled for %s via main table priority %s\n' \
    "$pod_cidr" "$POD_CIDR_POLICY_PRIORITY"
}

configure_haproxy() {
  render_haproxy_config | install_from_stdin "$state_dir/haproxy.cfg" 0644
  /usr/sbin/haproxy -c -f "$state_dir/haproxy.cfg" >/dev/null
  render_haproxy_service | install_from_stdin /etc/systemd/system/heteronetwork-kube-apiserver-lb.service 0644
  systemctl daemon-reload
  systemctl enable --now heteronetwork-kube-apiserver-lb.service
  systemctl is-active --quiet heteronetwork-kube-apiserver-lb.service \
    || die "local Kubernetes API load balancer did not become active"
}

configure_kubelet_api_ha() {
  require_root
  validate_common_config
  configure_haproxy
  reconcile_kubelet_api_endpoint
  systemctl restart heteronetwork-kube-apiserver-lb.service kubelet.service
  systemctl is-active --quiet heteronetwork-kube-apiserver-lb.service \
    || die "local Kubernetes API load balancer did not remain active"
  systemctl is-active --quiet kubelet.service || die "kubelet did not remain active"
}

reconcile_kubelet_resolver() {
  local source_path="${HETERONETWORK_KUBELET_RESOLVER_SOURCE:-/run/systemd/resolve/resolv.conf}"
  local temporary
  [[ -r "$source_path" ]] || die "resolver source is missing: $source_path"
  temporary="$(mktemp)"
  if ! awk '
    $1 == "nameserver" && $2 != "" && $2 != "127.0.0.53" && $2 != "::1" && !seen[$2]++ && count < 3 {
      print "nameserver " $2
      count++
    }
    END { if (count == 0) exit 1 }
  ' "$source_path" >"$temporary"; then
    rm -f "$temporary"
    die "no usable nameserver found in $source_path"
  fi
  install -D -o root -g root -m 0644 "$temporary" "$KUBELET_RESOLV_CONF"
  rm -f "$temporary"
}

reconcile_kubelet_api_endpoint() {
  local endpoint="https://${api_name}:${api_proxy_port}"
  local kubeconfig temporary
  local found=0
  for kubeconfig in /etc/kubernetes/kubelet.conf /etc/kubernetes/bootstrap-kubelet.conf; do
    [[ -f "$kubeconfig" ]] || continue
    found=1
    temporary="$(mktemp)"
    sed -E "s#^([[:space:]]*server:[[:space:]]*)https://[^[:space:]]+#\\1${endpoint}#" \
      "$kubeconfig" >"$temporary"
    [[ "$(grep -Ec "^[[:space:]]*server:[[:space:]]*${endpoint}$" "$temporary")" == "1" ]] \
      || { rm -f "$temporary"; die "failed to set the kubelet API endpoint to $endpoint in $kubeconfig"; }
    install -o root -g root -m 0600 "$temporary" "$kubeconfig"
    rm -f "$temporary"
  done
  ((found == 1)) || die "kubelet kubeconfig is missing"
}

configure_kubelet() {
  reconcile_kubelet_resolver
  printf 'KUBELET_EXTRA_ARGS="--node-ip=%s --hostname-override=%s --max-pods=%s"\n' "$node_ip" "$node_name" "$max_pods" \
    | install_from_stdin /etc/default/kubelet 0644
  install -d -o root -g root -m 0755 /etc/systemd/system/kubelet.service.d
  render_kubelet_dropin \
    | install_from_stdin /etc/systemd/system/kubelet.service.d/20-heteronetwork-underlay.conf 0644
  systemctl daemon-reload
  systemctl enable kubelet
}

configure_local_state() {
  cat <<EOF | install_from_stdin "$state_dir/node.env" 0600
HETERONETWORK_KUBEADM_INTERFACE=${interface}
HETERONETWORK_KUBEADM_NODE_IP=${node_ip}
HETERONETWORK_KUBEADM_NODE_NAME=${node_name}
HETERONETWORK_KUBEADM_CONTROL_PLANES=${control_plane_backends}
HETERONETWORK_KUBEADM_PREFERRED_CONTROL_PLANE=${preferred_control_plane}
HETERONETWORK_KUBEADM_APISERVER_ETCD_ENDPOINTS=${apiserver_etcd_backends}
HETERONETWORK_KUBEADM_API_NAME=${api_name}
HETERONETWORK_KUBEADM_API_PROXY_PORT=${api_proxy_port}
HETERONETWORK_KUBEADM_POD_CIDR=${pod_cidr}
HETERONETWORK_KUBEADM_SERVICE_CIDR=${service_cidr}
HETERONETWORK_KUBEADM_KUBERNETES_MINOR=${kubernetes_minor}
HETERONETWORK_KUBEADM_MAX_PODS=${max_pods}
EOF
}

ensure_agent_api_token() {
  require_command openssl
  install -d -o root -g root -m 0700 "$(dirname -- "$agent_api_token_path")"
  if [[ -e "$agent_api_token_path" || -L "$agent_api_token_path" ]]; then
    [[ -f "$agent_api_token_path" && ! -L "$agent_api_token_path" ]] \
      || die "Agent API token path is not a regular file: $agent_api_token_path"
    [[ "$(<"$agent_api_token_path")" =~ ^[a-f0-9]{64}$ ]] \
      || die "Agent API token must contain exactly 64 lowercase hexadecimal characters"
    chown root:root "$agent_api_token_path"
    chmod 0400 "$agent_api_token_path"
    return
  fi

  local token
  token="$(openssl rand -hex 32)"
  printf '%s' "$token" | install_from_stdin "$agent_api_token_path" 0400
  unset token
}

install_public_services_bootstrap_autopilot() {
  local helper="${SCRIPT_DIR}/public-services-bootstrap.sh"
  local service="${SCRIPT_DIR}/../deploy/systemd/heteronetwork-public-services-bootstrap.service"
  local timer="${SCRIPT_DIR}/../deploy/systemd/heteronetwork-public-services-bootstrap.timer"
  [[ -f "$helper" && -f "$service" && -f "$timer" ]] \
    || die "automatic public-services bootstrap files are missing from the checkout"
  install -D -o root -g root -m 0755 "$helper" \
    /opt/heteronetwork/libexec/public-services-bootstrap.sh
  install -D -o root -g root -m 0644 "$service" \
    /etc/systemd/system/heteronetwork-public-services-bootstrap.service
  install -D -o root -g root -m 0644 "$timer" \
    /etc/systemd/system/heteronetwork-public-services-bootstrap.timer
  systemctl daemon-reload
  systemctl enable heteronetwork-public-services-bootstrap.timer >/dev/null
}

kubernetes_versions_are_aligned() {
  local expected_minor="$1"
  local kubeadm_version="$2"
  local kubelet_version="$3"
  local kubectl_version="$4"
  [[ "$kubeadm_version" == "${expected_minor}."* ]] \
    && [[ "$kubelet_version" == "$kubeadm_version" ]] \
    && [[ "$kubectl_version" == "$kubeadm_version" ]]
}

installed_kubernetes_toolchain_version() {
  command -v kubeadm >/dev/null 2>&1 || return 1
  command -v kubelet >/dev/null 2>&1 || return 1
  command -v kubectl >/dev/null 2>&1 || return 1

  local kubeadm_version kubelet_version kubectl_version
  kubeadm_version="$(kubeadm version -o short 2>/dev/null)"
  kubelet_version="$(kubelet --version 2>/dev/null | sed -nE 's/^Kubernetes (v[0-9]+\.[0-9]+\.[0-9]+).*$/\1/p')"
  kubectl_version="$(kubectl version --client -o json 2>/dev/null | jq -er '.clientVersion.gitVersion')"
  kubernetes_versions_are_aligned \
    "$kubernetes_minor" "$kubeadm_version" "$kubelet_version" "$kubectl_version" \
    || return 1
  printf '%s\n' "$kubeadm_version"
}

install_kubernetes_packages() {
  require_command apt-get
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y apt-transport-https ca-certificates conntrack curl ethtool gpg haproxy iputils-ping jq libnss-resolve openssl socat
  if ! command -v containerd >/dev/null 2>&1; then
    apt-get install -y containerd
  fi

  install -d -o root -g root -m 0755 /etc/apt/keyrings
  local key keyring
  key="$(mktemp)"
  keyring="$(mktemp)"
  curl -fsSL --retry 3 --connect-timeout 10 \
    "https://pkgs.k8s.io/core:/stable:/${kubernetes_minor}/deb/Release.key" -o "$key"
  gpg --batch --yes --dearmor --output "$keyring" "$key"
  install -o root -g root -m 0644 "$keyring" /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  rm -f "$key" "$keyring"
  printf 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/%s/deb/ /\n' "$kubernetes_minor" \
    | install_from_stdin /etc/apt/sources.list.d/kubernetes.list 0644
  apt-get update
  local installed_version
  if installed_version="$(installed_kubernetes_toolchain_version)"; then
    printf 'preserving aligned Kubernetes toolchain %s\n' "$installed_version"
  else
    apt-get install -y --allow-change-held-packages kubelet kubeadm kubectl
  fi
  apt-mark hold kubelet kubeadm kubectl >/dev/null
}

prepare_host() {
  require_root
  validate_common_config
  verify_interface_address
  require_command systemctl
  install -d -o root -g root -m 0700 "$state_dir"
  install_kubernetes_packages
  configure_kernel
  configure_pod_cidr_routing
  configure_containerd
  configure_hosts_entry
  configure_overlay_dns
  configure_haproxy
  configure_kubelet
  configure_local_state
  ensure_agent_api_token
  install_public_services_bootstrap_autopilot
  verify_host
}

reconcile_control_plane_backends() {
  require_root
  validate_common_config
  verify_interface_address
  require_command systemctl
  configure_hosts_entry
  configure_overlay_dns
  configure_haproxy
  configure_pod_cidr_routing
  configure_local_state
  if [[ -n "$apiserver_etcd_backends" && -f /etc/kubernetes/manifests/kube-apiserver.yaml ]]; then
    reconcile_apiserver_etcd
  fi
  verify_host
  printf 'control-plane backends reconciled for %s\n' "$node_name"
}

reconcile_apiserver_etcd() {
  require_root
  validate_control_plane_config
  require_command awk
  require_command curl
  local manifest=/etc/kubernetes/manifests/kube-apiserver.yaml
  [[ -f "$manifest" && ! -L "$manifest" ]] \
    || die "kube-apiserver static Pod manifest is missing or is a symlink"

  local endpoints current desired temporary mode
  endpoints="$(render_apiserver_etcd_servers)"
  desired="    - --etcd-servers=${endpoints}"
  current="$(grep -E '^    - --etcd-servers=' "$manifest" || true)"
  [[ "$(grep -Ec '^    - --etcd-servers=' "$manifest")" == "1" ]] \
    || die "kube-apiserver manifest must contain exactly one etcd-servers argument"
  configure_local_state
  if [[ "$current" != "$desired" ]]; then
    temporary="$(mktemp)"
    if ! awk -v replacement="$desired" '
      /^    - --etcd-servers=/ { print replacement; next }
      { print }
    ' "$manifest" >"$temporary"; then
      rm -f "$temporary"
      die "failed to render the kube-apiserver manifest"
    fi
    mode="$(stat -c '%a' "$manifest")"
    install -o root -g root -m "$mode" "$temporary" "$manifest"
    rm -f "$temporary"
  fi

  local attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if curl --fail --silent --show-error \
      --connect-timeout 2 --max-time 5 \
      --cacert /etc/kubernetes/pki/ca.crt \
      "https://${node_ip}:6443/readyz" >/dev/null 2>&1; then
      printf 'API server etcd endpoints reconciled on %s\n' "$node_name"
      return
    fi
    sleep 2
  done
  die "local API server did not become ready after reconciling etcd endpoints"
}

installed_kubernetes_version() {
  kubeadm version -o short | sed -nE 's/^(v[0-9]+\.[0-9]+\.[0-9]+).*$/\1/p'
}

configure_root_kubeconfig() {
  install -d -o root -g root -m 0700 /root/.kube
  install -o root -g root -m 0600 /etc/kubernetes/admin.conf /root/.kube/config
}

join_bundle_path() {
  printf '%s\n' "${HETERONETWORK_KUBEADM_JOIN_BUNDLE:-$state_dir/join-bundle.json}"
}

worker_join_bundle_path() {
  printf '%s\n' "${HETERONETWORK_KUBEADM_WORKER_JOIN_BUNDLE:-$state_dir/worker-join-bundle.json}"
}

cluster_ca_cert_hash() {
  openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex \
    | awk '{print "sha256:" $2}'
}

render_worker_join_bundle() {
  local endpoint="$1"
  local token="$2"
  local ca_hash="$3"
  jq -n \
    --arg apiServerEndpoint "$endpoint" \
    --arg token "$token" \
    --arg caCertHash "$ca_hash" \
    '{apiServerEndpoint: $apiServerEndpoint, token: $token, caCertHash: $caCertHash}'
}

refresh_join_bundle() {
  require_root
  validate_control_plane_config
  require_command jq
  require_command kubeadm
  require_command openssl
  [[ -f /etc/kubernetes/admin.conf ]] || die "this node is not an initialized control plane"

  local token certificate_key ca_hash endpoint bundle temporary config version upload_output
  token="$(kubeadm token create --ttl 2h)"
  version="$(installed_kubernetes_version)"
  [[ -n "$version" ]] || die "failed to determine the installed Kubernetes version"
  config="$(mktemp)"
  render_init_config "$version" >"$config"
  chmod 0600 "$config"
  if ! upload_output="$(kubeadm init phase upload-certs \
    --upload-certs \
    --config "$config" \
    --kubeconfig /etc/kubernetes/admin.conf)"; then
    rm -f "$config"
    die "failed to upload control-plane certificates"
  fi
  rm -f "$config"
  certificate_key="$(tail -n 1 <<<"$upload_output" | tr -d '[:space:]')"
  ca_hash="$(cluster_ca_cert_hash)"
  endpoint="${api_name}:${api_proxy_port}"
  [[ "$token" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "kubeadm returned an invalid bootstrap token"
  [[ "$certificate_key" =~ ^[a-f0-9]{64}$ ]] || die "kubeadm returned an invalid certificate key"
  [[ "$ca_hash" =~ ^sha256:[a-f0-9]{64}$ ]] || die "failed to compute the cluster CA public-key hash"

  bundle="$(join_bundle_path)"
  temporary="$(mktemp)"
  jq -n \
    --arg apiServerEndpoint "$endpoint" \
    --arg token "$token" \
    --arg caCertHash "$ca_hash" \
    --arg certificateKey "$certificate_key" \
    '{apiServerEndpoint: $apiServerEndpoint, token: $token, caCertHash: $caCertHash, certificateKey: $certificateKey}' \
    >"$temporary"
  install -D -o root -g root -m 0600 "$temporary" "$bundle"
  rm -f "$temporary"
  printf 'join bundle refreshed at %s (credentials not printed)\n' "$bundle"
}

refresh_worker_join_bundle() {
  require_root
  validate_control_plane_config
  require_command jq
  require_command kubeadm
  require_command openssl
  [[ -f /etc/kubernetes/admin.conf ]] || die "this node is not an initialized control plane"

  local token ca_hash endpoint bundle temporary
  token="$(kubeadm token create --ttl 2h)"
  ca_hash="$(cluster_ca_cert_hash)"
  endpoint="${api_name}:${api_proxy_port}"
  [[ "$token" =~ ^[a-z0-9]{6}\.[a-z0-9]{16}$ ]] || die "kubeadm returned an invalid bootstrap token"
  [[ "$ca_hash" =~ ^sha256:[a-f0-9]{64}$ ]] || die "failed to compute the cluster CA public-key hash"

  bundle="$(worker_join_bundle_path)"
  temporary="$(mktemp)"
  trap 'rm -f "$temporary"' EXIT
  render_worker_join_bundle "$endpoint" "$token" "$ca_hash" >"$temporary"
  install -D -o root -g root -m 0600 "$temporary" "$bundle"
  rm -f "$temporary"
  trap - EXIT
  printf 'worker join bundle refreshed at %s (credentials not printed)\n' "$bundle"
}

initialize_cluster() {
  require_root
  validate_control_plane_config
  verify_interface_address
  require_command kubeadm
  [[ -f "$state_dir/node.env" ]] || die "run prepare before init"
  if [[ -f /etc/kubernetes/admin.conf ]]; then
    reconcile_kubelet_api_endpoint
    configure_root_kubeconfig
    refresh_join_bundle
    printf 'control plane is already initialized\n'
    return
  fi

  local version config
  version="$(installed_kubernetes_version)"
  [[ -n "$version" ]] || die "failed to determine the installed Kubernetes version"
  [[ "$version" == "${kubernetes_minor}."* ]] \
    || die "installed Kubernetes version $version does not match $kubernetes_minor"
  config="$(mktemp)"
  render_init_config "$version" >"$config"
  chmod 0600 "$config"
  kubeadm config validate --config "$config"
  kubeadm init --config "$config"
  rm -f "$config"
  reconcile_kubelet_api_endpoint
  configure_root_kubeconfig
  refresh_join_bundle
}

join_control_plane() {
  require_root
  validate_control_plane_config
  verify_interface_address
  require_command kubeadm
  ensure_agent_api_token
  [[ -f "$state_dir/node.env" ]] || die "run prepare before join-control-plane"
  if [[ -f /etc/kubernetes/admin.conf ]]; then
    reconcile_kubelet_api_endpoint
    configure_root_kubeconfig
    printf 'control plane is already joined\n'
    return
  fi

  local bundle config
  bundle="$(join_bundle_path)"
  config="$(mktemp)"
  chmod 0600 "$config"
  render_join_config "$bundle" >"$config"
  kubeadm config validate --config "$config"
  kubeadm join --config "$config"
  rm -f "$config"
  reconcile_kubelet_api_endpoint
  configure_root_kubeconfig
}

filter_preserved_node_labels() {
  jq -ce '
    .metadata.labels // {}
    | with_entries(select(
        .key
        | test("^(kubernetes\\.io/|beta\\.kubernetes\\.io/|node\\.kubernetes\\.io/|node-role\\.kubernetes\\.io/)")
        | not
      ))
  '
}

snapshot_promoted_node_labels() {
  local destination="$1"
  local labels
  labels="$(
    kubectl \
      --kubeconfig /etc/kubernetes/kubelet.conf \
      --request-timeout=30s \
      get node "$node_name" -o json \
      | filter_preserved_node_labels
  )" || die "failed to preserve labels from worker $node_name"
  printf '%s\n' "$labels" | install_from_stdin "$destination" 0600
}

restore_promoted_node_labels() {
  local source="$1"
  local patch
  if [[ -e "$source" ]]; then
    [[ -f "$source" && ! -L "$source" ]] \
      || die "preserved worker labels are not a regular file"
    patch="$(jq -cn --slurpfile labels "$source" '{metadata: {labels: $labels[0]}}')"
    kubectl --kubeconfig /etc/kubernetes/admin.conf \
      patch node "$node_name" --type=merge --patch "$patch" >/dev/null
  fi
  kubectl --kubeconfig /etc/kubernetes/admin.conf \
    label node "$node_name" node.kubernetes.io/exclude-from-external-load-balancers- \
    >/dev/null 2>&1 || true
  kubectl --kubeconfig /etc/kubernetes/admin.conf \
    taint node "$node_name" node-role.kubernetes.io/control-plane- \
    >/dev/null 2>&1 || true
}

promote_control_plane() {
  require_root
  validate_control_plane_config
  verify_interface_address
  require_command kubeadm
  ensure_agent_api_token
  [[ -f "$state_dir/node.env" ]] || die "run prepare before promote-control-plane"
  local marker="$state_dir/control-plane-promotion.in-progress"
  local preserved_labels="$state_dir/control-plane-promotion-labels.json"
  if [[ -f /etc/kubernetes/admin.conf && ! -e "$marker" ]]; then
    configure_root_kubeconfig
    printf 'control plane is already joined\n'
    return
  fi
  [[ "${HETERONETWORK_KUBEADM_PROMOTE_EXISTING_WORKER:-}" == "1" ]] \
    || die "set HETERONETWORK_KUBEADM_PROMOTE_EXISTING_WORKER=1 after draining this worker"

  if [[ ! -e "$marker" ]]; then
    [[ -f /etc/kubernetes/kubelet.conf ]] \
      || die "this host is not an existing Kubernetes worker"
    require_command kubectl
    require_command jq
    snapshot_promoted_node_labels "$preserved_labels"
    printf 'promotion requested for %s\n' "$node_name" \
      | install_from_stdin "$marker" 0600
  else
    [[ -f "$marker" && ! -L "$marker" ]] \
      || die "control-plane promotion marker is not a regular file"
  fi

  systemctl stop kubelet
  kubeadm reset --force --cri-socket unix:///run/containerd/containerd.sock
  join_control_plane
  restore_promoted_node_labels "$preserved_labels"
  rm -f "$marker"
  rm -f "$preserved_labels"
  printf 'worker %s promoted to a stacked-etcd control plane\n' "$node_name"
}

join_worker() {
  require_root
  validate_worker_config
  validate_worker_enrollment
  verify_interface_address
  require_command kubeadm
  ensure_agent_api_token
  [[ -f "$state_dir/node.env" ]] || die "run prepare before join-worker"
  if [[ -f /etc/kubernetes/admin.conf || -f /etc/kubernetes/manifests/kube-apiserver.yaml ]]; then
    die "this node is already configured as a control plane; refusing worker join"
  fi
  if [[ -f /etc/kubernetes/kubelet.conf ]]; then
    reconcile_kubelet_api_endpoint
    printf 'worker is already joined\n'
    return
  fi

  local bundle config
  bundle="$(worker_join_bundle_path)"
  config="$(mktemp)"
  chmod 0600 "$config"
  trap 'rm -f "$config"' EXIT
  render_worker_join_config "$bundle" >"$config"
  kubeadm config validate --config "$config"
  kubeadm join --config "$config"
  reconcile_kubelet_api_endpoint
  rm -f "$bundle"
  rm -f "$config"
  trap - EXIT
}

install_flannel() {
  require_root
  validate_control_plane_config
  verify_interface_address
  require_command curl
  require_command jq
  require_command kubectl
  require_command sha256sum
  [[ -f /etc/kubernetes/admin.conf ]] || die "this node is not an initialized control plane"
  export KUBECONFIG=/etc/kubernetes/admin.conf

  local manifest patched actual_hash underlay_mtu
  manifest="$(mktemp)"
  patched="$(mktemp)"
  curl -fL --retry 3 --connect-timeout 10 "$FLANNEL_MANIFEST_URL" -o "$manifest"
  actual_hash="$(sha256sum "$manifest" | awk '{print $1}')"
  [[ "$actual_hash" == "$FLANNEL_MANIFEST_SHA256" ]] \
    || die "Flannel manifest checksum mismatch: got $actual_hash"
  awk -v iface="$interface" '
    { print }
    $0 == "        - --kube-subnet-mgr" { print "        - --iface=" iface }
  ' "$manifest" >"$patched"
  [[ "$(grep -Fc -- "--iface=${interface}" "$patched")" == "1" ]] \
    || die "failed to pin Flannel to $interface"
  kubectl apply -f "$patched"
  underlay_mtu="$(ip -o link show dev "$interface" | sed -nE 's/.* mtu ([0-9]+).*/\1/p')"
  kubectl -n kube-flannel patch daemonset/kube-flannel-ds \
    --type=strategic \
    --patch "$(render_flannel_mtu_patch "$underlay_mtu")" >/dev/null
  rm -f "$manifest" "$patched"
  kubectl -n kube-flannel rollout status daemonset/kube-flannel-ds --timeout=5m
}

configure_coredns_ha() {
  local replicas
  replicas="$(backend_addresses | wc -l | tr -d ' ')"
  kubectl -n kube-system patch deployment coredns --type=merge --patch "$(cat <<EOF
{
  "spec": {
    "replicas": ${replicas},
    "template": {
      "spec": {
        "affinity": {
          "podAntiAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": [
              {
                "labelSelector": {
                  "matchExpressions": [
                    {
                      "key": "k8s-app",
                      "operator": "In",
                      "values": ["kube-dns"]
                    }
                  ]
                },
                "topologyKey": "kubernetes.io/hostname"
              }
            ]
          }
        }
      }
    }
  }
}
EOF
)" >/dev/null
  kubectl -n kube-system rollout status deployment/coredns --timeout=5m
}

finalize_cluster() {
  require_root
  validate_control_plane_config
  require_command kubectl
  export KUBECONFIG=/etc/kubernetes/admin.conf
  kubectl taint nodes --all node-role.kubernetes.io/control-plane- 2>/dev/null || true
  kubectl wait --for=condition=Ready nodes --all --timeout=10m
  configure_coredns_ha
}

verify_host() {
  validate_common_config
  verify_interface_address
  if [[ "$(id -u)" == "0" && -f "$state_dir/haproxy.cfg" ]]; then
    require_command haproxy
    haproxy -c -f "$state_dir/haproxy.cfg" >/dev/null
    systemctl is-active --quiet heteronetwork-kube-apiserver-lb.service \
      || die "local Kubernetes API load balancer is inactive"
    systemctl is-active --quiet containerd || die "containerd is inactive"
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] || die "IPv4 forwarding is disabled"
    [[ "$(sysctl -n net.bridge.bridge-nf-call-iptables)" == "1" ]] \
      || die "bridge netfilter is disabled"
    systemctl is-active --quiet heteronetwork-kubernetes-pod-routing.service \
      || die "Kubernetes Pod CIDR policy routing is inactive"
    verify_pod_cidr_policy_rule
  fi
  printf 'host prerequisites verified for %s (%s on %s)\n' "$node_name" "$node_ip" "$interface"
}

validate_cluster_counts() {
  local expected_control_planes="$1"
  local actual_nodes="$2"
  local ready_nodes="$3"
  local control_plane_nodes="$4"
  local control_planes="$5"
  local controller_managers="$6"
  local flannel_pods="$7"
  local coredns_pods="$8"
  local coredns_nodes="$9"

  ((actual_nodes >= expected_control_planes)) \
    || die "expected at least $expected_control_planes nodes, found $actual_nodes"
  [[ "$ready_nodes" == "$actual_nodes" ]] || die "expected all $actual_nodes nodes Ready, found $ready_nodes"
  [[ "$control_plane_nodes" == "$expected_control_planes" ]] \
    || die "expected $expected_control_planes control-plane nodes, found $control_plane_nodes"
  [[ "$control_planes" == "$expected_control_planes" ]] \
    || die "expected $expected_control_planes API servers, found $control_planes"
  [[ "$controller_managers" == "$expected_control_planes" ]] \
    || die "expected $expected_control_planes controller managers with ${NODE_MONITOR_GRACE_PERIOD} node monitoring, found $controller_managers"
  [[ "$flannel_pods" == "$actual_nodes" ]] || die "expected $actual_nodes Flannel pods, found $flannel_pods"
  [[ "$coredns_pods" == "$expected_control_planes" ]] \
    || die "expected $expected_control_planes Ready CoreDNS pods, found $coredns_pods"
  [[ "$coredns_nodes" == "$expected_control_planes" ]] \
    || die "CoreDNS pods are not spread across $expected_control_planes distinct nodes"
}

verify_cluster() {
  require_root
  validate_control_plane_config
  require_command kubectl
  require_command jq
  require_command ping
  export KUBECONFIG=/etc/kubernetes/admin.conf

  local nodes_json expected_control_planes actual_nodes ready_nodes control_plane_nodes
  local control_planes controller_managers flannel_pods coredns_pods coredns_nodes
  local backend expected_mtu underlay_mtu underlay_ping_payload attempt reachable
  nodes_json="$(kubectl get nodes -o json)"
  expected_control_planes="$(backend_addresses | wc -l | tr -d ' ')"
  actual_nodes="$(jq '.items | length' <<<"$nodes_json")"
  ready_nodes="$(jq '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length' <<<"$nodes_json")"
  control_plane_nodes="$(jq '[.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] != null)] | length' <<<"$nodes_json")"
  control_planes="$(kubectl -n kube-system get pods -l component=kube-apiserver -o json | jq '[.items[] | select(.status.phase == "Running")] | length')"
  controller_managers="$(kubectl -n kube-system get pods -l component=kube-controller-manager -o json | jq --arg expected "--node-monitor-grace-period=${NODE_MONITOR_GRACE_PERIOD}" '[.items[] | select(any(.spec.containers[]?.command[]?; . == $expected))] | length')"
  flannel_pods="$(kubectl -n kube-flannel get pods -l app=flannel -o json | jq '[.items[] | select(.status.phase == "Running")] | length')"
  coredns_pods="$(kubectl -n kube-system get pods -l k8s-app=kube-dns -o json | jq '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length')"
  coredns_nodes="$(kubectl -n kube-system get pods -l k8s-app=kube-dns -o json | jq '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .spec.nodeName] | unique | length')"
  validate_cluster_counts \
    "$expected_control_planes" \
    "$actual_nodes" \
    "$ready_nodes" \
    "$control_plane_nodes" \
    "$control_planes" \
    "$controller_managers" \
    "$flannel_pods" \
    "$coredns_pods" \
    "$coredns_nodes"

  underlay_mtu="$(ip -o link show dev "$interface" | sed -nE 's/.* mtu ([0-9]+).*/\1/p')"
  expected_mtu=$((underlay_mtu - FLANNEL_VXLAN_IPV4_OVERHEAD))
  underlay_ping_payload=$((underlay_mtu - 28))
  while IFS= read -r backend; do
    [[ "$backend" == "$node_ip" ]] && continue
    reachable=0
    for attempt in $(seq 1 15); do
      if ping -c 3 -W 3 -M probe -s "$underlay_ping_payload" "$backend" >/dev/null; then
        reachable=1
        break
      fi
      sleep 2
    done
    ((reachable == 1)) \
      || die "$interface cannot carry its declared MTU $underlay_mtu to control plane $backend"
  done < <(backend_addresses)

  local namespace="heteronetwork-underlay-e2e"
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  cat <<'EOF' | kubectl -n "$namespace" apply -f - >/dev/null
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: network-probe
spec:
  selector:
    matchLabels:
      app: network-probe
  template:
    metadata:
      labels:
        app: network-probe
    spec:
      containers:
      - command:
        - sh
        - -ec
        - |
          rm -f /tmp/heteronetwork-runtime.log
          syslogd -L -O /tmp/heteronetwork-runtime.log
          for attempt in $(seq 1 50); do
            [ -S /dev/log ] && break
            sleep 0.1
          done
          [ -S /dev/log ]
          logger -t heteronetwork-runtime ready
          for attempt in $(seq 1 50); do
            grep -Fq "heteronetwork-runtime" /tmp/heteronetwork-runtime.log 2>/dev/null && break
            sleep 0.1
          done
          grep -Fq "heteronetwork-runtime" /tmp/heteronetwork-runtime.log
          trap : TERM INT
          while true; do sleep 3600; done
        image: busybox:1.37.0
        imagePullPolicy: IfNotPresent
        name: probe
      terminationGracePeriodSeconds: 1
EOF
  kubectl -n "$namespace" rollout status daemonset/network-probe --timeout=5m

  local pods_json source target target_ip target_node source_node
  local kubernetes_service_url="https://kubernetes.default.svc.cluster.local/healthz"
  pods_json="$(kubectl -n "$namespace" get pods -l app=network-probe -o json)"
  for source in $(jq -r '.items[].metadata.name' <<<"$pods_json"); do
    source_node="$(jq -r --arg pod "$source" '.items[] | select(.metadata.name == $pod) | .spec.nodeName' <<<"$pods_json")"
    for target in $(jq -r '.items[].metadata.name' <<<"$pods_json"); do
      target_node="$(jq -r --arg pod "$target" '.items[] | select(.metadata.name == $pod) | .spec.nodeName' <<<"$pods_json")"
      [[ "$source_node" != "$target_node" ]] || continue
      target_ip="$(jq -r --arg pod "$target" '.items[] | select(.metadata.name == $pod) | .status.podIP' <<<"$pods_json")"
      reachable=0
      for attempt in $(seq 1 15); do
        if kubectl -n "$namespace" exec "$source" -- \
          ping -c 3 -W 3 "$target_ip" >/dev/null \
          && kubectl -n "$namespace" exec "$source" -- \
            ping -c 3 -W 3 -s "$((expected_mtu - 28))" "$target_ip" >/dev/null; then
          reachable=1
          break
        fi
        sleep 2
      done
      ((reachable == 1)) \
        || die "cross-node Pod traffic failed from $source_node to $target_node at MTU $expected_mtu"
    done
    reachable=0
    for attempt in $(seq 1 15); do
      if kubectl -n "$namespace" exec "$source" -- \
        nslookup kubernetes.default.svc.cluster.local >/dev/null \
        && kubectl -n "$namespace" exec "$source" -- \
          wget -q -T 5 --no-check-certificate -O /dev/null \
            "$kubernetes_service_url"; then
        reachable=1
        break
      fi
      sleep 2
    done
    ((reachable == 1)) \
      || die "Kubernetes Service VIP failed from $source_node"
  done

  local flannel_mtu flannel_link_mtu cni_link cni_link_mtu
  [[ -f /run/flannel/subnet.env ]] || die "local Flannel subnet environment is missing"
  flannel_mtu="$(awk -F= '$1 == "FLANNEL_MTU" {print $2}' /run/flannel/subnet.env)"
  [[ "$flannel_mtu" == "$expected_mtu" ]] \
    || die "Flannel MTU $flannel_mtu does not match $interface MTU $underlay_mtu minus VXLAN overhead ($expected_mtu)"
  flannel_link_mtu="$(ip -o link show dev flannel.1 | sed -nE 's/.* mtu ([0-9]+).*/\1/p')"
  [[ "$flannel_link_mtu" == "$expected_mtu" ]] \
    || die "flannel.1 MTU $flannel_link_mtu does not match the expected MTU $expected_mtu"
  if ip link show dev cni0 >/dev/null 2>&1; then
    cni_link_mtu="$(ip -o link show dev cni0 | sed -nE 's/.* mtu ([0-9]+).*/\1/p')"
    [[ "$cni_link_mtu" == "$expected_mtu" ]] \
      || die "cni0 MTU $cni_link_mtu does not match the expected MTU $expected_mtu"
    while IFS= read -r cni_link; do
      cni_link_mtu="$(ip -o link show dev "$cni_link" | sed -nE 's/.* mtu ([0-9]+).*/\1/p')"
      [[ "$cni_link_mtu" == "$expected_mtu" ]] \
        || die "$cni_link MTU $cni_link_mtu does not match the expected MTU $expected_mtu"
    done < <(
      ip -o link show master cni0 \
        | awk -F ': ' '{print $2}' \
        | cut -d@ -f1
    )
  fi

  kubectl delete namespace "$namespace" --wait=false >/dev/null
  printf 'cluster verified: %s control planes, %s Ready nodes, full-MTU underlay and cross-node Pod traffic, per-node DNS and Service VIP, and runtime Flannel MTU %s\n' \
    "$expected_control_planes" "$actual_nodes" "$flannel_mtu"
}

self_test() {
  interface="heteronetwork0"
  node_ip="10.250.0.2"
  node_name="control-plane-2"
  control_plane_backends="10.250.0.1,10.250.0.2,10.250.0.3"
  preferred_control_plane=""
  apiserver_etcd_backends="10.250.0.1,10.250.0.2,10.250.0.3"
  api_name="k8s-api.heteronetwork.internal"
  api_proxy_port="7443"
  pod_cidr="10.244.0.0/16"
  service_cidr="10.96.0.0/12"
  kubernetes_minor="v1.36"
  state_dir="/etc/heteronetwork/kubernetes"
  validate_control_plane_config
  rendered="$(render_apiserver_etcd_servers)"
  [[ "$rendered" == "https://10.250.0.1:2379,https://10.250.0.2:2379,https://10.250.0.3:2379" ]]
  apiserver_etcd_backends="10.250.0.1,10.250.0.2,10.250.0.99"
  if (apiserver_etcd_addresses >/dev/null 2>&1); then
    die "API server etcd validation accepted a non-control-plane address"
  fi
  apiserver_etcd_backends="10.250.0.1,10.250.0.2"
  if (apiserver_etcd_addresses >/dev/null 2>&1); then
    die "API server etcd validation accepted fewer than three endpoints"
  fi
  apiserver_etcd_backends="10.250.0.1,10.250.0.2,10.250.0.2"
  if (apiserver_etcd_addresses >/dev/null 2>&1); then
    die "API server etcd validation accepted duplicate endpoints"
  fi
  apiserver_etcd_backends="10.250.0.1,10.250.0.2,10.250.0.3"
  kubernetes_versions_are_aligned "v1.36" "v1.36.2" "v1.36.2" "v1.36.2"
  if kubernetes_versions_are_aligned "v1.36" "v1.36.2" "v1.36.3" "v1.36.2"; then
    die "Kubernetes toolchain validation accepted mixed patch versions"
  fi
  if kubernetes_versions_are_aligned "v1.36" "v1.35.9" "v1.35.9" "v1.35.9"; then
    die "Kubernetes toolchain validation accepted the wrong minor version"
  fi

  local rendered bundle worker_bundle worker_state forbidden_tag
  rendered="$(render_haproxy_config)"
  grep -Fq 'bind 127.0.0.1:7443' <<<"$rendered"
  grep -Fq 'option dontlog-normal' <<<"$rendered"
  grep -Fq 'option redispatch' <<<"$rendered"
  grep -Fq 'option httpchk GET /readyz' <<<"$rendered"
  grep -Fq 'http-check expect status 200' <<<"$rendered"
  grep -Fq 'default-server check check-ssl verify none' <<<"$rendered"
  preferred_control_plane="10.250.0.3"
  rendered="$(render_haproxy_config)"
  grep -Fxq '    server control-plane-3 10.250.0.3:6443' <<<"$rendered"
  [[ "$(grep -c '^    server control-plane-.* backup$' <<<"$rendered")" == "2" ]]
  preferred_control_plane=""
  rendered="$(render_haproxy_config)"
  grep -Fq 'retries 2' <<<"$rendered"
  grep -Fq 'timeout connect 5s' <<<"$rendered"
  grep -Fq 'timeout check 5s' <<<"$rendered"
  grep -Fxq '    option httpchk GET /readyz' <<<"$rendered"
  grep -Fxq '    http-check expect status 200' <<<"$rendered"
  grep -Fq 'default-server check check-ssl verify none' <<<"$rendered"
  grep -Fq 'fall 2 rise 2 on-marked-down shutdown-sessions' <<<"$rendered"
  [[ "$(grep -c '^    server control-plane-' <<<"$rendered")" == "3" ]]
  grep -Fxq '    server control-plane-2 10.250.0.2:6443' <<<"$rendered"
  [[ "$(grep -c '^    server control-plane-.* backup$' <<<"$rendered")" == "2" ]]
  control_plane_backends="10.250.0.1,10.250.0.2,10.250.0.3,10.250.0.4,10.250.0.5"
  rendered="$(render_haproxy_config)"
  [[ "$(grep -c '^    server control-plane-' <<<"$rendered")" == "5" ]]
  grep -Fxq '    server control-plane-2 10.250.0.2:6443' <<<"$rendered"
  [[ "$(grep -c '^    server control-plane-.* backup$' <<<"$rendered")" == "4" ]]
  control_plane_backends="10.250.0.1,10.250.0.2,10.250.0.3"
  rendered="$(filter_preserved_node_labels <<< '{"metadata":{"labels":{"kubernetes.io/hostname":"worker-a","beta.kubernetes.io/arch":"amd64","node.kubernetes.io/exclude-from-external-load-balancers":"","node-role.kubernetes.io/control-plane":"","database.heteronetwork.io/proxy-ready":"true","workload.heteronetwork.io/capacity-tier":"high"}}}')"
  [[ "$rendered" == '{"database.heteronetwork.io/proxy-ready":"true","workload.heteronetwork.io/capacity-tier":"high"}' ]]
  rendered="$(render_haproxy_service)"
  grep -Fq 'ExecReload=/bin/kill -USR2 $MAINPID' <<<"$rendered"
  rendered="$(render_overlay_dns_helper)"
  grep -Fq 'resolvectl domain' <<<"$rendered"
  grep -Fq '"~$HETERONETWORK_OVERLAY_DNS_ZONE"' <<<"$rendered"
  grep -Fq 'resolvectl default-route "$HETERONETWORK_OVERLAY_DNS_INTERFACE" no' <<<"$rendered"
  grep -Fq 'console.$HETERONETWORK_OVERLAY_DNS_ZONE' <<<"$rendered"
  rendered="$(render_overlay_dns_service)"
  grep -Fq 'BindsTo=heteronetwork-agent.service' <<<"$rendered"
  grep -Fq 'PartOf=heteronetwork-agent.service' <<<"$rendered"
  grep -Fq 'RemainAfterExit=yes' <<<"$rendered"
  grep -Fq 'Restart=on-failure' <<<"$rendered"
  grep -Fq 'TimeoutStartSec=75s' <<<"$rendered"
  grep -Fq 'WantedBy=multi-user.target heteronetwork-agent.service' <<<"$rendered"
  rendered="$(render_kubelet_dropin)"
  grep -Fq 'Wants=network-online.target heteronetwork-agent.service heteronetwork-overlay-dns.service heteronetwork-kube-apiserver-lb.service' <<<"$rendered"
  grep -Fq 'After=network-online.target heteronetwork-agent.service heteronetwork-overlay-dns.service heteronetwork-kube-apiserver-lb.service' <<<"$rendered"
  rendered="$(render_cloud_init_hosts_config)"
  grep -Fq 'manage_etc_hosts: false' <<<"$rendered"
  rendered="$(render_pod_cidr_routing_helper)"
  grep -Fq 'ip -4 rule add priority "$priority" to "$pod_cidr" lookup main' <<<"$rendered"
  rendered="$(render_pod_cidr_routing_service)"
  grep -Fq 'Before=kubelet.service' <<<"$rendered"
  grep -Fq 'apply 10.244.0.0/16 50' <<<"$rendered"
  grep -Fq 'RemainAfterExit=yes' <<<"$rendered"
  rendered="$(render_init_config v1.36.1)"
  grep -Fq 'controlPlaneEndpoint: "k8s-api.heteronetwork.internal:7443"' <<<"$rendered"
  grep -Fq 'advertiseAddress: "10.250.0.2"' <<<"$rendered"
  grep -Fq 'swapBehavior: NoSwap' <<<"$rendered"
  grep -Fq 'value: "20s"' <<<"$rendered"
  rendered="$(render_containerd_apparmor_profile)"
  grep -Fq 'abi <abi/3.0>,' <<<"$rendered"
  grep -Fq 'profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted)' <<<"$rendered"
  grep -Fq 'network,' <<<"$rendered"
  grep -Fq 'deny mount,' <<<"$rendered"
  rendered="$(render_flannel_mtu_patch 1200)"
  jq -e \
    '.spec.template.metadata.annotations["heteronetwork.io/underlay-mtu"] == "1200"
    and (.spec.template.spec.initContainers | length == 1)
    and (.spec.template.spec.initContainers[0].name == "heteronetwork-mtu")
    and (.spec.template.spec.initContainers[0].image == "ghcr.io/flannel-io/flannel:v0.28.4")
    and (.spec.template.spec.initContainers[0].env[] | select(.name == "HETERONETWORK_INTERFACE").value == "heteronetwork0")
    and (.spec.template.spec.initContainers[0].env[] | select(.name == "FLANNEL_OVERHEAD").value == "50")
    and (.spec.template.spec.initContainers[0].securityContext.capabilities.add == ["NET_ADMIN"])' \
    <<<"$rendered" >/dev/null
  validate_cluster_counts 3 5 5 3 3 3 5 3 3
  if (validate_cluster_counts 3 5 4 3 3 3 5 3 3 >/dev/null 2>&1); then
    die "cluster validation accepted a non-Ready worker"
  fi

  bundle="$(mktemp)"
  worker_bundle="$(mktemp)"
  worker_state="$(mktemp)"
  trap 'rm -f "$bundle" "$worker_bundle" "$worker_state"' EXIT
  jq -n \
    --arg apiServerEndpoint "k8s-api.heteronetwork.internal:7443" \
    --arg token "abcdef.0123456789abcdef" \
    --arg caCertHash "sha256:0000000000000000000000000000000000000000000000000000000000000000" \
    --arg certificateKey "1111111111111111111111111111111111111111111111111111111111111111" \
    '{apiServerEndpoint: $apiServerEndpoint, token: $token, caCertHash: $caCertHash, certificateKey: $certificateKey}' >"$bundle"
  chmod 0600 "$bundle"
  rendered="$(render_join_config "$bundle")"
  grep -Fq 'certificateKey: "1111111111111111111111111111111111111111111111111111111111111111"' <<<"$rendered"
  grep -Fq 'name: "control-plane-2"' <<<"$rendered"

  if (validate_worker_config >/dev/null 2>&1); then
    rm -f "$bundle"
    die "worker validation accepted a control-plane node IP"
  fi
  node_ip="10.250.0.4"
  node_name="worker-1"
  validate_worker_config
  agent_state_path="$worker_state"
  jq -n --arg vpn_ip "$node_ip" \
    '{registered_node: {vpn_ip: $vpn_ip, tags: []}}' >"$worker_state"
  validate_worker_enrollment
  for forbidden_tag in "kubernetes-control-plane" "kubernetes-ha-0123456789abcdef"; do
    jq -n --arg vpn_ip "$node_ip" --arg tag "$forbidden_tag" \
      '{registered_node: {vpn_ip: $vpn_ip, tags: [$tag]}}' >"$worker_state"
    if (validate_worker_enrollment >/dev/null 2>&1); then
      die "worker enrollment accepted reserved tag $forbidden_tag"
    fi
  done
  jq -n --arg vpn_ip "10.250.0.99" \
    '{registered_node: {vpn_ip: $vpn_ip, tags: []}}' >"$worker_state"
  if (validate_worker_enrollment >/dev/null 2>&1); then
    die "worker enrollment accepted a different HeteroNetwork VPN IP"
  fi
  rendered="$(render_haproxy_config)"
  grep -Fxq '    server control-plane-1 10.250.0.1:6443' <<<"$rendered"
  [[ "$(grep -c '^    server control-plane-.* backup$' <<<"$rendered")" == "2" ]]
  if (render_worker_join_config "$bundle" >/dev/null 2>&1); then
    die "worker join accepted a control-plane join bundle"
  fi

  render_worker_join_bundle \
    "k8s-api.heteronetwork.internal:7443" \
    "abcdef.0123456789abcdef" \
    "sha256:0000000000000000000000000000000000000000000000000000000000000000" \
    >"$worker_bundle"
  chmod 0600 "$worker_bundle"
  jq -e '
    (keys | sort) == ["apiServerEndpoint", "caCertHash", "token"]
    and (has("certificateKey") | not)
  ' "$worker_bundle" >/dev/null
  if (render_join_config "$worker_bundle" >/dev/null 2>&1); then
    die "control-plane join accepted a worker-only join bundle"
  fi
  rendered="$(render_worker_join_config "$worker_bundle")"
  grep -Fq 'apiServerEndpoint: "k8s-api.heteronetwork.internal:7443"' <<<"$rendered"
  grep -Fq 'criSocket: "unix:///run/containerd/containerd.sock"' <<<"$rendered"
  grep -Fq 'name: "hostname-override"' <<<"$rendered"
  grep -Fq 'value: "worker-1"' <<<"$rendered"
  grep -Fq 'name: "node-ip"' <<<"$rendered"
  grep -Fq 'value: "10.250.0.4"' <<<"$rendered"
  grep -Fq 'name: "worker-1"' <<<"$rendered"
  ! grep -Fq 'controlPlane:' <<<"$rendered"
  ! grep -Fq 'certificateKey:' <<<"$rendered"

  chmod 0644 "$worker_bundle"
  if (render_worker_join_config "$worker_bundle" >/dev/null 2>&1); then
    die "worker join accepted a group/world-readable join bundle"
  fi
  rm -f "$bundle" "$worker_bundle" "$worker_state"
  trap - EXIT
  printf 'kubeadm HA renderer self-test passed\n'
}

command="${1:-}"
case "$command" in
  prepare) prepare_host ;;
  configure-overlay-dns) configure_overlay_dns ;;
  init) initialize_cluster ;;
  refresh-join-bundle) refresh_join_bundle ;;
  refresh-worker-join-bundle) refresh_worker_join_bundle ;;
  join-control-plane) join_control_plane ;;
  promote-control-plane) promote_control_plane ;;
  join-worker) join_worker ;;
  reconcile-control-plane-backends) reconcile_control_plane_backends ;;
  reconcile-apiserver-etcd) reconcile_apiserver_etcd ;;
  reconcile-pod-routing) reconcile_pod_cidr_routing ;;
  install-flannel) install_flannel ;;
  finalize) finalize_cluster ;;
  verify-host) verify_host ;;
  configure-api-ha) configure_kubelet_api_ha ;;
  reconcile-kubelet-dns) require_root; reconcile_kubelet_resolver ;;
  reconcile-kubelet-api) require_root; reconcile_kubelet_api_endpoint ;;
  verify-cluster) verify_cluster ;;
  self-test) self_test ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
