# Kubernetes HA over HeteroNetwork

This runbook builds a three-control-plane kubeadm cluster over the
`heteronetwork0` WireGuard underlay. It is intended for nodes whose HeteroNetwork
VPN addresses are stable and whose enrollment includes the
`kubernetes-control-plane` tag.

## Topology

Each host runs a dedicated local HAProxy listener at
`k8s-api.heteronetwork.internal:7443`. The name resolves to `127.0.0.1` on every
host. HAProxy checks every API server over its HeteroNetwork VPN address:

```text
kubelet / kubectl -> 127.0.0.1:7443 -> 10.250.0.1:6443
                                      10.250.0.2:6443
                                      10.250.0.3:6443
```

All three nodes run kube-apiserver, scheduler, controller-manager, and a stacked
etcd member. Loss of one node preserves the etcd quorum and leaves two API
servers available. Each HAProxy uses its local API server as the primary and
keeps both remote API servers as health-checked backups. Failed connections are
redispatched, and an unreachable backend is removed after one bounded check.
HAProxy logs failures and backend transitions without synchronously journaling
every successful API connection on the etcd hosts.

Finalization also runs three CoreDNS replicas with required hostname
anti-affinity. DNS therefore remains available when any one control-plane node
is unavailable, including when the initial node fails after the other nodes
join.

The controller manager uses a 20-second node-monitor grace period instead of
the upstream 50-second default. This limits how long a failed node can remain in
Service endpoint selection while still allowing multiple missed kubelet status
updates on the WAN underlay.

Flannel VXLAN uses `heteronetwork0` explicitly. Flannel derives its MTU from the
underlay interface. With the default HeteroNetwork MTU of 1420, the expected Pod
MTU is 1370 after the 50-byte IPv4 VXLAN overhead.

## Automatic enrollment and setup

Create one reusable enrollment through `POST /v1/admin/enrollment` with the
following setup fields, then run the returned install command on three clean
Ubuntu hosts:

```json
{
  "expires_in_seconds": 86400,
  "role": "worker",
  "tags": [],
  "allow_relay": true,
  "reusable": true,
  "max_uses": 3,
  "setup": "kubernetes_ha_control_plane"
}
```

The same command is used on every host. It automatically adds the pinned
`kubernetes-control-plane` tag and a unique cohort tag. Once all three Agents
have enrolled, `heteronetwork-kubeadm-autopilot.service` discovers their VPN
addresses, orders them deterministically, and runs the preparation,
initialization, and control-plane joins. The kubeadm join bundle is served only
on the elected leader's HeteroNetwork address, requires a cohort-specific
Bearer credential, and is removed after verification. Setup credentials are
root-readable and deleted on successful completion.

The default cluster policy pins `kubernetes-control-plane`, so etcd and API
traffic do not depend on a first-packet lazy-connect trigger. Ordinary workers
remain lazy and do not create an all-to-all idle mesh.

The manual commands below remain available for recovery and custom layouts.

## Prepare each host

Run the same script on every host with its own VPN address and node name. The
control-plane list must be identical on all hosts.

```bash
export HETERONETWORK_KUBEADM_NODE_IP=10.250.0.1
export HETERONETWORK_KUBEADM_NODE_NAME=control-plane-1
export HETERONETWORK_KUBEADM_CONTROL_PLANES=10.250.0.1,10.250.0.2,10.250.0.3
sudo -E scripts/kubeadm-ha-node.sh prepare
```

`prepare` installs Kubernetes from the signed `pkgs.k8s.io` v1.36 repository,
configures containerd with the systemd cgroup driver and CRI enabled, loads
`overlay` and `br_netfilter`, enables forwarding, and starts the dedicated API
load balancer. An existing Docker-provided containerd is retained. Its minimal
`disabled_plugins = ["cri"]` configuration is backed up and expanded from that
installed containerd version's own defaults; custom layouts are updated in
place only when they already expose `SystemdCgroup`, otherwise the script
aborts for operator review.

Host swap remains available to non-Pod processes. kubelet uses
`failSwapOn: false` with `NoSwap`, so Kubernetes workloads cannot consume it.

## Initialize and join

On the first node:

```bash
sudo -E scripts/kubeadm-ha-node.sh init
sudo -E scripts/kubeadm-ha-node.sh install-flannel
```

The init command writes a root-only short-lived join bundle to
`/etc/heteronetwork/kubernetes/join-bundle.json`. Transfer that file to the same
path on each joining node with mode `0600`; it contains a bootstrap token and
the certificate upload key and must not be logged.

On each remaining node:

```bash
sudo -E scripts/kubeadm-ha-node.sh join-control-plane
```

Back on any control-plane node:

```bash
sudo -E scripts/kubeadm-ha-node.sh finalize
sudo -E scripts/kubeadm-ha-node.sh verify-cluster
```

## Add worker nodes

Generate a worker-only bundle on any initialized control-plane node:

```bash
export HETERONETWORK_KUBEADM_NODE_IP=10.250.0.1
export HETERONETWORK_KUBEADM_CONTROL_PLANES=10.250.0.1,10.250.0.2,10.250.0.3
sudo -E scripts/kubeadm-ha-node.sh refresh-worker-join-bundle
```

Transfer the resulting root-only
`/etc/heteronetwork/kubernetes/worker-join-bundle.json` to the same path on
each worker with mode `0600`. It contains only a two-hour bootstrap token, the
cluster CA hash, and the local HAProxy endpoint. It does not contain the
control-plane certificate upload key.

Prepare and join each worker with its own HeteroNetwork address:

```bash
export HETERONETWORK_KUBEADM_NODE_IP=10.250.0.10
export HETERONETWORK_KUBEADM_NODE_NAME=worker-1
export HETERONETWORK_KUBEADM_CONTROL_PLANES=10.250.0.1,10.250.0.2,10.250.0.3
sudo -E scripts/kubeadm-ha-node.sh prepare
sudo -E scripts/kubeadm-ha-node.sh join-worker
```

`join-worker` rejects a node whose address is in the control-plane backend
list or which still has control-plane manifests or `admin.conf`. Before
repurposing an existing control-plane host, export its workloads, snapshot its
etcd state, and explicitly reset it; the helper does not automate that
destructive operation. Enroll ordinary workers without the
`kubernetes-control-plane` and `route-provider` tags so they remain eligible
for lazy connect.

`verify-cluster` requires exactly the configured control-plane count, all
registered nodes Ready, and one running Flannel pod per node. It then runs DNS
and full cross-node Pod ping checks and verifies the derived Flannel MTU:

```bash
sudo -E scripts/kubeadm-ha-node.sh verify-cluster
```

## Failure test

Keep an authenticated shell open through HeteroNetwork before disabling any
bootstrap transport. Stop Tailscale on the private nodes and repeat
`verify-cluster`. Then stop kubelet and containerd on one control-plane node.
The remaining local HAProxy instances must continue serving `kubectl`, etcd
must retain two healthy members, CoreDNS must retain two replicas, and
cross-node traffic between the surviving nodes must continue. Restore both
services before testing another node.

Do not stop two stacked-etcd members at once. A three-member etcd cluster only
tolerates one failed member.
