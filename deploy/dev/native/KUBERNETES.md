# Fresh Dev Kubernetes Preparation

The already verified dev4 archive still contains the old
helper. Do not edit that archive, substitute its contents, or claim its digest
covers this change. Use a later reviewed release containing this helper, or a
separately reviewed, explicitly digest-pinned source delivery approved by the
deployment owner. No native packaging inventory changes are needed for the
`fresh-dev` path. No guest commands have been run as part of these tests.

## Actual Preparation: 2026-09-10

Preparation completed successfully on all three dev guests,
followed by read-only verification: kubeadm `v1.36.4`, containerd `2.2.1`, and
active agent, containerd, `heteronetwork-kube-apiserver-lb` and pod-routing
services. Persisted `fresh-dev` configuration uses node addresses
`10.251.0.1`, `.2`, `.3`, pod CIDR `172.29.0.0/16` and service CIDR
`172.30.0.0/16`. `/etc/kubernetes/admin.conf` was absent on all three.

The delivered preparation helper remains the separately reviewed `47dc...`
source, delivered at
`/opt/heteronetwork-dev-kubeadm-d9514d31/kubeadm-ha-node.sh`, not substituted into
the release archive. Commit `2d6e6d1f` and helper SHA-256
`04ea6c54bd295e963197a223056665378bcecffa02977b1f89ad117b75e739cf`
(init output protection and Flannel CIDR fixes) **have not yet been delivered**
at this checkpoint. Init and Flannel installation have not run. This establishes
host preparation only, not Kubernetes readiness or control-plane HA.

Separate read-only production inspection: `.10:19088` refused
connections; agent status identified build `0.1.0`, revision `bed2a7a`, started
at 20:54:25 UTC before this task, and `/v1/peers` returned 404, causing backend
autopilot failure. This is not a production-health claim or a dev deployment
result. The `bed2a` source contains the route; `runtime.peer_map_snapshot`
returning `PeerMapUnavailable` also maps to 404. Subsequent inspection confirmed
the response body: `peer map has not been synced for node
node-010adc8f711b1982b3f0d0870d54431e`. This establishes unsynced peer-map state,
not why synchronization failed. Neither a missing route nor version
incompatibility has been established. No production
changes or new remote checks accompanied this doc update.

## Subsequent Cluster Verification: 2026-09-10

After the preparation checkpoint above, all three Kubernetes `v1.36.4`
control-plane nodes were initialized/joined successfully using helper
`04ea6c54bd295e963197a223056665378bcecffa02977b1f89ad117b75e739cf`, delivered
separately at `/opt/heteronetwork-dev-kubeadm-2d6e6d1f/kubeadm-ha-node.sh`.
Join secrets remained root-only; no production issuer or credentials were reused.
The `04ea` helper did not fail init: its later Flannel client dry-run produced
six JSON documents rather than a List, so transformation stopped **before apply**.

Commit `bc407d33`, helper SHA-256
`2dddc699eeb2b728b8b9c0b56358d354b27fc4b1e8821bb32f63151dc67b57ea`,
was then delivered to **DEV1 only** at
`/opt/heteronetwork-dev-kubeadm-bc407d33/kubeadm-ha-node.sh`. It accepts the
document stream as well as a List. Retrying Flannel installation succeeded,
followed by finalization with three CoreDNS replicas; no reset or preparation
rerun was involved.

Actual `verify-cluster` exited 0, reporting three control-plane nodes and all
three Ready. Full-MTU underlay checks, cross-node Pod traffic, per-node DNS and
Service VIP checks passed; runtime Flannel MTU was 1230.

Read-only API verification observed kube-system UID
`a39281cb-d273-4c5f-b7a7-fca722fb417b` and exactly the three expected dev nodes,
all Ready on `10.251.0.1` through `.3`. The existing policy-only kube-router
manifest (`deploy/gitops/network-policy-engine/kube-router.yaml`, SHA-256
`a9ff6c2fd9f05ff3144e119f84c4fb480e6ed297795950892438affbaf80717b`)
passed server-side dry-run and was applied to this UID-checked dev cluster.
Its DaemonSet reached 3/3 Ready. The production kube-system UID query timed out; no
production identity or health conclusion was inferred from the dev results.

The separate `scripts/verify-dev-network-policy.py` gate (commit `d2048dc1`,
SHA-256 `42a18adc834fa6e34071818336b24773562a29403971e7527d2299a829f09743`)
then passed against this cluster. All six directed TCP paths passed baseline,
Ingress deny, Ingress allow, Egress deny and Egress restoration checks, with two
consecutive matching samples per phase. The probe used cached immutable image
`docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0`.
UID-preconditioned cleanup completed for namespace UID
`3c938efb-8160-49af-ad3f-36f94dc072e6`; no tenant namespace was used. This verifies
these TCP NetworkPolicy cases, not every future Flash policy or host-network
workload's isolation.

No fault/failover test was performed. All three guests reside on one physical
host, so this does not establish physical-host resilience. The native
HeteroNetwork CP remains single-instance SQLite on DEV1, separate from the
three-node Kubernetes control plane. Sudo production enforcement and cloud
services are not activated. The earlier preparation and VPN checkpoints remain
historical records, not claims about the current phase or perpetual health.

## Exact Dependencies

Standard `prepare` needs these checkout-relative files:

- `scripts/kubeadm-ha-node.sh` itself, copied to its canonical libexec location
  for subsequent reconciliation.
- `scripts/public-services-bootstrap.sh` (present as `libexec/` in native archives).
- `deploy/systemd/heteronetwork-public-services-bootstrap.service`.
- `deploy/systemd/heteronetwork-public-services-bootstrap.timer`.

The last two are not in the native helper inventory. Standard preparation now
checks these dependencies before package installation or host writes. Its
existing behavior otherwise remains unchanged, including enabling the timer.
The dev profile does not need any of the three public-bootstrap files.
Other preparation helpers, systemd units, HAProxy configuration and Kubernetes
configuration are rendered by the main script, not loaded from sibling files.

Preparation still needs root, Bash, systemd and an already running native agent
with its canonical API token and WireGuard interface. It installs Kubernetes,
containerd when missing, HAProxy and supporting packages through apt. Package
repository/network access is required. `install-flannel` is a separate later
operation using the helper's pinned upstream manifest digest. No production
credentials or cluster discovery data are inputs.

## Explicit Dev Profile

First complete the identity-pinned native bootstrap and collect fresh sustained
VPN verification reports from all three guests against the same public roster,
as described in `README.md`. An active systemd unit is not sufficient evidence.
The helper additionally checks the local VPN interface address and active agent;
it does not itself aggregate the three sustained reports.

Set the following explicitly in the root administration environment, using the
actual local guest name and observed VPN allocations (never assume their order):

```sh
export HETERONETWORK_KUBEADM_PROFILE=fresh-dev
export HETERONETWORK_KUBEADM_NODE_NAME=hetero-dev-1
export HETERONETWORK_KUBEADM_NODE_IP='<observed local 10.251.0.x address>'
export HETERONETWORK_KUBEADM_CONTROL_PLANES='<observed comma-separated dev VPN addresses>'
export HETERONETWORK_KUBEADM_API_NAME=k8s-api.hetero-dev.internal
export HETERONETWORK_KUBEADM_POD_CIDR=172.29.0.0/16
export HETERONETWORK_KUBEADM_SERVICE_CIDR=172.30.0.0/16
/opt/heteronetwork/libexec/kubeadm-ha-node.sh prepare
```

These placeholders intentionally fail validation. The script requires matching
`hetero-dev-{1,2,3}` hostname, canonical agent paths/local endpoints, explicit dev
API name/CIDRs and exclusively `10.251.0.0/24` host addresses. The provisioning
and native bootstrap identity checks remain mandatory: hostname validation alone
is not proof of exclusive dev ownership.

`fresh-dev` skips public-service bootstrap, API backend discovery timers and host
overlay split DNS. The native agents initially disable overlay services; the
Kubernetes API hostname instead uses the helper's explicit hosts entry and
configured backend list. No production DNS/CP address is silently substituted.
Existing conflicting public/discovery/DNS units or Kubernetes state cause refusal
before package installation. Nothing disables an existing timer or deletes state.

The profile is persisted in root-owned `node.env` along with explicit network
settings. Subsequent manually invoked commands must load/export that file rather
than fall back to defaults. Preparation is for fresh nodes: partial package or
configuration failure requires inspection, not automatic reset/retry or erasing
`/etc/kubernetes`, `/var/lib/kubelet` or `/var/lib/etcd` to pass the gate.

After successful preparation, the existing `init`, `refresh-join-bundle` and
`join-control-plane` workflow applies with the same dev environment. Transfer
new dev join credentials only through the authenticated administration path.
The reviewed init/Flannel fixes must be delivered separately before those
operations; already delivered preparation helpers and verified release archives
are not updated by a source commit.

`init` captures both stdout and stderr from kubeadm configuration validation and
initialization in a private temporary file, removed on exit. Neither successful
join instructions nor failure output containing credentials is echoed. Failure
reports are sanitized; inspect local cluster state before retrying rather than
assuming initialization made no changes. Join credentials remain available only
through the existing private join-bundle workflow.

`install-flannel` first verifies the pinned upstream YAML checksum, retains the
existing interface pin, and converts it to a Kubernetes JSON List using kubectl
client dry-run. A structured jq transform parses the sole `kube-flannel-cfg`
ConfigMap's `net-conf.json`, replacing only `Network` with the validated pod CIDR
(`172.29.0.0/16` for fresh-dev) before apply. Missing/duplicate ConfigMaps or
malformed network JSON fail closed. Other fields and the existing MTU patch are
preserved; neither the pinned upstream bytes nor any release archive is changed.

Flannel installation, cluster verification and workload readiness are separate
gates; successful preparation does not mean a ready Kubernetes cluster. The
initial HeteroNetwork SQLite control plane remains single-instance, not CP HA.

## Local Checks

```sh
bash -n scripts/kubeadm-ha-node.sh
python3 -B scripts/kubeadm-ha-node-dev.test.py
bash scripts/kubeadm-ha-node.sh self-test
```

Tests use mocked shell operations and renderers. They do not install packages,
start services, enroll nodes or prove live Kubernetes behavior.
