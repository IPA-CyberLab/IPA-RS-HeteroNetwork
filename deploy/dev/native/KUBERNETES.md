# Fresh Dev Kubernetes Preparation

Source support only: the already verified dev4 archive still contains the old
helper. Do not edit that archive, substitute its contents, or claim its digest
covers this change. Use a later reviewed release containing this helper, or a
separately reviewed, explicitly digest-pinned source delivery approved by the
deployment owner. No native packaging inventory changes are needed for the
`fresh-dev` path. No guest commands have been run as part of these tests.

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
