# DEV Identity Foundation

This is an isolated development deployment, not a production rollout. The native
HN control plane is still separate; this PostgreSQL cluster is for the new dev
Keycloak identity provider. No production database, realm or user state is copied.

## Reviewed Sources

The CNPG `v1.30.0` release manifest asset 461304060 was downloaded from the
[official release](https://github.com/cloudnative-pg/cloudnative-pg/releases/tag/v1.30.0).
Its bytes match the GitHub asset SHA-256 in `operator-lock.json`. This is a
publisher/asset pin, not a claim that an independent signature was verified.
The operator image and PostgreSQL image digests were resolved through their
official GHCR repositories; no mutable tag is deployed alone. PostgreSQL 18.6
is the current 18.x minor in the [upstream version table](https://www.postgresql.org/support/versioning/),
and PostgreSQL 18 is supported by [Keycloak](https://www.keycloak.org/server/db).

`render-operator.py` requires the exact upstream bytes and preserves the CRDs,
RBAC, webhook and security settings. It changes the operator to three replicas
with required hostname anti-affinity, retains leader election, pins both the
manager and generated instance-manager images, and adds a two-available PDB.
The official [installation guide](https://cloudnative-pg.io/docs/1.30/installation_upgrade/)
supports multiple operator replicas with leader election and server-side apply.

## Reproduction

Use the repo's existing `deploy/gitops/environments/requirements.txt` environment
for PyYAML. Download the asset in `operator-lock.json`, then render locally:

```sh
python3 deploy/dev/identity/render-operator.py --upstream /private/cnpg-1.30.0.yaml --output /private/operator.json
```

Check the result and all three authored resource files against `delivery.json`.
Deliver them, `delivery.json` and `apply.py` to a root-owned private
`/opt/heteronetwork-dev-identity` on DEV1. Deliver `prepare-storage.py` to the
same protected directory on each guest. Check reviewed source hashes before
executing copied helpers; do not source code from a writable download directory.

Run `prepare-storage.py` as root on each guest. It checks hostname, machine ID,
DMI UUID and bootstrap cluster, then creates only a fresh private data directory
for UID/GID 26. An inode-bound root marker makes rechecking idempotent without
changing ownership or deleting existing data. Unknown or partial allocation is
rejected. This does not allocate an 8Gi filesystem quota; see [STORAGE.md](STORAGE.md).

On DEV1, invoke the protected apply helper one phase at a time:

```sh
sudo python3 /opt/heteronetwork-dev-identity/apply.py operator
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf -n cnpg-system rollout status deployment/cnpg-controller-manager --timeout=300s
sudo python3 /opt/heteronetwork-dev-identity/apply.py storage
sudo python3 /opt/heteronetwork-dev-identity/apply.py network
sudo python3 /opt/heteronetwork-dev-identity/apply.py database
```

Each phase rechecks the observed kube-system UID, all three Ready dev node IPs,
and actual API Service/EndpointSlice addresses. Artifact hashes are checked before
server-side dry-run and apply; no force-conflicts or delete/reset is used.
Namespaces are applied first because dry-run of namespaced resources requires an
existing namespace. A later failure can therefore leave an empty namespace;
this is not an atomic transaction or automatic rollback.

The database requires one synchronous standby, quorum-based failover and three
instances with required hostname anti-affinity. Missing synchronous capacity
blocks writes rather than silently lowering durability. Operator-managed fresh
credentials remain in the dev namespace. NetworkPolicy permits only the scoped
database/Keycloak/operator flows, dev DNS and observed Kubernetes API endpoints.
No NodePort, public ingress or external database endpoint is created here.

The webhook ingress allows the three node VPN IPs and each node's two reserved
Flannel/CNI addresses (`172.29.0.0/31`, `172.29.1.0/31`, `172.29.2.0/31`) only on
TCP 9443. Actual DEV1 route inspection found source `172.29.0.1` for a local Pod
and `172.29.0.0` for remote Pods; VPN IP-only webhook policy would miss those
host-originated flows. The apply guard pins the three per-node PodCIDRs too.
These narrow ranges do not include the ordinary Pod allocation addresses.

Ready replicas and a successful apply are not sufficient HA evidence. Verify
the mounted ownership, generated claims, actual replication/synchronous settings,
write/read behavior and controlled primary recovery before deploying Keycloak.
All dev VMs share one physical host, and static local PVs have no spare volumes.

## Observed Runtime: 2026-09-10

The operator rollout completed, and storage, network and database phases applied
successfully to kube-system UID `a39281cb-d273-4c5f-b7a7-fca722fb417b`.
All three PostgreSQL Pods became Ready, with claims bound to the matching static
local PVs on `hetero-dev-1`, `hetero-dev-2` and `hetero-dev-3`.

`verify.py` passed against the actual database through local PostgreSQL sockets.
It reuses the protected apply helper's cluster guards and bounded command runner;
it does not read credentials or change database contents. Deliver its reviewed
bytes beside the root-owned `apply.py`, then run:

```sh
sudo python3 /opt/heteronetwork-dev-identity/verify.py
```

The observed primary was `dev-identity-postgres-1`. Both other instances were in
recovery and appeared on the primary as `streaming`, `quorum` standbys.
`synchronous_commit` was `on`; `synchronous_standby_names` used `ANY 1`.
The checker currently expects the initial numbered Pod-to-PV placement. A later
replacement with different instance names needs a separately reviewed check;
do not rename instances or reset storage simply to satisfy this checker.

This verifies the current read-only replication state, not write durability
during a failure. No primary termination, VM fault, recovery exercise or physical
HA test was performed in this step. Keycloak and live majority-authorized sudo
issuance/enforcement remain unconfigured.

After the subsequent one-guest-at-a-time CPU migration, `verify.py` passed again:
the primary was `dev-identity-postgres-2`, with DEV1 and DEV3 as streaming quorum
standbys, `synchronous_commit=on` and `ANY 1` synchronous standby selection.
The primary change was observed during DEV1 maintenance. No write-loss or
uninterrupted-login test is implied. Keycloak server rollout and verified HTTPS
discovery now pass as recorded in [KEYCLOAK.md](KEYCLOAK.md); owner login and sudo
issuance/enforcement are still unfinished.
