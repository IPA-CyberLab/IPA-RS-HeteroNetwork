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

Ready replicas and a successful apply are not sufficient HA evidence. Verify
the mounted ownership, generated claims, actual replication/synchronous settings,
write/read behavior and controlled primary recovery before deploying Keycloak.
All dev VMs share one physical host, and static local PVs have no spare volumes.
