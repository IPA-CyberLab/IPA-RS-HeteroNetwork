# Fresh DEV Identity Storage

Prepared only; no resources applied and no host directories created. `storage.yaml`
is a Kubernetes List expressed in the JSON subset of YAML so the offline tests
need only Python's standard library. It contains a namespace, non-default static
StorageClass and three node-local filesystem PVs, not a PostgreSQL Cluster or PVCs.

## Deployment Preconditions

- Independently verify kube-system UID
  `a39281cb-d273-4c5f-b7a7-fca722fb417b`, node identities `hetero-dev-1..3` and
  VPN addresses `10.251.0.1..3`. Annotations are documentation, **not an enforced
  cluster-identity guard**. The deployment owner must enforce that check.
- On each pinned guest, inspect actual disk backing, free bytes/inodes and
  competing usage before creating the fresh, empty, non-symlink directory
  `/var/lib/heteronetwork-dev-storage/identity-postgres`. Never reuse production
  data, clear an existing directory or recursively change ownership of unknown
  data. Host directory creation remains a separately reviewed parent operation.
- With the selected PostgreSQL image confirmed to use UID/GID 26, prepare the
  fresh volume directory for `26:26` with restrictive permissions (0700), with
  trusted root-controlled ancestors. Check the actual generated pod security
  context and mounted-volume access before readiness; PV metadata has no UID or
  fsGroup field. Do not use a privileged chmod/chown sidecar or disable security
  policies to work around a mismatch.
- Confirm CNPG 1.30.0's operator/webhook is ready, the three initial claim names
  below are unused, and namespace/PVC creation is restricted to the intended
  administrators/operator. Required hostname anti-affinity in the parent Cluster
  config should keep one PostgreSQL instance per guest. Leave scheduling to the
  scheduler; do not set pod `nodeName` with delayed binding.

The advertised 8Gi per PV is **not** an 8Gi directory quota, allocated disk space,
I/O reservation or evidence of available capacity. All VMs share one physical
host and may share backing storage. This does not establish host/storage-failure
resilience, backup, encryption at rest or successful database initialization.

## Parent CNPG Contract

For the fresh `dev-identity-postgres` Cluster in `hetero-dev-identity`, incorporate
these storage/security fields into the separately owned Cluster configuration:

```yaml
spec:
  instances: 3
  postgresUID: 26
  postgresGID: 26
  podSecurityContext:
    runAsUser: 26
    runAsGroup: 26
    fsGroup: 26
  storage:
    size: 8Gi
    storageClass: dev-identity-local
    resizeInUseVolumes: false
    pvcTemplate:
      accessModes: [ReadWriteOnce]
      volumeMode: Filesystem
      storageClassName: dev-identity-local
      resources:
        requests:
          storage: 8Gi
      selector:
        matchLabels:
          heteronetwork.dev/storage-purpose: identity-postgres
```

CNPG creates the PVCs; do not manually create competing claims. The three PVs
reserve `hetero-dev-identity/dev-identity-postgres-1`, `-2` and `-3` respectively
using `claimRef`, without fabricating PVC UIDs. Mandatory PV hostname affinity
binds each volume to its corresponding guest. Labels/selectors alone do not
prevent an unrelated PVC from capturing a PV; the explicit claim reservations
provide that additional initial binding restriction. They do not constrain an
administrator or an actor able to create the exact reserved claims.

There is no dynamic provisioner, spare PV or separate WAL/tablespace capacity.
Replacement instance serials, additional replicas, deleted/recreated claims and
volume expansion require a new reviewed storage plan. `Retain` keeps data after
claim deletion; do not clear claim references, delete data or repurpose a Released
volume automatically. Static local storage restricts automated recovery when a
node or its disk is unavailable.

## Official Compatibility References

CNPG 1.30 documents static provisioning with matching PVC templates, while
warning about scheduling and reduced self-healing:
[v1.30.0 storage documentation](https://github.com/cloudnative-pg/cloudnative-pg/blob/v1.30.0/docs/src/storage.md#static-provisioning-of-persistent-volumes).
Its security documentation supports pod `runAsUser`, `runAsGroup` and `fsGroup`
settings, including UID/GID 26:
[v1.30.0 security documentation](https://github.com/cloudnative-pg/cloudnative-pg/blob/v1.30.0/docs/src/security.md#customizing-security-contexts).
Kubernetes requires node affinity for local PVs and recommends delayed binding:
[official local-volume documentation](https://kubernetes.io/docs/concepts/storage/volumes/#local).

## Offline Checks

```sh
python3 -B deploy/dev/identity/test_storage.py
```

These tests check manifest contracts only. Parent must validate against the
installed Kubernetes/CNPG APIs, confirm generated PVC selectors and claim names,
then inspect binding, scheduling, permissions and database health during the
separately authorized deployment. No live capacity or readiness is asserted here.
