# DEV App Storage Activation

## Scope

`activate-storage.py activate` verifies a completed, identity-pinned mount,
reloads systemd, and verifies the loaded kubelet Requires/BindsTo/After edges.
The kubelet PID and invocation ID must remain unchanged. Run in an exclusive
systemd/storage maintenance window: daemon-reload is manager-wide. The command
does not restart services, unmount filesystems, format disks or mutate Kubernetes.

It then creates six fixed app directories on that guest's dedicated disk:
three PostgreSQL directories (UID/GID 26), Redis (1001), and Garage metadata/data
(65532). Initial permissions are 0700. An intent is written before creation;
completion records filesystem identity, plan hash and each directory inode.
An interrupted directory transaction is refused, not adopted or deleted.

`activate-storage.py verify` rechecks those records, mount and dependency graph
without daemon-reload or directory creation. These checks target the prepared
storage stage. Once workloads create bind mounts or change volume permissions,
the verifier needs explicit support for those observed consumer mounts; do not
remove its checks just to make a later deployment pass.

## Cluster Apply

The host-only `scripts/apply-dev-app-storage.py inspect` checks the libvirt
journal, all three dedicated disks, firewall and cluster readiness. It then
independently invokes the pinned storage verifier on every guest over pinned
SSH. It checks for conflicting resource ownership and performs a server dry-run
against the dedicated DEV Kubernetes UID.

`scripts/apply-dev-app-storage.py apply` repeats all checks, then applies only
the fixed StorageClass and 18 local PVs with field manager
`hetero-dev-app-storage`. It does not use force-conflicts, delete resources,
create PVCs, launch workloads or reuse identity volumes. Existing objects must
already have the same field manager and contain the desired definition.
Applied definitions are read back and compared with the requested manifest.

## Runtime Evidence: 2026-09-11

All three guests completed activation and directory creation. Each reported:

- Active mount dependency verified.
- Six directories created on its previously recorded filesystem UUID.
- Kubelet PID and invocation ID unchanged during activation.
- No service restart or guest reboot issued.

The first DEV1 attempt stopped before creating directories because systemctl
quoted and escaped the mount unit name in list-valued properties. Parsing now
uses `shlex.split`; the same live dependency edges then passed verification.

Pinned guest bundle: `/opt/heteronetwork-dev-app-activation-32497083`.
Archive SHA-256: `324970837f258c02d5ceb79b18a3a0a0b31625cc0858e509c40357ef03cbfd27`.

Current host apply bundle: `/opt/heteronetwork-dev-pvs-2884a268`.
Archive SHA-256: `2884a2685551e9c6bb06d468f5114b3dd9016cdb0c3808119950de91eac4afcc`.

The host inspection and real apply both verified all three guest mounts. The
real apply returned `applied: true` and `readback_verified: true` for 18 PVs and
`dev-app-local`, in Kubernetes cluster
`a39281cb-d273-4c5f-b7a7-fca722fb417b`.

The original repeat attempt stopped because kubectl hid managedFields in its
default JSON output. An explicit read with `--show-managed-fields` confirmed
`hetero-dev-app-storage` ownership. Ownership reads now request that field;
they do not bypass the check. Reapplying the existing 19 objects then succeeded,
again verifying all three guests and reading back the definitions. Guest
verification returned `directories_created: false`; directories were not reset.

PVC binding, application startup and storage-loss recovery are not verified.
PV capacity declarations do not enforce individual directory quotas. The three
DEV guests still share one physical host; this does not establish host HA.
