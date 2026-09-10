# Existing DEV CPU Migration

The initial three domains inherited `qemu64`. The official Keycloak 26.7.3
container failed immediately with `CPU does not support x86-64-v2`, although the
physical host exposes the required additional CPU flags. New domains now use
`host-model`; existing domains need a cold restart to expose a different CPU.

`scripts/migrate-dev-cpu.py --guest hetero-dev-2` performs this specific migration
on the authorized physical host. Deliver it with the matching protected
`provision-dev-libvirt.py` and `deploy/dev/libvirt/profile.json`, preserving their
relative repository paths. Execute only reviewed, root-owned copies. The helper
reuses the provisioner's exclusive journal lock, owned-file checks, UUID and
definition hashes, and live isolation-rule verification.

Before changing one guest, all three VMs, Kubernetes nodes and database instances
must be running/Ready in the pinned DEV cluster. The guest's hostname and machine
ID are checked over pinned SSH. The XML transformation accepts only the observed
minimal `qemu64` CPU or the already configured `host-model`. It proves all non-CPU
XML content is unchanged. Definitions are validated through libvirt, read back,
and recorded in the existing journal with an explicit migration intent.

The helper requests ACPI shutdown and waits up to 180 seconds. It never forces
power-off, resets a guest, recreates disks or edits cloud-init state. After a
confirmed stop it starts that same UUID and checks for a new boot ID, the CPU
flags, all three Ready nodes and three Ready database instances. Recovery has a
420-second bound, after individual command timeouts. A completed record makes
subsequent verified invocations a no-op. Invoke only one guest at a time and
inspect its completed result before proceeding to the next.

This operation is not atomic. A failure may leave a pending definition intent,
a changed inactive CPU definition, a stopped VM or an incomplete recovery record.
Do not clear pending state or alter recorded hashes merely to get past checks.
Inspect the actual definition and lifecycle state and explicitly recover that
same guest before requesting another migration. The helper refuses to begin a
new migration while another guest is stopped or the cluster is degraded.

Required-flag and Ready checks are bounded operational gates, not proof of
application HA, etcd durability under arbitrary faults or all-node connectivity.
Host-model uses the current physical host's capabilities; it does not guarantee
live migration to unlike hardware. The three guests still share one physical
host and fail together if that host fails.

Focused tests cover wrong identities, unreviewed CPUs, unchanged non-CPU XML and
idempotent transformation. They do not power-cycle guests. Live results must be
recorded separately from those fixture tests.
