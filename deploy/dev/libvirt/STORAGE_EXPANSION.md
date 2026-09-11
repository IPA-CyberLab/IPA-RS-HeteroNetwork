# DEV App Storage Expansion

The application manifests need new storage separate from the live identity
Postgres directory. Do not edit `profile.json`'s 40GiB boot size, regenerate
domains, overwrite provisioner journals, or mount over identity storage.

## Observed Capacity: 2026-09-11

Read-only libvirt inventory found exactly four domains and two directory pools.
All four active disk XML definitions had empty backing stores; libvirt reported
no managed snapshots for those domains. Both pools reside on filesystem device
64512, ext4 on `/dev/mapper/ubuntu--vg-ubuntu--lv` mounted at `/`.

| Domain | Virtual Capacity | Allocated Bytes |
| --- | --- | --- |
| hetero-dev-1 | 40GiB | 7176564736 |
| hetero-dev-2 | 40GiB | 7158185984 |
| hetero-dev-3 | 40GiB | 7196143616 |
| vercel-research | 40GiB | 5994098688 |

Libvirt allocation values matched `stat.st_blocks * 512` at observation time.
The two pool directories also contained fixed base images and seed ISOs; the
Vercel pool contained a cloud-init directory. No content of that directory or
credential-bearing seed media was read. Directory enumeration and managed
snapshot lists are not a whole-host storage audit or an allocation reservation.

Fresh `statvfs` reported 514584236032 available bytes and 38877160 available
inodes. Accounting for current disk allocations gives:

| Budget Item | Bytes |
| --- | --- |
| Proposed three 64GiB app disks | 206158430208 |
| Existing disks' remaining virtual growth | 144273698816 |
| Host reserve, 128GiB | 137438953472 |
| Metadata/operational allowance, 5GiB | 5368709120 |
| Total additional admission budget | 493239791616 |
| Observed available minus budget | 21344444416 |

The approximate 19.88GiB remainder assumes the observed standalone ext4 files
are not shared allocations and that no additional commitments are introduced.
Without crediting already allocated blocks, the conservative budget exceeds
available space by about 5.76GiB. Do not silently omit the unrelated Vercel disk
from either calculation. Refresh and validate the complete inventory under the
provisioner lock immediately before any allocation. Unknown allocations,
backing chains, snapshots or concurrent provisioning require investigation.

## Implementation And Deployment Gates

Add a separate, identity-pinned expansion operation using the existing journal
lock and resource/file/firewall checks. Create only a new app disk for each DEV
guest, retaining existing boot disks, CPU configuration, seed and networking.
Preallocation must be verified; a sparse 64GiB logical size reserves nothing.
Record intent before mutations, refuse partial or replaced files, and verify
the exact persistent and live disk mappings before acknowledging completion.

Guest formatting must select a verified unique disk serial and expected size,
reject mounted/root/identity devices and existing signatures, and record the
filesystem UUID. Mount only at a separate app-storage path, with fail-closed
consumer ordering so missing storage cannot fall back onto the boot disk.
The host helper is `scripts/expand-dev-storage.py`; its offline `plan` command
does not admit capacity or make mutations. Root-only `inspect --probe-readiness`
checks the live inventory and all three guests before any disk operation.
The one-guest `apply` path uses
verified ext4 preallocation and live/persistent hotplug without guest restart.
The guest helper is `deploy/dev/apps/prepare-storage.py`, which verifies the
native identity and live Kubernetes UID before formatting a fresh serial-pinned
disk.

`complete-readback --guest NAME --probe-readiness` is only for an inspected
interruption after both live and persistent attachment completed. It checks the
original journaled domain hash, exact unchanged preexisting XML, owned request
and disk inode, allocated capacity, all resource definitions, firewall, guest
identities and cluster readiness. It acknowledges completion but cannot create,
attach, detach, format or adopt an unowned disk. Preserve incomplete journals;
do not delete them to retry.

Guest preparation deliberately does not restart consumers or activate the
kubelet mount dependency after installing it. It reports app provisioning as
not ready pending a planned activation and operational verification. The mount
guard alone does not stop existing containers. Do not deploy app workloads on
the new paths merely because formatting and mounting succeeded.

Per guest, current requested app storage is approximately 35GiB: 15GiB for
three app databases, 8GiB Redis and 12GiB Garage. Remaining nominal capacity
must cover filesystem overhead and operational/replacement volumes. PVC sizes
do not enforce directory quotas. Fresh retained PVs, exact claim reservations,
correct service ownership and actual recovery checks remain required. The
three guests still share one physical host and storage failure domain.

## Actual Deployment: 2026-09-11

All three new standalone 64GiB qcow2 disks were preallocated and attached to
running guests, with live and persistent definitions verified. No shutdown,
reboot, detach, or root-disk change was issued. The unrelated Vercel VM remained
running and was included in every capacity calculation.

The first attachment stopped at readback because live libvirt XML added a
numeric source `index`. Inspection confirmed the correct source/serial and
unchanged existing devices. The scoped `complete-readback` operation then
acknowledged that already-completed attachment, without repeating it. The next
two attachments completed normally with the corrected validation.

The active host bundle is `/opt/heteronetwork-dev-storage-6bf26b81`:

- Bundle SHA-256: `6bf26b81eecfa993f655d1f9a01ae6be879bd144559742093a0494af3b855c59`
- Host helper SHA-256: `4c5760fe39eab786888325e939296b903bc63fd46ddaf9e50d0ca6dcf5f7ff1d`

Each guest uses `/opt/heteronetwork-dev-app-storage-a349cce2/prepare-storage.py`,
SHA-256 `a349cce218e84713e8967f96c3a9fee740b5441cf79819c9e0f1eb8e5ba80afe`.
The guest helper now reads `/proc/swaps`, since the installed `swapon` has no
JSON option. It tightens only the known root:root `/etc/kubernetes` directory
from mode 0775 to 0755 before the private admin.conf path checks. No credential
contents were exported. An earlier attempt stopped before format intent.

All app disks are mounted as ext4 at
`/var/lib/heteronetwork-dev-app-storage`, separate from identity data:

| Guest | Disk Serial | Filesystem UUID |
| --- | --- | --- |
| hetero-dev-1 | hnapp-381d1ae16f55 | 17138c6e-6b4d-4751-be77-d543492b0b76 |
| hetero-dev-2 | hnapp-acc5151b6b24 | e57ca4f8-930c-4c23-9830-951a563fef09 |
| hetero-dev-3 | hnapp-165a6e8acc3a | 21469bc7-98b6-420e-9850-67582114c05f |

Repeat preparation returned `created: false` on every guest and verified each
mount/UUID. All kubelets were active, all three Kubernetes nodes Ready, and all
three identity database instances Ready. Post-format host inventory still
verified allocated blocks, with 308095922176 available bytes versus a remaining
admission budget of 286759317504 bytes. These are point-in-time observations.

At this mount-only checkpoint the kubelet guard was installed but not activated,
and no app directories, PVs or workloads had been provisioned. Subsequent guard
activation, directory preparation and PV apply are recorded in
`../apps/STORAGE_ACTIVATION.md`. No storage-loss or physical-host HA test was run.
