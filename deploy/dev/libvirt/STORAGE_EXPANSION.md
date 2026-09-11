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

## Required Implementation

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
These operations have not been implemented or performed by this inspection.

Per guest, current requested app storage is approximately 35GiB: 15GiB for
three app databases, 8GiB Redis and 12GiB Garage. Remaining nominal capacity
must cover filesystem overhead and operational/replacement volumes. PVC sizes
do not enforce directory quotas. Fresh retained PVs, exact claim reservations,
correct service ownership and actual recovery checks remain required. The
three guests still share one physical host and storage failure domain.
