# DEV Application Capacity

## Observed Configuration: 2026-09-11

Read-only libvirt inspection found four domains:

| Domain | vCPU Maximum | Configured RAM |
| --- | --- | --- |
| hetero-dev-1 | 4 | 8GiB |
| hetero-dev-2 | 4 | 8GiB |
| hetero-dev-3 | 4 | 8GiB |
| vercel-research | 16 | 16GiB |

The DEV definitions have `vcpu placement="static"` with value 4, no separate
current-vCPU count, no maxMemory entry and no CPU topology override. Existing
definitions do not provide spare hotplug capacity for the proposed increase.
No domain definition or guest power state was changed during this inspection.

The host reported 104 logical CPUs and 82061076 KiB RAM. LVM also reported
252371271680 unallocated bytes in `ubuntu-vg`; the existing linear root LV is
644245094400 bytes. Unallocated VG extents are not filesystem free space and
were not added to the app-disk admission budget. No LV/filesystem resize ran.

## Selected Chart Request Accounting

`deploy/gitops/environments/capacity.py` accounts for declared pod requests,
regular init-container peaks, explicit pod overhead and limit-to-request
defaults. Jobs are reported separately. It rejects unmodelled pod-level
resources, restartable init containers and workloads needing explicit placement
counts. It does not implement scheduling, rollout surge, LimitRange admission,
memory limits, runtime overhead or load-test capacity.

Actual selected release charts at channel revision 11 were rendered from clean
exact-commit checkouts through the existing Helm validator. Site hostnames,
identities and auxiliary digests were explicitly offline test fixtures. No
fixture manifests or identities were deployed or treated as verified site data.

| Scope | CPU Request | Memory Request |
| --- | --- | --- |
| App steady workloads including the nine app DB instances | 14000m | 16374562816 bytes (15.25GiB) |
| Rendered migration/layout jobs | 75m | 100663296 bytes (96MiB) |
| Existing pre-app-DB foundation, observed | 5250m | approximately 6.09GiB |

Thus full steady CPU requests would reach approximately 19250m, while the
current three nodes expose only 9000m allocatable CPU in total. Summing requests
does not prove a workload's placement or performance; it does prove this
configuration is too small without lowering declared requests.

The rendered Deployment strategies permit one unavailable replica. Flow and
HeteroCloud use maxSurge 0; Flash and Syouyu use maxSurge 1. This inspection did
not find the zero-unavailable/hard-anti-affinity deadlock considered during
review, but it is not a runtime rollout or availability test.

## Prepared Resize

`capacity_resize.py` prepares XML for **8 vCPU / 10240MiB per DEV guest** only.
It preserves all non-capacity XML, rejects foreign identities or unfamiliar
memory/topology settings, and performs no commands or writes. It is not a
deployment helper or authorization to restart a guest.

The prospective static budget is 40 VM vCPUs including Vercel. Configured VM
memory would total 46GiB; including the unchanged 24GiB host reserve gives
70GiB against approximately 78.26GiB physical RAM. This is only a static check.
Fresh available memory, outstanding allocations, other host workloads and
guest/database health must be admitted immediately before any change.

Changing the current maximums requires a separately approved DEV rolling
restart. Approval was requested; no restart or resize has been performed.
Do not touch production VMs or user Flash containers. The eventual operation
must preserve the existing provisioner journal and disks, update only validated
resource hashes, handle one guest at a time and verify all four database
clusters and the identity service before proceeding to another guest.

## Approved Execution: 2026-09-11

The user approved proceeding with the DEV-only rolling capacity change.
`scripts/resize-dev-capacity.py` now implements one-guest admission and execution
using the original provisioner's lock, file/resource ownership checks and firewall
guard. It leaves the bootstrap profile hash and disks unchanged; reviewed capacity
definitions and completion records are appended to the existing journal. Pending
operations are not automatically adopted or cleared after an error.

Fresh host inspection reported104 logical CPUs,82061076KiB total memory and
57367668KiB available memory. Other domain `vercel-research` remains untouched.
The operation requests graceful guest `systemctl poweroff --no-block`, pins the
machine ID and pre-operation boot ID, waits for shutdown, starts only the selected
domain and verifies a new boot,8 CPUs, expanded memory and mounted app storage.
All three Kubernetes nodes, all four three-instance DB clusters and the complete
three-replica Keycloak rollout must be ready before continuing.

DEV2 completed first:8 CPUs,10182476KiB guest MemTotal, all DBs and identity ready.
Its initial ACPI-based runner needed intervention: a guest poweroff request raced
with restart, leaving the expanded VM stopped. After checking pending intent,
definition hashes, ownership and firewall guards, the same selected VM was started
again and the existing runner completed. No disk or journal reset occurred.
The revised runner avoids mixed ACPI/guest requests and validates boot identity.

During this restart the identity DB elected a new primary and Keycloak temporarily
lost readiness; it recovered before the subsequent JDBC timeout change was applied.
Do not attribute that recovery to the later change or claim uninterrupted HA.
The DEV JDBC configuration now bounds connection/read waits while retaining
verify-full TLS. Its rollout is a prerequisite for continuing DEV3 and DEV1.

Current reviewed execution bundle:
`/opt/heteronetwork-dev-capacity-e3bc8132`, archive SHA256
`e3bc813240f8cd8f43f1d4d8706cb9853fc8a32d10d5ebc45f058dc290661664`.
DEV3/DEV1 completion must be recorded separately after actual verification.
