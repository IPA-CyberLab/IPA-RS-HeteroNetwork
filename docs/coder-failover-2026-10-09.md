# Coder outage and failover recovery, 2026-10-09

Coder returned HTTP 503 after `ichikawap1` stopped reporting to Kubernetes.
Its last node heartbeat was 08:33:50 UTC. SSH, its public HTTPS origin, and
the VPN endpoint were also unavailable. The node restarted at 11:26 UTC;
the previous boot's journal ends around 08:35 UTC. The host interruption's
underlying cause is not established. The preceding Flow API OOM records were
`CONSTRAINT_MEMCG` events inside individual container limits; they do not prove
a host-wide OOM.

## Why automatic relocation failed

Kubernetes deleted the unavailable workload Pods and created replacements.
Those replacements could not schedule because `ichikawap1` was the only node
with an installed, advertised `gvisor` runtime. Both surviving workers lacked
runsc. The dedicated Secret Manager masters correctly rejected workloads.
The weekly allowances remained at their raised maximum values throughout this
incident; CPU, memory, and GPU quota exhaustion were false.

The Coder control plane and PostgreSQL already had usable disk replicas on
`uc-k8sp4` and `uc-k8sp5`. Reverse and HyperEVM each had only one actual disk
replica, on the unavailable node, despite a desired replica count of three.
Their volumes reported `ReplicaSchedulingFailure: insufficient storage`.
The workers had physical free space, but nominal reserved volume capacity
exceeded the 100% allocation ceiling. A desired replica count was incorrectly
treated as evidence of redundancy.

## Applied changes

- Terraform now manages gVisor on `uc-k8sp4` and `uc-k8sp5`, through the pinned
  Flash installer and the authenticated `20261005.0` package. A bounded,
  nonroot, tokenless probe must actually execute under runsc before the worker
  gets the runtime scheduling label. Existing healthy application tasks must
  remain running through configuration changes.
- Worker memory reservations default to 3 GiB for native services and 1 GiB
  for Kubernetes. The previous generated 512 MiB command-line defaults, which
  overrode the config file, were corrected. Advertised memory capacity fell
  by 3 GiB on each worker while their CPU capacity remained unchanged.
- Argo CD owns the storage scheduling policy: 200% nominal allocation,
  15% minimum physical free space, and hard node anti-affinity. The physical
  free-space guard and host disk reservations remain in effect. The measured
  additional data needed for the attached degraded volumes was about 57 GiB.
  Replica reconstruction uses the existing volume data.
- Infrastructure CI now includes the runtime acceptance tests and triggers
  for changes to the runtime verifier and storage policy.

The host configuration was applied with Terraform targets limited to the two
runtime resources. A separate targeted publication updated the versioned
internal Git source. The storage policy Application reconciled to
`Synced/Healthy`; the live settings were read back as `200`, `15`, and `false`.

## Observed recovery and validation

The Coder control plane and database started on `uc-k8sp4` after runtime
acceptance. Their original PVCs and configuration were reused. Reverse and
HyperEVM resumed from their existing disks after `ichikawap1` returned; both
agents became `connected/ready` and both application health checks passed.
The deliberately stopped coconel workspace remains stopped.

Authenticated Chromium opened the workspace list three times: all document
and workspace API responses were 200, the table rendered, and no 502/503 was
observed across 371 requests. Observed page readiness was 2504, 1462, and
1221 milliseconds. Chromium also opened the actual editor workbench for
Reverse and HyperEVM: both returned 200, with no gateway errors across
42 requests. Editor readiness was 7496 and 6788 milliseconds; these are
editor load measurements, not the three-second management-console check.
Temporary verification credentials were revoked after each check.

Both workspaces now have three healthy replicas on three distinct workload
nodes: `ichikawap1`, `uc-k8sp4`, and `uc-k8sp5`. Reverse's new replicas became
healthy at 12:24:28 UTC and 12:33:43 UTC; HyperEVM's new replicas became healthy
at 12:18:27 UTC and 12:20:17 UTC. Both volumes report `healthy`. Completion is
verified from replica health, rather than the configured replica count.

During the physical outage, GitHub's actual VPN client joined successfully,
but the full gateway convergence check failed on `10.250.0.10`. Those failed
runs are retained as evidence of the outage, not described as passing tests.
The final infrastructure workflow runs again after the recovered topology.

Private receipts and browser screenshots are stored under
`/workspace/.heteronetwork-iac/coder-outage-20261009/`. They are not release
artifacts and contain no retained verification credentials.
