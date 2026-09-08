# Control Plane Recovery, 2026-09-08

## Observed State

At 02:57 UTC, uc-k8sp1 (10.250.0.4) and uc-k8sp2 (10.250.0.5) were
NotReady. SSH over the VPN, Tailscale, and public addresses failed. Kubernetes
node-proxy health requests also timed out. Physical or hypervisor console access
is required to establish their current host state; neither was force-reset.

The remaining etcd voters (10.250.0.8, 10.250.0.10, 10.250.0.6) responded with
leader 10.250.0.8 and term 4115. This is three of five voters: quorum remains,
but another voter loss would prevent consensus. Endpoint status alone does not
establish application availability or successful failover.

uc-k8sp2 previously reported an unhealthy PLEG and unavailable container runtime.
Healthy-node logs also contained API timeouts and etcd overload responses.
These observations do not establish the original cause of the node failures.

Both failed nodes have approximately 4 GiB RAM. Several management containers
had no memory requests, and observed etcd memory exceeded its 512 MiB request.
Under-reservation is confirmed; an OOM kill is not confirmed without host logs.

## Applied Changes

- Cordoned uc-k8sp1 and uc-k8sp2 to prevent new assignments during Ready flaps.
  No drain, force deletion, or etcd membership change was performed.
- Replaced the containerd version-only recovery probe with CRI RuntimeReady,
  ListPodSandbox, and ListContainers checks. Retained the healthy-kubelet guard,
  boot grace, and six-failure threshold. NetworkReady alone does not trigger a
  runtime restart. Missing cri-tools produces a warning without blocking API
  backend reconciliation.
- Installed cri-tools and the updated node script on ichikawap1 only. The live
  CRI probe passed. This is not a completed fleet rollout.
- Focused runtime-probe smoke checks passed, including failed list operations,
  invalid status, and timeouts.

The escape Pod retained UID 08942b6b-7a5d-408d-9a88-16acfbe24b40, phase Running,
and zero container restarts. Tenant workload templates were not changed.

## Staged Work And Recovery Requirements

Argo and Harbor resource-request edits remain local and unapplied. Do not roll
the remaining healthy quorum services while two voters are unavailable.
Flash commit e56e628 records status-field clearing and resourceVersion conflict
protection; it has not been released or deployed as part of this recovery.

Use physical/hypervisor consoles to inspect runtime, kernel, disk and network
logs on the two failed nodes. Restore their management connectivity before
distributing the CRI probe there. Do not replace etcd membership merely because
SSH is unavailable. After recovery, verify quorum health, runtime operations,
node readiness and resource capacity before uncordoning nodes. Apply resource
reservations with observed rollouts, then repeat the provider Web Shell preflight.

Full HA recovery and further failure-injection tests remain pending.
