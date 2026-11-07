# Identity availability during database and storage contention

On 2026-11-07 the live VPN/browser acceptance test failed because no assigned
identity replica was ready. External OIDC discovery alternated between HTTP 200
and 503. Two identity connectors were unready; the stopped `uc-k8sp4` node was
excluded and its stale connector status was not evidence of availability.

The PostgreSQL primary was `ichikawap1` and its only synchronous standby was
`uc-k8sp5`. The primary had high I/O pressure, many sessions waiting for
synchronous replication, and transaction/tuple lock waiters. Control-plane logs
showed commits lasting tens of seconds, while the identity placement client
allowed only two seconds per request. When placement renewals repeatedly
timed out, its 45-second assignment lease expired and the client stopped the
replica. A later successful renewal briefly started it again. Concurrently, a
degraded Coder workspace disk had a stalled Longhorn I/O device and repeated
replica rebuilds. These observations establish a contention and timeout failure
chain, but do not yet establish the initiating cause of the storage failures.

The `ichikawap1` host was also a declared and running PostgreSQL member, but
its bundle retained a proxy-only marker from an earlier role. This prevented
the identity reconciler from treating it as an eligible replica. At 07:18 UTC,
the operator cleared that marker after validating the bundle. The database
autopilot then applied topology revision 14 and restarted the PostgreSQL primary
at 07:19 UTC, causing a failover to `uc-k8sp5` and another identity interruption.
The checks did not account for that automatic reconciliation, so the marker
repair has been removed from the routine identity deployment. Future marker
changes require a separately reviewed database plan, including its effect on
the active primary. Do not infer data-loss status from service readiness alone.

The placement reconciler now allows a slower individual response within a
bounded total scan, resumes an interrupted scan at the next endpoint, and
checks the server's actual assignment expiry rather than extending a stale
response by a fresh local TTL. It still stops a replica when its lease expires;
it does not change PostgreSQL durability or copy credentials to other nodes.
The runtime is distributed serially via the Terraform-managed Ansible playbook
and can be reconciled from an exact master commit using the protected workflow.
Installing the script alone does not restart a database or user workload; the
existing timer runs the new version on its next reconciliation. This distinction
did not apply to the subsequently removed marker repair described above.

The shell acceptance suite exercises unavailable endpoints, resumed directory
scans, lease expiry and delayed responses. The live VPN/Chromium test passed on
retry when identity became available, but that retry alone does not prove the
intermittent incident is resolved. Monitor the actual script rollout, OIDC
availability, PostgreSQL replication latency and Longhorn rebuilds separately.
An additional independent worker/storage failure domain and an independently
verified backup are still required; neither exists merely because two API
replicas are running. The root cause of the repeated Longhorn replica failure
and the effect of workload I/O on control-plane storage remain under investigation.

At 08:20 UTC the affected workspace volume still had one read/write replica on
`ichikawap1` and one write-only rebuilding replica on `uc-k8sp5`. Longhorn
events show repeated file-sync connection resets and rebuild attempts. Both
storage nodes reported free space and a short host-to-host ICMP check did not
lose packets; neither observation proves the network or disks are healthy under
sustained rebuild load. No replica or user data was removed during diagnosis.
Across the cluster, eight attached volumes were degraded: seven had two
read/write replicas against a desired three, and the affected workspace had one
read/write and one rebuilding replica against a desired two. Four detached
Syouyu volumes were faulted; their recoverability was not established.

Storage robustness is now collected through a namespace-scoped read-only
Longhorn API role. Prometheus evaluates separate degraded, faulted, and
inventory-unavailable alerts; duplicate collectors are deduplicated. The live
collector reported the affected volume as degraded, and Prometheus fired the
corresponding alert after the configured delay. Prometheus and Grafana
were adjusted to the two actually available monitoring workers, rather than
claiming three-way redundancy while `uc-k8sp4` is excluded. Alert delivery to
an external receiver is not configured. These changes improve detection but do
not restore the missing replica or establish the cause of the connection resets.

## Subsequent storage investigation

At approximately 09:10–09:11 UTC the affected Longhorn v1.12.1 engine's
pre-rebuild snapshot purge exceeded the manager's 30-second engine poll
timeout. Manager logs then show a second rebuild starting while the first was
still active, an `already rebuilding` error, and removal of the write-only
replica. File-sync resets followed the removal; those resets do not establish
that the network initiated the failure. The pattern recurred while the volume
still had only one read/write copy. High I/O pressure was observed on
`ichikawap1`, but a causal link to the slow purge has not been established.

This is consistent with [Longhorn issue 13914](https://github.com/longhorn/longhorn/issues/13914)
and the upstream [manager fix](https://github.com/longhorn/longhorn-manager/pull/5323).
The fix was backported to the upstream v1.12 branch for a future v1.12.2
release. At investigation time that release was not available. The manager
change can be applied to v1.12.1 source, but it and the related engine fix have
not been validated together against this cluster; no custom storage image has
been deployed. The sole healthy replica must not be removed to force a rebuild.
Longhorn manager rollouts now use a maximum of one unavailable manager for
same-version patch changes. Full version upgrades require separate review of
the chart's upgrade guidance.

A later read-only inventory at about 09:55 UTC found five attached degraded
volumes with one `RW` replica: the Flash homes for the Coder `dYdx` and
`CKB-VM` workspaces, `coder-postgres`, and two Registry Redis volumes. Four
additional attached volumes were healthy according to Longhorn but explicitly
configured with only one replica. The inventory also showed five degraded
attached volumes with two `RW` replicas, two healthy attached volumes with
two, four detached faulted volumes and 37 detached volumes of unknown
robustness. Replica rebuilds continued and individual counts changed during
inspection; these numbers are a point-in-time observation. Both active
Longhorn disks reported schedulable with free space, which does not establish
that rebuilds or storage I/O are healthy. A new critical alert fires for any
attached volume with at most one observed `RW` replica, including deliberately
single-replica volumes; unavailable observations are reported separately.

## Overlay DNS and monitoring follow-up

The overlay DNS discovery deployment had one running controller and one pod
still assigned to the stopped `uc-k8sp4` node. Its blanket toleration allowed
the latter to remain there indefinitely. Its policy now selects the two active
workers and bounds not-ready and unreachable tolerations at 30 seconds; both
controllers became ready on separate active workers. The single-controller
state was a failover risk, but was not established as the cause of the DNS
timeouts in the live client test. A stricter separation policy keeps a
replacement pending while only one eligible node remains, so that recovery
restores the two controllers on separate nodes. An [isolated node-loss E2E](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42360502284)
paused a worker, verified DNS changes during the outage, and verified separate
placement and record removal after recovery. This exercises the controller in
a disposable kind cluster, not a production node shutdown.

Recent authenticated GitHub Actions VPN/browser runs did not all pass: one
timed out resolving Grafana, another exceeded the three-second Grafana HTTP
budget, and a later run failed while reconciling the dedicated test identity.
On `ichikawap1`, Grafana logged an interrupted settings lookup for the
three-second request. Twenty read-only `SELECT 1` queries through the same
database proxy averaged approximately 90 ms from that node versus approximately
2 ms from `uc-k8sp5`; repeated inter-node probes also showed variable latency.
These measurements identify a performance difference, not a proven root cause
for every failed test. The [next real VPN and authenticated browser run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42360502185)
passed within the existing deadlines, but one passing run does not establish
that the intermittent failures have been eliminated. The deadline is unchanged.
