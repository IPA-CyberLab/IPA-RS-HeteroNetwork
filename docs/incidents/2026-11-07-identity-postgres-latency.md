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
