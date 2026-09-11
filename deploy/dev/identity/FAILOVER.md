# DEV Identity Recovery

## Timeout Override

Keycloak 26.7.3 does not retain the initial JDBC URL `socketTimeout` as a
connection-wide upper bound. Its
[connection acquire interceptor](https://github.com/keycloak/keycloak/blob/26.7.3/quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/configuration/UpdateSocketTimeoutOnConnectionAcquireInterceptor.java)
sets a network timeout from the current transaction limit, falling back to
`transaction-default-timeout`. For PostgreSQL it adds one second. The
[default transaction limit](https://github.com/keycloak/keycloak/blob/26.7.3/quarkus/config-api/src/main/java/org/keycloak/config/TransactionOptions.java)
is five minutes. This explains why the previous URL-only 30-second setting
did not establish the intended wait bound. It is consistent with the observed
readiness and JDBC discovery threads waiting in TLS socket close after DB loss;
a single thread dump is not a measurement of the whole outage duration.

The DEV Deployment now explicitly sets `KC_TRANSACTION_DEFAULT_TIMEOUT=30s`.
This changes the transaction budget, not only health checks. Normal login and
administration transactions exceeding that budget can fail. Explicit per-task
transaction limits can still override it; migration/import/export setup timeout
is separate and remains unchanged. This is not a strict end-to-end 30-second
recovery guarantee: connection abort, discovery, queues and DB election can add
latency. TLS still uses `verify-full`; no trust or credential settings changed.

`configure-db-timeouts.py` checks the original DEV foundation helper hash and
actual cluster identity. It CAS-patches only the container environment, accepts
only known previous values and verifies the new environment on readback.
Repeated application is a no-op. Deployment rollout must be checked separately.

## Operational Probe

`probe-device-availability.py` runs on DEV1 as root and uses the same pinned
foundation guard. By default it changes no workloads. It repeatedly calls the
DEV realm's real device authorization endpoint with its public device client,
using the discovered ClusterIP but the correct TLS server name and trusted DEV
CA. Response credentials and user codes are never printed or persisted.
These calls create temporary device authorization requests in the DEV realm.

`--restart-primary` explicitly crash-restarts one DEV identity PostgreSQL pod,
not a VM, PVC, database cluster or application container. Before the mutation it
requires three ready DB instances and a completed three-replica Keycloak rollout
with the new timeout. It verifies the pod's Cluster owner UID, primary name and
immutable PostgreSQL image; the delete request includes UID/resourceVersion
preconditions. Intent and observations are fsynced to a root-only JSONL record
under `/var/lib/heteronetwork-dev-identity-probes/`. A process lock excludes
concurrent invocations of this probe. Failed baseline checks prevent disruption.

The final check requires DB and Keycloak readiness, replacement of the original
pod UID when requested, and five successful final requests. Individual request
failures are reported, not hidden by retries or treated as uninterrupted service.
The test may recover the same primary rather than elect a new one; both primary
names are recorded. A pod restart is not a VM-loss or physical-host-loss test.
Device authorization initiation is not browser login, token exchange, refresh,
or verification of existing user-session continuity.

The DEV environment remains entirely on one physical machine and must not be
described as physically highly available. Production promotion remains blocked
on the broader application and identity verification requirements.

## Observed Execution: 2026-09-11 UTC

The transaction timeout update was applied to DEV and repeated with `changed:
false`. All three pods of ReplicaSet `dev-keycloak-86b7f67fdc` became ready.
The source helper deployed under `/opt/heteronetwork-dev-db-timeouts-a0697d2f`
has SHA256 `a0697d2f20e4b196adf5f7e4901662077a664d4151b776c3e2a3300d82ff695b`.
No production resources or secrets were changed.

The real probe at `/opt/heteronetwork-dev-device-probe-00f7b03e` has SHA256
`00f7b03ec16cbaa99c32c2931d297fcf7e9b2867c70323c56ee7be8f0d8660b6`.
Both executions ended with exit status zero and final admission passed:

| Run | Measured Requests After Baseline | Failures | Maximum Request Time |
| --- | --- | --- | --- |
| Normal operation,30 seconds | 15 | 0 | 55ms |
| DB primary pod crash-restart,180 seconds | 88 | 2 | 91ms |

Each run also required five successful baseline requests before measurement or
disruption. Those baseline requests are not included in the table.
The DB restart was requested at05:37:51. Connection refused was observed at
05:38:09 and05:38:11; success resumed at05:38:13 and continued through05:40:50.
Approximately two-second sampling does not establish the exact outage duration;
four seconds between first observed failure and next success is not zero downtime.

The primary changed from `dev-identity-postgres-2` to `dev-identity-postgres-1`.
The original pod UID was replaced. All three DB instances and all three updated
Keycloak replicas were ready at final admission. No manual Keycloak recovery
or additional workload restart was used. Local focused tests passed: two
Keycloak manifest contract cases and three response/redaction probe cases.

Root-only records on DEV1:

- `7f365134-79de-4c89-b9c6-184c737f1777.jsonl` (normal)
- `29d55787-c40f-4e9c-bf67-fe757c1bad11.jsonl` (DB restart)

This was not the same fault as the earlier whole-VM restart, so it does not
prove that whole-VM recovery improved from minutes to seconds. Browser login,
token exchange/refresh, existing sessions, VM loss and sustained load still need
separate verification. No production promotion followed this test.
