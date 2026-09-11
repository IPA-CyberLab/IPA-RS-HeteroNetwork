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
