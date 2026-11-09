# HeteroCloud OIDC callback unavailable during storage contention

On 2026-11-09 at 08:52 UTC, the HeteroCloud API logged an OIDC discovery
failure with upstream HTTP 503 after its bounded retries. Users could reach the
sign-in page but could receive `identity_provider_unavailable` at the callback.
The callback URL and its one-time authorization code are intentionally excluded
from this report and from the verification logs.

The assigned identity replicas were not independent of the control plane's
database and storage. PostgreSQL and control-plane requests experienced
latency while Longhorn volumes were rebuilding. The identity placement client
could not consistently renew its server-issued 45-second lease and stopped the
local replica when that lease expired. It started again after a successful
reconciliation. The two active replica hosts both showed this behavior, so
their interruptions could overlap. The stopped `uc-k8sp4` is excluded; its
stale pod readiness is not evidence of an available identity replica. This
follows the same failure chain described in the
[November 7 incident](2026-11-07-identity-postgres-latency.md). It is not yet
proven that rebuild activity alone caused the database latency or that all
replica failures have the same initiating cause.

## Actions and verification

- Longhorn's per-node concurrent replica rebuild limit was changed from 5 to
  1 through Terraform and Argo CD. The live setting was verified as 1. This
  bounds future rebuild scheduling and may slow restoration of redundancy;
  already running rebuilds continue. Volume replica counts and existing data
  were not changed. PostgreSQL synchronous replication remains enabled.
- The Argo application was added to the published master-only bundle and its
  workflow path filters, so subsequent IaC reconciliation retains the setting.
- At approximately 09:12 UTC, two separate fresh Chromium sessions completed
  the production OIDC flow: the callback returned HTTP 303, the authenticated
  session returned HTTP 200, and logout returned HTTP 204 in each session.
  A uniquely named temporary identity and its newly created HeteroCloud user
  and organization were removed after safety checks. This is a point-in-time
  result, not proof that the intermittent failure is fixed.
- The independently triggered [VPN/browser acceptance run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42590756897)
  failed while configuring its dedicated identity; it must not be reported as
  passing. The [isolated storage heartbeat test](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42590756830)
  passed, but does not test this OIDC or Longhorn failure chain.
- A read-only Longhorn inventory during this incident showed 12 attached
  degraded volumes and four detached faulted volumes. Some attached volumes
  previously had only one read/write replica; recoverability of the detached
  volumes has not been established. At this point in time no Longhorn `Backup`
  objects were listed. That inventory does not establish whether backup data
  exists in any external store or whether it can be restored.
- A retry failure was found in the control-plane lease protocol: a timed-out
  request could commit, after which an identical retry through another endpoint
  was rejected as a duplicate generation. Idempotent retries now preserve the
  original expiry while changed, stale, and expired generations are rejected.
  Both active control-plane hosts were upgraded serially to the verified
  binary. The [retry tests](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42596808210)
  and a subsequent [real VPN/Chromium acceptance run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42598578880)
  passed. This fixes a demonstrated failure mode; the incident evidence does
  not establish how frequently it caused the observed outages.
- In a [disposable two-worker VM cluster](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42595524607),
  an attached single-copy volume was preserved while Longhorn managers were
  upgraded from 1.12.1 to 1.12.2, the second copy was rebuilt, and the volume
  engine was upgraded. All 308 HTTP probes succeeded. This test does not
  establish that production data is recoverable or make the upgrade reversible.
- A later read-only inventory still found 12 attached degraded volumes and
  four detached faulted volumes. Several desired three copies while only two
  storage workers were eligible, and multiple attached volumes had just one
  read/write replica. A scoped independent backup destination and an additional
  eligible worker remain necessary; the dedicated control-plane hosts and the
  administratively excluded worker have not been reassigned.
- The identity-placement agent on `ichikawap1` subsequently showed local
  control-plane timeouts before the 45-second lease expired. Both actual
  control-plane peers accepted the node's scoped credential. The IaC-managed
  agent now tries its configured private peer endpoints before the local agent
  gateway, without sending its local-only credential to remote peers. This is
  a failover mitigation, not removal of the shared database dependency.
- Two later live VPN/browser runs failed: one could not finish identity setup,
  while another exceeded the Grafana screen deadline. A subsequent run failed
  convergence of the `uc-k8sp1` console route, then
  [run 42608949533](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42608949533)
  completed with a real WireGuard client and authenticated Chromium. One
  successful run does not prove that intermittent gateway convergence is fixed.
  The verifier now identifies the health, DNS and UI subchecks separately on
  another convergence failure.
- Grafana's lightweight health API could return promptly while its login UI
  took more than three seconds. Its Kubernetes readiness probe now checks the
  actual login page; liveness still uses the lightweight health API. A
  [disposable Kubernetes test](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flow/actions/runs/42608332247)
  verified removal and readdition of a slow endpoint. The change was observed
  in production, including temporary exclusion of a slow `ichikawap1` replica.
  The underlying UI latency has not been conclusively attributed.
- An unrelated Kubernetes API write timed out on etcd. The explicitly stopped
  `uc-k8sp4` was still one of six voting etcd members. The other five reported
  one leader and no errors. A private etcd snapshot was created, restored into
  a separate data directory, copied to the IaC workspace and checked against
  the source SHA-256. Terraform then retired the exact stopped voter with guards
  for node identity, age of unavailability, backup, and health of all five
  surviving members. The five remaining voters were healthy after removal;
  quorum fell from four to three. This snapshot is not an independently
  verified offsite backup, and its restored directory was not started as a
  production cluster. A causal link between this etcd timeout and the original
  OIDC error has not been established.
- Network counters provided evidence of continuing receive loss. On
  `uc-k8sp5` the physical interface accumulated approximately 496 missed
  packets and 26 dropped packets over a ten-second sample while its average
  receive rate was well below the link's nominal 1 Gbit/s. On `ichikawap1`,
  the physical interface's receive FIFO error counter increased by 45 in five
  seconds; CRC and frame error counters were zero. A short VPN ping sample
  also showed one lost packet out of eight. These observations do not by
  themselves prove the cause of the original identity incident.
- The receive rings were 256/4096 descriptors on the `igb` NIC and 151/4078
  on the `bnx2x` NIC. Both drivers reload or stop an active interface when
  ring parameters change ([Linux igb implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/net/ethernet/intel/igb/igb_ethtool.c),
  [Linux bnx2x implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/net/ethernet/broadcom/bnx2x/bnx2x_ethtool.c)).
  The setting was not changed during this incident because multiple production
  volumes still have only one known read/write replica and an independently
  restorable backup has not been established. Prometheus now alerts separately
  on sustained node receive errors, receive drops and missing kubelet metrics;
  explicitly stopped nodes are removed from these scrape targets.
- After the Flash cost release was rolled out, all API, owner and worker
  deployments had two updated, available replicas and Argo CD was Healthy
  and Synced. The new unauthenticated budget mutation endpoint returned 401.
  [Live VPN/Chromium run 42613051961](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42613051961)
  passed, but the two preceding runs failed on a slow Grafana endpoint and on
  a DNS timeout to `ichikawap1`. Public API monitoring recorded two timeouts
  during 150 probes while rolling out, and one timeout during 30 later probes.
  These results confirm that network and service latency remain intermittent.

## Remaining storage risk

[Longhorn 1.12.2](https://github.com/longhorn/longhorn/releases/tag/v1.12.2)
was released on November 9 and includes the backported fix for the rebuild
state issue previously investigated, as well as fixes for other v1 rebuild
problems, including a possible acknowledged-write loss during certain
concurrent unaligned writes. The running Longhorn manager and engine remain on
1.12.1. These upstream defects are relevant risks, not proof that this cluster
has suffered data corruption or that upgrading alone will eliminate the
observed failure.

The 1.12.2 official chart was rendered and linted locally using the current
values; it would change the manager, driver, UI, CRDs and other resources. This
is not a production upgrade test. Upstream requires volume backups before an
upgrade and does not support downgrading after a successful upgrade. Since
independently restorable backups are not established and multiple volumes are
degraded, the chart revision was not changed and Argo CD was not allowed to
perform an irreversible production upgrade during diagnosis. Verify backups
and restores, assess the sole-copy volumes, and validate an upgrade and engine
rollout in an isolated environment before scheduling the production update.
Consult the [upstream upgrade procedure](https://longhorn.io/docs/1.12.2/deploy/upgrade/longhorn-manager/)
and [upgrade restrictions](https://longhorn.io/docs/1.12.2/deploy/upgrade/).

The incident remains open until storage redundancy, independent recoverability,
database latency and identity behavior under a recurring failure have been
verified. The rebuild limit is a mitigation and does not itself repair the
degraded volumes, establish data integrity, or remove the shared failure domain.
