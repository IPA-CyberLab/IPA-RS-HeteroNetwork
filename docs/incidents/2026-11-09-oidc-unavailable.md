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
  quorum fell from four to three. A causal link between this etcd timeout and
  the original OIDC error has not been established.
- That etcd snapshot was compressed, encrypted with AES-256-GCM and stored in
  the independent R2 control-plane recovery bucket. The object was downloaded,
  authenticated and decompressed; its original SHA-256 matched the snapshot
  previously restored into a separate data directory. The protected recovery
  key was also matched against an environment-restricted GitHub Actions secret.
  The recovered directory was not started as a production cluster. This is a
  single etcd recovery point, not a scheduled backup or a backup of PostgreSQL,
  Flash, Registry, Secret Manager, or Syouyu data.
- Network counters provided evidence of continuing receive loss. On
  `uc-k8sp5` the physical interface accumulated approximately 496 missed
  packets and 26 dropped packets over a ten-second sample while its average
  receive rate was well below the link's nominal 1 Gbit/s. On `ichikawap1`,
  the physical interface's receive FIFO error counter increased by 45 in five
  seconds; CRC and frame error counters were zero. A short VPN ping sample
  also showed one lost packet out of eight. These observations do not by
  themselves prove the cause of the original identity incident.
- On `uc-k8sp5`, received traffic was concentrated on an `igb` queue whose
  CPU reached about 100% utilization. In a reversible comparison, the first
  15-second baseline saw 760 missed receives across 53,294 received packets;
  distributing receive processing across other online CPUs saw 12 and then
  zero missed receives during consecutive 15-second samples of 55,284 and
  54,858 packets. After reverting, 3,407 receives were missed in 15 seconds
  with 53,227 received packets. The samples are not a controlled workload or
  proof that all user-facing errors have been resolved. A second 15-second
  sample after the final Terraform/Ansible apply saw zero missed receives.
  The applied setting is limited to the verified `uc-k8sp5` NIC and CPU
  topology, is configured to reassert at boot and NIC add, and does not reset
  the NIC or change IRQ affinity. It refuses a different existing RPS policy.
  On `ichikawap1`, a later reversible comparison reduced the CPU load on the
  two busy receive queues; 80 FIFO errors occurred after reverting, versus
  zero in the two intervening 20-second trials. The production setting was
  subsequently applied through Terraform and Ansible only to those two
  verified queues and CPUs in the NIC's NUMA node. The short comparisons do
  not establish a durable error-rate improvement. Dropped-packet counters and
  end-to-end latency still need monitoring.
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
  passed, but other runs failed on a slow Grafana endpoint and on a DNS timeout
  to `ichikawap1`; [run 42616784695](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42616784695)
  subsequently exceeded the Grafana three-second deadline. Public API monitoring recorded two timeouts
  during 150 probes while rolling out, and one timeout during 30 later probes.
  These results confirm that network and service latency remain intermittent.
- At 12:49:54 UTC the PostgreSQL primary `db-b` demoted itself after its DCS
  requests timed out and a TLS handshake to the other live database member
  timed out during the configured failsafe check. PostgreSQL connections were
  terminated; the same member recovered its lock and promoted itself at
  12:50:18. Both Keycloak replicas subsequently stopped after their placement
  leases expired and restarted at 12:50:55 and 12:51:08. The PostgreSQL DCS
  is a separate etcd cluster from Kubernetes: its three voters still include
  the explicitly stopped `uc-k8sp4` (`db-e`), leaving both surviving voters
  necessary for quorum. The earlier Kubernetes etcd retirement did not change
  this separate membership. A voter replacement requires an independent,
  suitable host; the three Secret Manager custodians must remain dedicated.
- Both live database hosts now expose only aggregate local DCS health to the
  approved monitoring hosts over the private overlay. The exporter returns an
  error instead of a healthy zero when the local metrics source is unavailable;
  a request from another overlay node was rejected with HTTP 403. Each live
  voter currently reports just one active peer. Prometheus rules warn about
  missing peer connectivity, missing metrics, absent leaders and repeated
  elections. These alerts do not add a voter or restore failure tolerance.
- A separate availability feedback loop was found in the public-service
  supervisor: a transient database-proxy failure demoted the local control
  plane and also restarted the VPN Agent. The reviewed change stops the local
  control plane while retaining the existing agent and its configuration,
  then restores the control plane after database recovery. Missing or invalid
  credentials still fail closed. Both hosts received their compatible
  IaC-managed supervisor changes. [Fault-injection tests](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42625652576)
  exercised outage, recovery, and a fresh boot without credentials in an
  isolated environment; no production database failure was injected.
- The PostgreSQL DCS snapshot captured at 12:57 UTC was restored to a
  separate, unstarted data directory. Its encrypted, compressed R2 copy was
  downloaded, authenticated and decompressed, and its SHA-256 matched the
  original. The recovery manifest records the protected etcd-key reference.
  This protects DCS state only; it does not contain the PostgreSQL databases.
- A [subsequent VPN/browser run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42620011540)
  failed during identity preparation, and [another run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42620318171)
  exceeded the Grafana three-second budget. On `ichikawap1` Grafana's local
  login response was repeatedly about 1.6–2.4 seconds while `uc-k8sp5` was
  around 60–75 ms. Its readiness budget was tightened to one second to leave
  room for VPN transit. Production DNS subsequently retained only the fast
  replica. The slow replica can return after recovery, but until then Grafana
  has only one ready endpoint and the application is degraded. Both current
  Grafana pods later reported Ready; that point-in-time observation does not
  establish stable response times or continued two-replica availability.
- [VPN/browser run 42626737541](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42626737541)
  established a WireGuard handshake but failed because the `ichikawap1`
  console check did not converge in time. Its disposable client could not be
  confirmed removed by the verifier. Its specific registration was still
  present on later inspection. The admin node list excludes client-role
  records, so absence from that list was not proof of removal. The exact
  client's ID, address and role were checked in the store, the [admin API
  removed it](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42629572327),
  and a read-only database query confirmed the record was absent. The verifier's
  cleanup path now also runs after a sponsorship timeout or a pre-tunnel
  failure, and can retry through alternative declared gateways.
- After both receive-steering policies were applied, [VPN/browser run 42629826604](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42629826604)
  established WireGuard, converged the console routes, and confirmed removal of
  its temporary client. It still failed when a Prometheus DNS query to
  `ichikawap1` timed out. Later direct samples from each worker to itself and
  its peer each completed 20 out of 20 DNS queries. These are not equivalent
  to the hosted runner's VPN path and do not establish why its query timed out.
- [VPN/browser run 42630592496](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42630592496)
  also removed its test client, but Grafana exceeded the three-second page
  retrieval deadline. A later 20-second NIC sample counted 48 receive drops
  on `uc-k8sp5`, although no missed receives were counted; `ichikawap1`
  counted neither receive drops nor receive errors in that interval. These
  samples do not identify the cause of the runner's Grafana delay. Failure
  reports now include the endpoint and elapsed time when that deadline is
  exceeded; the three-second budget itself has not been relaxed.
- [VPN/browser run 42631202968](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42631202968)
  subsequently passed on an Actions VM with a real WireGuard tunnel and
  authenticated Chromium. Every tested console and monitoring page responded
  within three seconds, and the temporary client was removed. Initial route
  convergence took 16.8 seconds before those page checks. The cold-start VPN
  recovery test also passed. This successful sample does not negate the
  immediately preceding intermittent DNS and latency failures.

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
