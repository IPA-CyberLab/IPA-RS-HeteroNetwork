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
