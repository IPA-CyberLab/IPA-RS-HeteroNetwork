# Flash operations: admission, deployment recovery and backups

HeteroCloud 0.1.110 and Flash 0.1.54 expose capacity diagnostics, revision history,
health-checked updates, rollback, scheduled backups and restore verification in
the API, CLI and console. Terraform and the Argo CD Applications pin the deployed
source commits and image digests. The workload helper remains pinned separately
so an operator upgrade does not restart existing tenant Pods.

## Capacity and failure visibility

Two capacity admission replicas share a reservation ledger. Before a new workload
can pull an image, admission checks eligible workers, CPU/memory/GPU reservations,
fresh node filesystem measurements, image expansion and the writable filesystem.
It keeps 25% or 10 GiB free, whichever is larger. New or expanded Longhorn volumes
must fit on distinct eligible storage nodes for all required replicas. The
control-plane-only nodes are excluded. Legacy thin volumes are not retroactively
reserved at their full provisioned size.

Snapshots are single-flight, paginated and cached for five seconds after refresh;
filesystem observations older than 90 seconds are rejected. The webhook bounds
concurrent requests. Missing measurements produce an explicit admission error,
not a fabricated zero. Capacity may change after a snapshot; admission does not
promise that every future write to an existing thin volume will fit.

Service diagnostics and tenant/owner notifications distinguish memory failure,
health-check failure, image errors, capacity shortage and network errors. Disk
warnings have 80/90/95% thresholds. Unknown usage stays unknown. Retired failed
Pods do not override a healthy replacement; actual serving replicas and allocated
resources remain visible while an unsuccessful desired revision is pending.

## Updates and rollback

The deployment policy selects `auto`, `rolling` or `recreate`, a 60–3600 second
deadline, automatic rollback and an optional TCP/HTTP health check. Stateful and
GPU services drain and restart. Explicitly stateless services use zero-unavailable
rolling updates with one surge replica. Sufficient surge capacity is required.
This provides restart-based recovery; it does not migrate a running process or
its in-memory state between machines.

The history records a healthy revision only after a current-generation replica
has actually become ready. A stopped service or one at zero replicas is not proof
of health. For scale-to-zero services, the failure deadline starts on activation,
not during idle time. Weekly quota exhaustion does not trigger rollback.

Automatic rollback requires the initiating principal to remain enabled and
authorized. Manual rollback is fenced by the expected current generation. Both
keep current IAM roles, environment/secret bindings, network/exposure settings and
data; disk sizes never shrink. Revision summaries omit historical environment
values and full workload specifications. An unsuccessful update keeps an already
serving workload where possible.

Examples, using an already configured CLI and endpoint:

```sh
heterocloud flash revisions SERVICE_ID
heterocloud flash events SERVICE_ID
heterocloud flash rollback SERVICE_ID --generation GOOD_GENERATION --expected-generation CURRENT_GENERATION
```

## Scheduled backups and restore verification

Policies are opt-in per service and have an interval, retention count and restore
verification option. Background workers claim due policies using database leases,
recheck the actor's current permissions and use idempotent backup requests. Edits
to a policy fence completion of earlier work. Retention affects scheduled backups
only. Manual backups are preserved. With verification enabled, the previous good
scheduled backup remains until a new backup has uploaded and passed verification.

```sh
heterocloud flash backup-policy get SERVICE_ID
heterocloud flash backup-policy set SERVICE_ID --file policy.json
heterocloud flash backup-policy run SERVICE_ID
heterocloud flash backups verify BACKUP_ID
```

`policy.json` example:

```json
{"enabled":true,"interval_seconds":86400,"retention_count":7,"verify_restore":true}
```

The primary private Syouyu bucket has a 40 GiB physical quota. Size policies to
that budget before enabling them on large services. This release does not turn
on scheduled backups for every existing service.

Two verifier controllers share one lease. A verifier restores into an independent
temporary volume on the explicitly tagged worker `uc-k8sp4`, waits for physical
restore completion and runs a trusted gVisor job with a read-only mount. It never
executes the restored application, mounts a service-account token or permits
network traffic. Sampling is bounded to 1024 files and 128 MiB total, up to 1 MiB
per file; a pass is a physical restore and sampled readability check, not a full
application recovery or exhaustive checksum of every file. The job, PVC, PV and
Longhorn volume must all disappear before verification is reported as passed.

## Independent external copies

**Production external export is disabled until independent S3 credentials are
configured and a recovery test passes.** The primary bucket is in this cluster;
it alone cannot recover a lost cluster or site.

The optional [R2 module](../deploy/terraform/flash-offsite-r2/README.md) creates a
private bucket with public r2.dev access disabled and destruction protection.
`configure-flash-offsite.py` reads credentials from an owned regular 0600 file,
writes a Kubernetes Secret without logging values, and saves the catalog key to
a protected recovery file before publishing the Secret. Keep that key outside
the cluster. Credentials and keys do not enter Terraform state or process
arguments. The source credential is read-only and scoped to one bucket.

The exporter verifies content hashes, signs catalogs with a separate HMAC key,
pins backups against concurrent deletion and bounds storage and transfer. It
retains seven catalogs and gives garbage collection a two-day grace period.
Recovery verifies hashes and writes only into an explicitly empty destination;
it refuses to overwrite an existing backup bucket. Transport uses HTTPS and
private S3 authorization. HMAC authenticates catalogs; it does not encrypt them.
Provider storage encryption and independent protection of the recovery key remain
necessary. Backup copies do not include the control-plane PostgreSQL database,
IAM or Secret Manager data; those require their own recovery plan.

## Native acceptance

Use `scripts/run_flash_operations_live_e2e.py` with an explicit `--endpoint`,
`--account-file`, `--cli`, `--kubectl`, `--kubeconfig`, pinned `--image`, `--report`,
`--inventory` and `--ssh-key`. It prompts privately for sudo only for the isolated
memory fault. The account must be a dedicated `heterocloud-e2e` test identity
owning exactly one test organization. Paths and results may be recorded; account
files, auth transcripts and screenshots remain private.

Scopes include `--admission-only`, `--rollout-only`, `--rolling-only`,
`--backups-only` and `--cold-start-only`. `--skip-admission` and
`--skip-cold-start` permit independent reruns. All mutations target new nonce-owned
fixtures. The memory test checks Pod UID, service nonce, node, gVisor runtime and
the existing 64 MiB limit before disabling swap only in that disposable cgroup.
It allocates at most 1 GiB and never changes the host's swap or other services.
Cleanup deletes only recorded fixture resources and revokes its CLI/browser
sessions. The empty dedicated project remains reusable.

`flash_capacity_live_e2e.py` exercises real large-inventory concurrent admission
inside a limited gVisor VM. `flash_offsite_s3_e2e.py` uses fresh private buckets to
test signed copy, source deletion and empty-bucket recovery. Its same-cluster S3
fixture validates the protocol, not independent-site durability. CI also runs
PostgreSQL concurrency/IAM tests, CLI tests and desktop/mobile Chromium tests.
Operator SSH keys and admin kubeconfigs are not uploaded for these native tests.

`flash_legacy_recovery_e2e.py` covers automatic CSI allocation and replacement of
an older ReplicaSet when the desired revision is invalid. Supply `--kubectl`,
`--kubeconfig`, `--report` and an immutable official Flash `--image` already
cached on every ready worker. It creates its own small Flash service and home,
checks the combined image/rootfs/home budget over repeated reconciliations,
then verifies that a cached legacy replacement retains a marker and the PVC
identity. The replacement must use `imagePullPolicy: Never`; an unknown uncached
digest is rejected in a server-side dry run. Cleanup fences its own claims and
volumes by nonce, UID and claim reference before removing them. This test never
evicts or rewrites an existing user workspace.

The [2026-10-20 acceptance record](verification/flash-operations-2026-10-20.md)
contains release references, measured results and remaining external setup.
