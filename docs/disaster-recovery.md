# Control-plane recovery sets

`scripts/control_plane_dr.py` can stream explicitly configured recovery sources
into a private S3-compatible restic repository. Restic encrypts the data before
upload. Each source is read back and compared with its original SHA-256 and byte
count before the recovery manifest is saved. A failed source or readback cannot
produce a successful recovery-set result. Restore requires an explicit manifest
snapshot and an empty, owner-only directory; it never replaces a running cluster.

This is the transport and verification layer, **not an automated complete
cluster recovery**. PostgreSQL and etcd source programs are included, but they
are not installed or scheduled. Secret Manager, Flash, Registry and Syouyu
sources are not supplied yet. It does not provision a destination or restore
live systems. Data-level restore and
cross-component consistency still need separate acceptance tests. A manifest's
`required_components_present` value says only that the six expected source
names exist; it does not prove those sources contain every database or object.
Do not treat it as proof of site disaster recovery.

## Configuration and trust

Create a dedicated private bucket in an independent failure domain. A recovery
configuration and its parent directory must be owned by the invoking user; the
configuration and password files must have mode `0600`. Source programs are
absolute paths to owner-only executable files and must exit nonzero on failure.
They receive a minimal environment, not S3 or restic credentials. Configure
them to produce consistent, bounded snapshots to stdout without putting secrets
in process arguments or logs. For example:

```json
{
  "repository": "s3:https://s3.example.net/private-bucket/heterocloud-control-plane",
  "password_file": "/secure/heterocloud-dr/repository-password",
  "timeout_seconds": 3600,
  "max_component_bytes": 42949672960,
  "max_total_bytes": 85899345920,
  "sources": [
    {"name": "postgres", "executable": "/secure/heterocloud-dr/sources/postgres"}
  ]
}
```

Provide S3 authentication to restic using a restricted AWS shared credentials
file or supported short-lived AWS credentials. Never place credentials in the
repository URL, Git, command arguments, reports or chat. Protect the repository
password independently of the cluster and the destination credentials; losing it
makes encrypted backups unrecoverable. Secret Manager's own snapshot identity
and threshold unseal shares have separate recovery requirements and are not
included by this transport automatically.

The byte limits constrain each backup run, not total S3 expenditure. A bucket
quota, retention policy and external cost alert are still required. Do not
automatically delete or prune prior recovery points until independent restore
has been verified and retention has been reviewed.

Initialize the dedicated empty restic repository separately using protected
`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`, and S3 credentials. Then run:

```sh
python3 scripts/control_plane_dr.py backup --config /secure/heterocloud-dr/config.json
python3 scripts/control_plane_dr.py verify --config /secure/heterocloud-dr/config.json --snapshot SNAPSHOT_ID
install -d -m 0700 /secure/heterocloud-dr/restore
python3 scripts/control_plane_dr.py restore --config /secure/heterocloud-dr/config.json --snapshot SNAPSHOT_ID --target /secure/heterocloud-dr/restore
```

The explicit snapshot ID is the manifest ID returned by the completed backup,
not a component snapshot or `latest`. The restore directory will contain
sensitive plaintext and must be on protected storage. Verify the restored
PostgreSQL and other applications in an isolated environment before using any
data for a real recovery. Original source programs are not required on the
recovery host; a recovery config can omit `sources`.

`--require-complete` rejects a source list missing any of `postgres`, `etcd`,
`secret-manager`, `flash-catalog`, `registry`, or `syouyu`. This is a source
inventory guard only: it cannot validate application consistency or physical
failure-domain separation. Separate repositories may be needed when different
data sets have different retention, authority and recovery requirements.

## Included source programs

`control_plane_dr_postgres_source.py` streams a `pg_basebackup` tar containing
the physical data and WAL needed to start that backup. It checks the server
identity and role before and after the stream, requires a matching PostgreSQL
major version, and rejects extra tablespaces. Standby backups are opt-in and
require a recent streaming receiver with bounded replay lag. The `fetch` WAL
method fails if required WAL is recycled before collection. It does not provide
continuous WAL archiving or point-in-time recovery, and a PostgreSQL cluster
on a different server needs a separate source.

`control_plane_dr_etcd_source.py` checks the local TLS endpoint and cluster
identity, writes the snapshot only to a private `noswap` tmpfs, verifies its
revision, and streams it for encryption. The host must provision that tmpfs and
install trusted, compatible etcd tools before enabling a schedule. These
sources require individually protected configuration and credentials. Never
point the snapshot tooling at a live database during recovery.

## Verification

The unit suite uses real restic against a disposable local repository and tests
failure, size limits, encryption, readback, refusal to overwrite existing files,
and cleanup of failed restores. `control_plane_dr_postgres_e2e.py` creates two
independent temporary PostgreSQL servers, restores logical and physical backups,
and checks a fresh marker. `control_plane_dr_etcd_e2e.py` starts independent
mutual-TLS etcd servers and restores a snapshot to the second one. The etcd
source requires a private `tmpfs` mount with `noswap`; it refuses an ordinary
temporary directory even when `/proc/swaps` reports no swap, since sandboxes
can hide the host's swap configuration. `control_plane_dr_s3_e2e.py` creates and removes a small,
scoped Syouyu fixture bucket and tests the actual HTTPS S3 path. Its fixture is
in the same cluster and therefore does **not** verify an offsite failure domain.
None of these tests uses customer data.
