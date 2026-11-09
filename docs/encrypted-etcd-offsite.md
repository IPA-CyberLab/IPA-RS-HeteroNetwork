# Encrypted etcd snapshot transfer

`scripts/encrypted-etcd-snapshot.py` encrypts a previously captured etcd
snapshot with a 32-byte key and AES-256-GCM. It authenticates the envelope,
and restore also checks the expected plaintext SHA-256. Python's `cryptography`
package and a separately authenticated object-storage client are required.

Generate a key in a private directory with `keygen --key KEY_FILE`. Preserve a
secure copy of the key outside both the cluster and the backup bucket; losing
the key makes all snapshots encrypted with it unrecoverable. Never commit it or
print it in CI logs. The key file must be owned by the invoking user and
unreadable to other users.

The 2026-11-09 key also has an encrypted copy in the GitHub Actions environment
`heteronet-disaster-recovery`; that environment only accepts the `master` branch.
The `Verify etcd backup key custody` workflow compares its key with an expected
SHA-256 fingerprint without revealing the key. A future recovery workflow must
use that environment and deliver recovered material only to an authorized
private destination. GitHub environment access depends on maintaining the
repository and its security settings.

For a private Cloudflare R2 bucket, compress the snapshot and save only the
encrypted stream to a temporary file. Preserve both the original snapshot
SHA-256 and the compressed plaintext SHA-256 printed by the encryption command:

```sh
set -o pipefail
umask 077
gzip -1 -n -c SNAPSHOT | \
  python3 scripts/encrypted-etcd-snapshot.py encrypt --key KEY_FILE --input - \
    --bytes-per-second 2097152 > ENCRYPTED_FILE
wrangler r2 object put BUCKET/OBJECT --remote --file ENCRYPTED_FILE --content-type application/octet-stream
```

Verify the stored object and its compressed SHA-256 with:

```sh
set -o pipefail
wrangler r2 object get BUCKET/OBJECT --remote --pipe | \
  python3 scripts/encrypted-etcd-snapshot.py verify --key KEY_FILE --sha256 COMPRESSED_SHA256 \
    --bytes-per-second 2097152
```

For recovery, replace `verify` with `restore --output NEW_GZIP_PATH` and use
the compressed SHA-256. Restore creates an owner-only file and refuses to
overwrite an existing path. It publishes the compressed file only after both
the GCM tag and checksum pass. Decompress it into a new private file and verify
its SHA-256 against the original snapshot hash before following the etcd
recovery runbook. Validating the envelope is not a substitute for testing a
cluster restore. A single manual export does not provide scheduled backups or
protect the separate PostgreSQL and Flash volumes.

Do not assume a successful exit from a large `wrangler r2 object put --pipe`
means the object exists: one large piped upload exited without saving an
object. File uploads must also be verified by reading the object back.
