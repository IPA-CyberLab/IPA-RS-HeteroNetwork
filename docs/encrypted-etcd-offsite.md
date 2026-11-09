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

For a private Cloudflare R2 bucket, a one-time transfer can stream ciphertext
without an unencrypted temporary file:

```sh
set -o pipefail
python3 scripts/encrypted-etcd-snapshot.py encrypt --key KEY_FILE --input SNAPSHOT \
  --bytes-per-second 2097152 | \
  wrangler r2 object put BUCKET/OBJECT --remote --pipe --content-type application/octet-stream
```

The plaintext SHA-256 from the encryption command must match the independently
recorded snapshot hash. Test the stored object with:

```sh
set -o pipefail
wrangler r2 object get BUCKET/OBJECT --remote --pipe | \
  python3 scripts/encrypted-etcd-snapshot.py verify --key KEY_FILE --sha256 SNAPSHOT_SHA256 \
    --bytes-per-second 2097152
```

For recovery, replace `verify` with `restore --output NEW_SNAPSHOT_PATH` and
use the same key and expected SHA-256. Restore creates an owner-only file and
refuses to overwrite an existing path. It publishes the plaintext file only
after both the GCM tag and checksum pass. Follow the etcd recovery runbook with
the recovered file; validating the envelope is not a substitute for testing a
cluster restore. A single manual export does not provide scheduled backups or
protect the separate PostgreSQL and Flash volumes.
