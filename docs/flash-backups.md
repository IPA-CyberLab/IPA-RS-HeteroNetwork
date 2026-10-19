# Flash disk backups: infrastructure and acceptance

Terraform manages `csi-snapshots` and the private backup-store Ansible playbook.
Snapshot CRDs and the snapshot-controller image are pinned in
`deploy/gitops/csi-snapshots/UPSTREAM.json`. Controllers run on workers, never the
control-plane-only nodes. CSI metadata CRDs are retained during Argo pruning.

`terraform_data.flash_backups` provisions one private Syouyu/Garage bucket,
limits its physical storage to 40 GiB, creates a key with read/write permission
only on that bucket, and stores it in `longhorn-system/flash-backup-store`.
The default Longhorn BackupTarget uses it, including pre-existing Flash volumes.
Reconciliation refuses to redirect a nonempty existing target or reuse a key
with unrelated/global privileges. Credentials are never written into Terraform
state, command arguments, Git or reports. The program passes its Kubernetes
Secret only through stdin and prints nonsecret status.

Enable `backups.snapshotClass: flash-disk-backup` in the Flash Application only
after the target and snapshot controllers are healthy. Source disks must use
Longhorn. The provider rejects local `type: snap` classes. See the HeteroCloud
repository's `docs/flash-backups.md` for user operations, IAM and limitations.

This bucket lives in the same cluster. This setup does not provide protection
against losing the cluster or site; that requires an independent S3 target and
recovery of CSI/etcd metadata. Never add an object-store lifecycle expiration
policy: Longhorn owns incremental block references and deletion.

## Reproducible storage test

```sh
python3 scripts/flash_backup_storage_e2e.py \
  --kubeconfig /path/to/admin.conf \
  --image ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:VERSION@sha256:DIGEST \
  --report /private/storage-e2e.json
```

It creates uniquely labelled, isolated gVisor fixtures, saves random files to a
real CSI/S3 backup, changes the source, deletes the source volume, restores a
different volume, waits for physical copy completion while no restored workload
exists, deletes the backup, then starts a workload and compares original file
contents and SHA-256. The test cleans up only its recorded claim UIDs and namespace.

## Console, OAuth, CLI and storage together

`scripts/flash_backup_live_e2e.mjs` accepts an explicit endpoint, private account
JSON (`username`, `password`), CLI, kubectl, kubeconfig, fixture image digest and
report path. Run `node scripts/flash_backup_live_e2e.mjs --endpoint URL
--account-file FILE --cli CLI --kubectl KUBECTL --kubeconfig CONFIG --image IMAGE
--report REPORT`. `--preflight` verifies login and prepares the reusable test project.
The script requires a dedicated `heterocloud-(browser-)e2e` identity and a test
organization owned by that account. It creates/reuses `flash-backup-e2e` inside
that organization; that empty project remains for subsequent runs.

It logs in through the normal public OIDC screen, obtains and revokes a CLI
device-code token, and tests backup CRUD, retry idempotency and actual console
restore into a stopped private service. It deletes its source volume, checks
that the backup survives, deletes the backup after copy completion, starts the
restored service and compares file contents/hashes. All created services,
backups, PVs, token files and sessions are cleaned up. Existing user workloads
and files are never used as fixtures. Reports omit passwords, cookies, tokens
and raw authentication errors. Keep the account input and screenshots private.

The GitHub Actions jobs in HeteroCloud run PostgreSQL authorization/retention
tests, CLI command audits, and desktop/mobile Chromium UI tests without cluster
operator credentials. Native storage acceptance uses these isolated scripts;
no SSH administrator key or cluster-admin kubeconfig is uploaded to GitHub.

## Declared releases and automatic security images

The security promoter uses a Helm image parameter, which has precedence over
Helm YAML and is intentionally preserved by Terraform. On a declared release
change, `application_helm_value_cleanup` now verifies source history and removes
only a superseded older security override. Same-source or newer security images
are retained; unrelated histories fail without changing the image. The update
uses resourceVersion and parameter tests to avoid overwriting a concurrent
promotion. Subsequent Terraform runs do not periodically reset security fixes.
