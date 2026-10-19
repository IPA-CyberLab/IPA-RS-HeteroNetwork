# Flash persistent disk backup and restore acceptance — 2026-10-19

HeteroCloud 0.1.106 and Flash 0.1.49 are deployed through Terraform-managed
Argo Applications with immutable image digests. Both Applications are Synced
and Healthy. The [HeteroCloud release](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/actions/runs/39194834556)
passed Rust workspace, PostgreSQL, console, Chromium and all six native CLI
platform jobs. The [Flash release](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/actions/runs/39194999726)
passed all targets, Clippy, generated CRD and Helm checks before publishing both
image architectures. The [dedicated backup checks](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/actions/runs/39194734357)
also passed. The CLI command audit passed 337/337 cases.

## Actual user operations

The isolated native test used normal public OIDC login, the released Linux CLI's
device-code login, and the production console/API. A dedicated E2E organization
was used throughout. No cluster administrator key was sent to GitHub Actions.

1. Create a private fixture service and write random content, a hidden `.bashrc`,
   a permission mode and a symbolic link into its persistent `/root`.
2. Create a backup with the CLI; repeat the request ID and confirm one backup.
   The source Pod and container IDs remain unchanged while saving.
3. Change source contents, delete only the fixture service and its original
   physical volume, and confirm the backup remains listed.
4. Open the backup screen and restore through the actual browser UI. The screen
   became usable in **1,040 ms**, within the three-second limit. Repeating the
   browser's restore request with the CLI returns the same new service ID.
5. Confirm the restored service is stopped, private, has no copied environment,
   disables egress and uses a different disk. Confirm Longhorn completed its
   physical copy while no restored user Pod exists.
6. Delete the backup before starting the restored service. Start it, compare
   the original marker and SHA-256, and verify the hidden file, mode `640` and
   symbolic link survived.
7. Delete fixture services, backups and PVs, revoke CLI and browser sessions,
   and remove temporary credential files. The empty `flash-backup-e2e` project
   remains under the dedicated test account for future runs.

Both independent raw CSI/S3 tests also restored after deletion of the original
volume. The second additionally deleted the backup before mounting the restored
volume for the first time. Anonymous access to the backup bucket returned 403.

The source PVC must be stable and fully resized before backup. Restored PVC
`Bound` is insufficient for readiness: both the completion path and backup
deletion guard require Longhorn `restoreInitiated=true` and
`restoreRequired=false`. Backups are crash-consistent; transactional apps must
be quiesced. Storage currently resides in the same cluster and does not provide
site disaster recovery.

## Deployment and preservation

Existing security-promoter Helm image parameters initially took precedence over
the declared release YAML. IaC now compares source history and retires only
older overrides superseded by a declared release. Same-source/newer security
fixes are retained, and concurrent changes are guarded by resourceVersion.
Four boundary tests verify this behavior. API-server normalization of empty
CRD short names is ignored explicitly for the new backup CRD.

All **16** pre-existing user Pods retained their Pod/container IDs and restart
counts. All **12** existing PVC identities and capacities were preserved. All
six nodes are Ready; `uc-k8sp1`, `uc-k8sp2`, and `uc-k8s3p` still have no user
Pods. The workload helper image was kept at its prior digest to avoid rolling
existing user Pods. A pre-existing VPC Helm YAML drift was reconciled to its
already-running image; VPC Pod creation times and running images were unchanged.

Machine-readable evidence, exact commits and image digests are in
[flash-backups-2026-10-19.json](flash-backups-2026-10-19.json). Private input
credentials, browser sessions, raw authentication errors and user disk contents
are excluded from this repository.
