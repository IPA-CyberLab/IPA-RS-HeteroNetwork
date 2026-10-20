# Flash operational safeguards: 2026-10-20

The rollout adds capacity admission, tenant/owner diagnostics, deployment history
and rollback, scheduled backups, and isolated restore verification. The API, CLI
and console are included. IaC pins the component commits and image digests;
the independent external-copy job remains disabled pending destination access.

## Releases and CI

| Component | Release | Source | Validation |
| --- | --- | --- | --- |
| HeteroCloud | [0.1.110](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/releases/tag/v0.1.110) | `4e4d2a67e995de70aa9898ae195cde8d3174cb0e` | [Release workflow](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/actions/runs/39445168140) |
| Flash | [0.1.54](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/releases/tag/v0.1.54) | `ebde56c153312b9313692f5d91ca1ff75e397337` | [Release workflow](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/actions/runs/39445276808) |

Cloud's release gate covers Rust, PostgreSQL IAM/concurrency/retention tests,
strict Clippy, Lean, console tests, build and desktop/mobile Chromium. The release
publishes checksum-protected Linux/macOS/Windows CLI archives for x64 and arm64.
Flash's gate covers 93 library tests plus API/activator tests, strict Clippy,
Python operations tests, generated CRDs, Helm and amd64/arm64 image artifacts.
Infrastructure acceptance additionally covers backup credential boundaries,
protected external configuration and rejection of foreign OOM fault targets.
The [infrastructure workflow](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/39448502112)
passed on feature commit `12d56d7a`, including an actual GitHub runner VPN join
and authenticated Chromium access through HeteroNetwork.

## Native measurements

The machine-readable [acceptance record](flash-operations-2026-10-20.json) contains
the passing receipts. Each scope uses a dedicated test identity and newly created
nonce-owned services. OIDC uses the public login screen and CLI authorization
uses the device-code flow. Sessions and fixture resources are removed afterward.

| Scope | Observation |
| --- | --- |
| Capacity | An uncached oversized image is refused before pull; an oversized replicated PVC is refused in server dry-run. Neither resource is created. |
| Admission concurrency | 128 concurrent requests on 32 threads share one snapshot over 1395 real Pods. Peak RSS is 121,372,672 bytes inside a 256 MiB gVisor limit. |
| Memory failure | A new disposable VM is limited to 64 MiB. Its own cgroup swap is disabled after identity checks, and a bounded allocation produces `OOMKilled`, exit 137. Host swap and other Pods are unchanged. |
| Automatic rollback | The failed revision returns to the prior runtime-verified revision. The same persistent claim, random 2 MiB payload SHA-256 and marker survive. |
| Manual rollback | The real CLI selects a revision with an expected-generation fence; the persistent data hash remains identical. |
| Stateless update | 293 HTTP requests span both application versions with zero errors during a delayed startup. |
| Console | Real revision history opens in 1099 ms; the backup policy screen opens in 1798 ms. Tests fail above 3000 ms. |
| Scheduled backups | Two scheduled backups pass independent physical restore verification, including temporary-volume cleanup. Retention then removes the older scheduled backup and retains the manual backup. |
| Cold revision | The updated service stays at zero Pods for over 75 seconds. A real request starts the health-failing revision; automatic rollback selects a runtime-verified revision and public HTTP returns the original response. |
| S3 copy/recovery protocol | Signed copy, source-object deletion, exact-byte recovery, refusal of a nonempty destination and anonymous-list denial pass against three fresh private S3 buckets. All fixture objects, buckets and their key are removed. |

Runtime recovery and scheduled-backup native receipts used Cloud 0.1.109 and Flash
0.1.53. The cold revision regression runs against the final 0.1.110/0.1.54 rollout.
The final preservation check is performed after that rollout. The concurrency
probe loads the release's Python admission source into a separately limited VM.

## Defects found and corrected during validation

Concurrent inventory refreshes originally duplicated large snapshots and exhausted
the admission service's memory. Single-flight refresh, compact paginated Pod
inventory, bounded request concurrency and cache expiry measured after refresh
corrected this. Kubernetes appends `?timeout=15s` to admission requests; routing
now normalizes the path, and a regression covers this actual request form.

Restore verification initially requested a capability forbidden by namespace
baseline policy. The trusted job now uses the permitted capability with a
read-only root and restored volume, dropped other capabilities, no token and
denied network access. Only nonce-owned legacy verification jobs can be replaced.
Two real scheduled restore verifications completed and cleaned up successfully.

An update to an idle scale-to-zero service used to wake the new revision merely
because its generation changed. Flash now carries forward an already sleeping
state until actual traffic refreshes activity. Cloud ignores observations from an
older runtime generation when recording state, diagnostics or activation time.
An empty/stopped service is not a verified rollback target, and idle time does
not consume a cold-start deployment deadline.

The first memory-fault attempt did not OOM because the VM correctly kept RAM at
64 MiB while allowing swap. The corrected test limits swap only on its disposable
cgroup. A separate cold-start health test keeps a small process alive without
opening its health port; it tests activation deadlines independently of OOM.
The stateless probe also uses the allocated service port rather than assuming
that the internal port equals the container port.

## Preservation and external setup

The final check preserved all eight originally running Flash Pod UIDs and restart
counts, all 24 original PVC identities and volume bindings (including ten Flash
claims), and HyperEVM's 8 GiB memory limit. Dedicated masters have no Flash Pods.
Coder and Whisper both returned HTTP 200 over public HTTPS. Both Applications
are Synced/Healthy. Test services, Pods, namespaces, cluster RBAC, backups and
temporary volumes are removed; the dedicated native test identity is disabled.
The shared CI identity is untouched. Exact timestamps are in the JSON record.
Existing unrelated failed Pods and pending workload
configuration are preserved; this rollout does not claim to resolve those.

The primary private backup store has a 40 GiB quota and shares this cluster's
failure domain. The real S3 protocol fixture also shares that domain. Neither is
an independent disaster-recovery copy. A private R2 Terraform module, protected
credential installation, bounded exporter, authenticated catalogs and empty-bucket
recovery are implemented and validated. Production external export remains
disabled because an independent destination credential has not been supplied.

Restore verification samples bounded file data; it does not run the restored
application or prove exhaustive file integrity. Independent copies cover backup
store data and CSI catalog metadata, not PostgreSQL, IAM or Secret Manager.
Operational controls and enabling steps are in [the runbook](../flash-operations.md).
