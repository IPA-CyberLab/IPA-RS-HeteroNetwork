# OSS inventory and security updates

The fleet collects host package/runtime inventory and scans deployed image digests and all seven service repositories every 15 minutes. Failures and stale or missing hosts produce an incomplete result, never a clean result. This interval is a polling configuration, not a guarantee that upstream databases publish a fix within 15 minutes.

## Inventory

The private scanner on the bootstrap node writes:

- `/var/lib/heteronetwork-security/cluster/inventory.json`: packages, CVE/GHSA findings, installed and running binary identities, upstream releases, coverage errors.
- `/var/lib/heteronetwork-security/cluster/oss-cve.csv`: OSS name, installed version, ecosystem, deployment, advisory, severity, fixed version and source URL.
- `/var/lib/heteronetwork-security/host-report.json`: per-node package/runtime information. An inventory-only SSH identity can execute only the forced read command; it cannot open a shell or forward a connection.

Completed/failed Pods are removed from current inventory. Nonterminal Pods use their observed image digest, including init containers. Trivy scans only vulnerabilities, not secrets. For private images the scanner reads only registry-pull secrets referenced by observed Pods, scopes credentials to the matching registry, stages them in temporary private files and removes them after scanning. Credential values never appear in command arguments, reports, artifacts or metrics. Hosts enumerate installed packages and runtime binary identities without walking user disks, databases, credentials or logs. OS vulnerability matching runs centrally against the collected package metadata, avoiding large advisory databases and slow I/O on dedicated masters. The collector requires actual OS detection and package enumeration: exit code zero with no packages is an error.

Trivy provides vendor package advisories; OSV is polled directly for language dependencies. Public release feeds avoid distributing permanent GitHub tokens. NVD also tracks gVisor product disclosures because not every disclosure appears in GitHub advisories. Product-name matches remain a catalogue with official version conditions; they are not automatically counted as vulnerabilities in the installed release. A newer release alone does not establish which CVE it fixes.

Aggregate metrics are bound only to the bootstrap VPN address on TCP 19765. Grafana exposes the `HeteroCloud OSS・脆弱性` dashboard; Prometheus alerts on incomplete/stale scans, unavailable collectors, critical findings and running superseded runtime binaries. Raw inventories, SSH keys and user image identities are not published through the metrics HTTP endpoint or committed into Git.

## Automatic source patches

Each repository calls the same immutable, pinned reusable GitHub Actions workflow on a 15-minute schedule. Compatible Cargo fixes are chosen from actual advisories, including CVE-less GHSA entries. The job runs all-target tests and Clippy, re-scans the patched lockfile with Trivy and live OSV, then commits only `Cargo.lock` using an ephemeral job token. A failed lookup, test, re-scan or non-fast-forward push stops the patch.

The pipeline builds content-addressed security images with SBOM and provenance, re-scans the exact digest, and signs the candidate descriptor using a pinned reusable GitHub Actions builder. Immutable prerelease assets provide candidate discovery without a permanent GitHub credential on the fleet. Compatible source patches trigger candidate publication; a requested build can also publish fixes that have already been merged. The last stable release contract binds those manual fixes to the previous image and lockfile.

An unchanged source commit also rebuilds when a fresh scan of its previous candidate discovers a new fixable OS advisory. Debian runtime layers update vendor packages during that build. Candidates use both source commit and CI run identity, so an OS-only fix never replaces a previously signed release asset or digest. Findings already present in the last build do not start a rebuild loop.

The native reconciliation service verifies the signed descriptor, exact builder/source identity, complete successful CI, current advisory scan, available platform replicas and drained incoming platform connections. It changes only the declared Argo CD Application's image parameter (`image.tag`, or the VPC chart's scalar `image`). It observes running tenant container IDs, PIDs, executable hashes and generations before and after the rollout, keeps the declared health endpoints within their deadlines, and verifies recovery of the previous image on acceptance failure. A changed template with stale Deployment status is not acceptance: the controller must observe the new generation and all replicas must finish updating. User Pod templates and helper images are separate from platform image promotion. Failed or unverifiable candidates remain held in the protected reconciliation status, rather than becoming eligible updates. The current single-replica VPC controller fails the replica-reserve requirement and stays held.

Production targets and health URLs are deployment configuration in `deploy/security/promotion-heteronet.json`. The builder commit must be pinned to the immutable reusable workflow used by the six service repositories. The runtime observer has a separate forced-command SSH identity and argument-free sudo rule; it can export IDs/PIDs, hashes and connection counts, never select a command or read process environment or arguments. Non-Cargo source edits and arbitrary tenant image upgrades are detected and reported, not automatically rewritten.

## Runtime patches and availability

`deploy/security/containerd-lock.json` records the official archive and individual binary hashes. Terraform manages the scanner and serial containerd reconciliation independently of normal master setup. The updater requires `KillMode=process`, refuses unsafe experimental CRI restore, preserves every pre-existing running task ID and PID, checks CRI readiness and the active daemon hash, and restores the old binaries if acceptance fails. This replaces the parent daemon while existing shims/workloads remain running; it is not a Sentry or VM live migration. Existing shim binaries may remain active until their workloads naturally end, and that difference stays visible in inventory.

For user workloads, `security_update_gate.py` rejects a change without evidence tied to the exact artifact, workload generation and recent test. It requires memory/process state, established connections, fencing, reserved destination capacity, health and rollback evidence. GPU workloads need separate GPU-state evidence. A gVisor version change also needs an actual cross-version restore test. Restart fallback is disabled.

`security_gvisor_e2e.py` exercises real checkpoint/restore using a compiled probe with a random 32 MiB memory buffer and a persistent external TCP connection. Checkpoints live in a private `noswap` tmpfs. An incompatible restore must recover the original memory identity and existing socket with the source runtime. The runner stages the whole gVisor bundle, including Sentry sidecars; hashing or replacing `runsc` alone does not identify the active sandbox kernel. Sandbox namespace IP configuration must be recreated when rebinding a restored netstack.

The exact-version restore and the rejected 20260928.0 → 20261005.0 restore with successful source-version recovery have been exercised on an isolated real-host canary. GitHub Actions runs the same tests. These are runtime acceptance tests, not a completed cross-node Kubernetes migration executor. The currently deployed shim's standard task Checkpoint RPC returns NotImplemented, and its custom restore API documents an outstanding cgroup/OOM-notification setup requirement. A CRI migration must cover those limits, filesystem/volume attachment, CPU capabilities, credential rebinding, stable routing/NAT and source fencing before automatic host evacuation is eligible. Kernel/gVisor changes that need that relocation remain held; restart fallback stays disabled.

The current containerd patch disables vulnerable CRI checkpoint restore by default. Do not re-enable `enable_experimental_restore_via_create` as a migration workaround.

## Verification

Run the security policy tests with:

```sh
python3 -m unittest discover -s scripts -p test_security_inventory.py
```

Reconcile only the scanner or runtime resources through Terraform, or their dedicated Ansible playbooks with the protected operator inventory. No user Pod belongs on the three master-only nodes; native read-only inventory services do not change that constraint.

## Upstream constraints

- [gVisor checkpoint/restore](https://gvisor.dev/docs/user_guide/checkpoint_restore/): raw runsc support, CPU/GPU constraints; host-network restore resets established TCP connections.
- [gVisor maintainers on version compatibility](https://groups.google.com/g/gvisor-users/c/hYRsWpqD4kM): exact-version restoration is supported; a structural compatibility hash alone does not prove semantic compatibility.
- [GKE snapshot compatibility](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/pod-snapshots): snapshot compatibility also depends on runtime and GPU driver versions.
- [containerd GHSA-p7v4-vr35-mj6f / CVE-2026-95837](https://github.com/containerd/containerd/security/advisories/GHSA-p7v4-vr35-mj6f): fixed in 2.2.7 / 2.3.4 by disabling experimental CRI restore. Re-enabling it leaves the issue present.
- [rustls GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc): the affected 0.23 series is fixed in 0.23.45; detection must not require a CVE alias.
