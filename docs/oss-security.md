# OSS inventory and security updates

The fleet collects host package/runtime inventory and scans deployed image digests and all seven service repositories every 15 minutes. Failures and stale or missing hosts produce an incomplete result, never a clean result. This interval is a polling configuration, not a guarantee that upstream databases publish a fix within 15 minutes.

## Inventory

The private scanner on the bootstrap node writes:

- `/var/lib/heteronetwork-security/cluster/inventory.json`: packages, CVE/GHSA findings, installed and running binary identities, upstream releases, coverage errors.
- `/var/lib/heteronetwork-security/cluster/oss-cve.csv`: OSS name, installed version, ecosystem, deployment, advisory, severity, fixed version and source URL.
- `/var/lib/heteronetwork-security/host-report.json`: per-node package/runtime information. An inventory-only SSH identity can execute only the forced read command; it cannot open a shell or forward a connection.

Completed/failed Pods are removed from current inventory. Nonterminal Pods use their observed image digest, including init containers. Trivy scans only vulnerabilities, not secrets. Host collection stages OS package metadata and explicitly managed binaries rather than walking user disks, databases, credentials or logs. The collector requires actual OS detection and package enumeration: exit code zero with no packages is an error.

Trivy provides vendor package advisories; OSV is polled directly for language dependencies. Public release feeds avoid distributing permanent GitHub tokens. NVD also tracks gVisor product disclosures because not every disclosure appears in GitHub advisories. Product-name matches remain a catalogue with official version conditions; they are not automatically counted as vulnerabilities in the installed release. A newer release alone does not establish which CVE it fixes.

Aggregate metrics are bound only to the bootstrap VPN address on TCP 19765. Grafana exposes the `HeteroCloud OSS・脆弱性` dashboard; Prometheus alerts on incomplete/stale scans, unavailable collectors, critical findings and running superseded runtime binaries. Raw inventories, SSH keys and user image identities are not published through the metrics HTTP endpoint or committed into Git.

## Automatic source patches

Each repository calls the same immutable, pinned reusable GitHub Actions workflow on a 15-minute schedule. Compatible Cargo fixes are chosen from actual advisories, including CVE-less GHSA entries. The job runs all-target tests and Clippy, re-scans the patched lockfile with Trivy and live OSV, then commits only `Cargo.lock` using an ephemeral job token. A failed lookup, test, re-scan or non-fast-forward push stops the patch.

The pipeline can build a content-addressed security image with SBOM and provenance. Publishing a candidate is separate from deploying it or remediating active processes. Automatic promotion of those images is not implemented yet. Non-Cargo package updates are currently detected and reported, not automatically merged.

## Runtime patches and availability

`deploy/security/containerd-lock.json` records the official archive and individual binary hashes. Terraform manages the scanner and serial containerd reconciliation independently of normal master setup. The updater requires `KillMode=process`, refuses unsafe experimental CRI restore, preserves every pre-existing running task ID and PID, checks CRI readiness and the active daemon hash, and restores the old binaries if acceptance fails. This replaces the parent daemon while existing shims/workloads remain running; it is not a Sentry or VM live migration. Existing shim binaries may remain active until their workloads naturally end, and that difference stays visible in inventory.

For user workloads, `security_update_gate.py` rejects a change without evidence tied to the exact artifact, workload generation and recent test. It requires memory/process state, established connections, fencing, reserved destination capacity, health and rollback evidence. GPU workloads need separate GPU-state evidence. A gVisor version change also needs an actual cross-version restore test. Restart fallback is disabled.

The validation gate is implemented; the integrated cross-node live migration executor is not implemented yet. Do not call ordinary Kubernetes rescheduling, replacing `runsc` on disk, or a boolean fixture a completed live migration. Kernel/gVisor changes that need workload relocation stay unapplied until real migration evidence and an executor exist. This is an explicit remaining requirement, not a silent restart.

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
