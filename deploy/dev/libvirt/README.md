# Guarded Dev Libvirt Provisioning

The provisioner implements local root-only creation and bounded first-boot
verification. After reviewed guard recovery and seed repairs, all three owned
guests passed live boot verification and a subsequent regular apply passed
idempotently. Earlier failures and their bounded repair procedures remain
documented below; they are not outstanding blockers for this allocation.

## Fixed Allocation

The committed profile targets `ichikawap1`, `qemu:///system` only:
- New network/pool `hetero-dev`, bridge `virbr-hdev`.
- Storage `/var/lib/libvirt/hetero-dev`.
- Guests `hetero-dev-1..3`: each 4 vCPU, 8192 MiB RAM, 40 GiB standalone disk.
- Total 12 vCPU, 24 GiB RAM, 120 GiB virtual disk.
- Underlay `172.28.240.0/24`, gateway `172.28.240.1`, reservations `.11..13`.
- Reserved overlay `10.251.0.0/24`, pods `172.29.0.0/16`, services `172.30.0.0/16`.

Three guests on one host are **not physical HA**. This does not install Kubernetes,
native services, databases or OIDC. Separate dev bootstrap must supply fresh
credentials and must not copy production or tenant state.

Existing `vercel-research` domain/pool, `default` network, all autostart flags and
other resources are preserved. Names or deterministic UUIDs alone do not prove
ownership. Changed profiles cannot reuse the ownership journal.

## Commands

Use a trusted checkout with Python 3.11+. Apply needs local root, libvirt system
access, usable KVM, ip, nft, gpgv, qemu-img, cloud-localds, ssh-keygen and ssh.
IPv4 forwarding must already be enabled; no global sysctls are changed.

```sh
python3 scripts/provision-dev-libvirt.py plan
python3 scripts/provision-dev-libvirt.py render \
  --ssh-public-key /private/dev-only/id_ed25519.pub \
  --output /private/dev-only/new-preview
```

Preview is create-only (directory 0700, files 0600), accepts only a public key and
omits sudo/private host keys. Actual apply generates fresh keys and seeds itself.
Do not use production keys.

After review, run **locally on ichikawap1**:

```sh
sudo python3 scripts/provision-dev-libvirt.py preflight
sudo python3 scripts/provision-dev-libvirt.py verify-image \
  --image-directory /tmp/hetero-dev-base-image.YJa0fiJbuD
sudo python3 scripts/provision-dev-libvirt.py apply \
  --image-directory /tmp/hetero-dev-base-image.YJa0fiJbuD \
  --confirm-create hetero-dev
```

Use the existing image described in [IMAGE_PREPARATION.md](IMAGE_PREPARATION.md);
do not redownload it. Every apply independently verifies signed checksums using
the installed root-owned Ubuntu cloud image keyring, the profile pin and source
hash. Import hashes bytes copied from an opened descriptor into an exclusive
owned file. QCOW2 header and QEMU chain checks reject backing/external data files
before conversion into fresh standalone disks. No keys are imported. See
[Canonical artifact verification](https://ubuntu.com/docs/public-images/public-images-reference/artifacts/).

Preflight reads all route tables, addresses, active/inactive network definitions,
domain/pool names and pool paths, and checks KVM access and capacity. Conflict
checks repeat under the lifetime lock immediately before definition/start.
It preserves 24 GiB available host memory, 128 GiB disk plus 5 GiB image overhead,
and four logical CPUs beyond the guests. These checks are not reservations.
Reapply still requires conservative full disk headroom and signed image input.
Standalone preflight rejects existing dev names; apply performs ownership-aware
checks for previously journaled resources.

## Isolation and Lifecycle

Before NAT or guests start, apply checks and installs additive JSON rules in new
`inet hetero_dev` and `bridge hetero_dev` tables. Kernel acknowledgement and
normalized live readback must agree. No global flush or existing-table editing
occurs. Unjournaled collisions, partially missing tables or guard drift refuse.

- Guest-to-host permits DHCP, DNS to its gateway and established replies to
  host-originated management; other services are dropped.
- Forwarding allows its own subnet and public Internet, blocking RFC1918, CGNAT,
  loopback, link-local, listed special-use IPv4 and production public
  `163.220.236.0/23`. Unsolicited routed ingress is dropped.
- IPv6 is blocked in routed and bridge hooks; cloud-init disables DHCPv6, RA and
  link-local addressing.
- Rules scope only the new bridge. Other firewall drops can still block Internet.
  Additional production public ranges require operator review.

Libvirt NAT alone does not isolate host services. References:
[libvirt networks](https://libvirt.org/formatnetwork.html),
[nftables hooks/verdicts](https://netfilter.org/projects/nftables/manpage.html),
[nft JSON](https://manpages.debian.org/bookworm/libnftables1/libnftables-json.5.en.html).

Apply exits after strict authenticated SSH hostname and guest
`sudo -n cloud-init status --wait` checks, with a shared 300-second boot-check
deadline and bounded commands/output. Guests remain running; **no supervisor is
required**. Normal guest reboot uses `on_reboot=restart`. No VM/network/pool
autostart is enabled. After host reboot, rerun apply: if both guard tables are
absent it requires owned guests stopped, reinstalls/verifies isolation, starts
owned resources and repeats boot checks. Cold domains are accepted before boot;
all three must be running before success.

Host root is trusted and can override these controls. This is not a hostile
tenant sandbox or protection against arbitrary public-Internet tunnels.
There is no continuous firewall monitor. Stop owned guests before an operator
firewall reload removes these tables; restore via guarded apply before restart.
Do not enable autostart or manually bypass guard ordering.

## Ownership and Failures

Root-private `/var/lib/hetero-dev-provisioner` holds the lifetime lock, durable
`journal.json`, fresh admin and guest host keys, pinned `known_hosts`, and seed
sources. Ownership binds host/profile hash, resource UUIDs and normalized
definitions, storage paths/inodes and immutable file hashes. Exclusive,
descriptor-relative writes and fsynced journal replacement protect local state.
Warm/cold reapply checks ownership and does not regenerate disks or identities.

The fresh guest `devadmin` uses key-only SSH and passwordless sudo inside its
own VM. Root/password SSH is disabled. Private NoCloud seeds install distinct
ed25519 host identities pinned before first contact. SSH uses strict verification,
no agent forwarding and no password fallback. Keys and seed contents are never
printed. Protect root state and seed ISOs as credentials; never commit them.
See [NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)
and [cloud-init SSH configuration](https://cloudinit.readthedocs.io/en/latest/topics/modules.html).

On boot failure, apply attempts to stop only guests it started in that invocation,
after UUID verification. Previously running guests remain untouched. Definitions,
disks, pool, network and guard remain for inspection; there is no automatic delete.

**Crash recovery is not automatic.** Nonempty journal `pending` blocks subsequent
apply until an operator reviews the exact operation and actual owned resources.
Never clear it blindly. There is no general recovery/adoption command. Interruption
between guest start and recording normalized XML can also require manual review.
The lifetime lock serializes this script, not unrelated trusted administrators.

### Exact Guard-Only Recovery

The 2026-09-10 nft 1.0.9 live readback is preserved in
`testdata/nft-1.0.9-live-guard.json` (only the two scoped guard tables, no secrets).
Its only semantic-printing differences from the original batch are three omitted
redundant `meta l4proto` matches before same-protocol DHCP/DNS port matches.
Normalization removes only those implied checks in pure match/verdict rules;
conflicting protocol checks, rule order and other predicates remain intact.
The original committed/root-installed c5f850 tool reproduced the failure on
ichikawap1 in a temporary `unshare --net` namespace: echo and live readback each
had 12 groups, but original canonical comparison failed only for these inet
input rules. The probe completed and the namespace was removed; host rules were
unchanged. This verifies the original readback-comparison failure, not merely
an inferred normalization difference.

After review, the explicit local-root recovery command is:

```sh
sudo python3 scripts/provision-dev-libvirt.py recover-guard \
  --expected-batch-sha256 339f000d6e74f479d30bb01c04053631d7c3176d1abe25d80a074d4a76b12e73
```

It takes the existing lifetime lock and requires the host/profile binding, exact
pending `install-guard` operation and original batch hash, empty resource/file
records, no recorded guard/pool directory/readiness, and only lock/journal files
in private state. Fresh preflight must reject any resource/pool-path collision.
Two scoped live reads must equal the full normalized expected batch, not merely
counts or comments. Only then does one durable journal update record the verified
guard and clear this specific pending operation. It does not delete, reinstall,
modify firewall rules, create resources, or continue into apply. A later apply is
a separate reviewed action. Any mismatch requires investigation, not blind clear.

## Focused Verification

```sh
python3 scripts/provision-dev-libvirt.test.py
```

36 tests cover policy modeling, XML/budgets, collisions, exclusive writes,
durable intent, guard readback/drift, QCOW2 rejection, pinned bootstrap identity,
bounded subprocesses, partial boot cleanup, and complete mocked first/warm/cold
apply, real nft readback normalization and tightly gated guard recovery. They use
temporary fixtures and synthetic subprocesses, not real libvirt,
nft mutations, SSH or guest creation.

Review precedes recovery or another apply. Host preflight, privileged nft checks,
guard readback and live guest boot verification passed as recorded below.
No packet-isolation matrix or public Internet reachability pass is claimed.
Apply checks kernel readback and boot, not a packet reachability matrix.
After reviewed creation, separately verify DHCP/DNS, public egress, denied
host/production destinations and IPv6 using only these guests. Kubernetes and
application bootstrap remain separate.

### Pool Metadata and Refusal Diagnostics

The next apply reached pool/network start and domain 1 definition, then refused
pool definition drift. Saved evidence in `testdata/libvirt-dir-pool-runtime.json`
shows libvirt adds root/root `0700` directory permissions even to `--inactive`
pool XML. Only the fixed pool name/UUID/path with an exact permissions node
(mode `0700` or `0711`, owner/group `0`, no extra fields or attributes) is
normalized. Unexpected modes, ownership and XML remain hash-significant.
Directory verification independently requires root-owned protected ancestors,
the journaled inode and mode `0700` or `0711`.

Creation explicitly applies descriptor-based chmod `0711`, since umask `077`
otherwise turns mkdir's requested `0711` into `0700`. Warm/cold apply similarly
corrects only the verified owned `0700` directory to `0711`, with journal intent
and fsync. There is no pool-definition rewrite, blanket permissions exclusion,
pool recovery command or journal-hash replacement.

CLI failures remain nonzero and now report JSON with code stage/line, a fixed
refusal reason, and a whitelisted command tool/exit code or numeric OS errno
where available. Raw subprocess output, command arguments, parser exception
text and credential paths are not included. Source-literal reason checks and
synthetic secret-bearing failure tests enforce this reporting boundary.

## Exact Seed Schema Repair

The first boots retained supplied host identities but cloud-init reported
terminal degraded status because `ssh_genkeytypes: []` violates its schema.
New seeds use `["ed25519"]`; supplied `ssh_keys` cause cloud-init to install the
same pinned pair instead of generating replacements. Normal apply never silently
rewrites existing journal-owned seeds.

This repair is only for these fresh, never-enrolled development guests. It is
not a general cloud-init reset or a procedure for workload-bearing VMs. The
parent inspected the installed plain-clean implementation: without flags it
removes cloud-init instance state under its configured cloud directory, preserves
the seed directory, machine ID, logs, SSH/network/fstab configuration, and invokes
the configured clean-hook directory. The command below verifies that directory
is empty before allowing clean. See [Canonical's clean implementation](https://raw.githubusercontent.com/canonical/cloud-init/main/cloudinit/cmd/clean.py).

### Inspect First

After reviewer clearance and installation of the pinned source, inspect one
explicitly selected guest. It must already be running under the verified guard;
other guests may remain off. Read only the existing journal SHA-256 for that
guest's `/var/lib/hetero-dev-provisioner/hetero-dev-1-user-data` entry.
Do not print userdata or private keys.

```sh
sudo python3 scripts/provision-dev-libvirt.py repair-seed \
  --vm hetero-dev-1 --expected-userdata-sha256 OLD_JOURNALED_SHA256 --inspect-only
```

Inspection performs no starts, shutdowns, journal updates, clean or seed writes.
It verifies journal/file/resource ownership, guard, preflight, pinned SSH
identity, machine ID equal to the guest UUID without hyphens, and installed host
keys. Guest checks require:

- Terminal cloud-init `done`, no fatal errors, and only either exact observed
  schema warning (short form or the full schema-command suggestion). Unrelated
  warnings are refused. All cloud-init stage units must be dead or exited.
- Configured `init.paths.cloud_dir == /var/lib/cloud` and
  `settings.CLEAN_RUNPARTS_DIR == /etc/cloud/clean.d`, with no clean hooks.
- No alternate nonempty seed directory; only empty directories may exist below
  `/var/lib/cloud/seed`. Symlinks are rejected.
- No HeteroNetwork, Kubernetes, kubelet, Rancher, Docker or HeteroCloud state
  markers checked by the fixed helper. The instance directory must contain only
  this guest's instance ID.
- Exact original userdata, differing from the corrected host seed only at
  `ssh_genkeytypes`, and unchanged supplied private/public host keys.

Fixed `guest_stage` refusals and hashes contain no private configuration.
These checks supplement, not replace, the operator's fresh/no-workload
attestation. They cannot prove the absence of arbitrary software installed by
a trusted administrator.

### Repair One Guest

```sh
sudo python3 scripts/provision-dev-libvirt.py repair-seed \
  --vm hetero-dev-1 --expected-userdata-sha256 OLD_JOURNALED_SHA256 \
  --confirm-repair hetero-dev --confirm-fresh-unenrolled
```

Repeat separately for dev-2 and dev-3 using each guest's own old userdata hash.
Repair may start only its selected stopped VM; inspection never starts one.
No other VM, including `vercel-research`, is changed.

1. Verify exact old seed hash/contents, all recorded resources/files, private
   keys, guard and preflight. Require the complete owned three-guest resource
   set. Write durable repair intent before any guest start or repair.
2. Inspect the selected guest; if started by this command, allow at most 90
   seconds for pinned SSH readiness. Stage corrected userdata and a replacement
   ISO using unchanged metadata, network data and keys, and fsync staging.
3. Recheck guest preconditions and its inspected userdata hash. Invoke exactly
   `cloud-init clean` with **no flags** and a 30-second timeout. Never pass
   `--machine-id`, `--logs`, `--configs`, `--seed` or `--reboot`. Suppress
   command output, require exit zero, and immediately verify machine ID and SSH
   key files are byte-for-byte unchanged. No pickle is loaded or rewritten;
   no private cache format or semaphore is edited by this tool.
4. Gracefully shut down only the selected guest, with a 90-second bound, and
   reverify host files. Preserve private `.before-schema-repair` originals,
   fsync their directory entries, replace only the owned userdata/ISO, and record
   hashes/inodes. Guest disks, UUIDs, network data and definitions are unchanged.
   Stopping QEMU ensures the corrected ISO is reopened on next start.
5. Restart that guest under the guard. Require pinned hostname, successful
   `cloud-init schema --system` and actual status exit zero within the bounded
   180-second boot-check window. Reverify all ownership and record completion
   before clearing repair intent. Existing first_boot behavior is unchanged.

Clean deliberately lets cloud-init perform its supported first-instance setup
again from the corrected ISO. The exact seed contains no workload bootstrap,
and the same supplied host pair is reinstalled. No machine-ID change or disk
recreation is requested. A degraded exit 2 is never accepted as final success.

Failure leaves pending intent, staged files and any preserved originals for
reviewed diagnosis; there is no automatic partial-repair adoption or retry.
If the command originally started a stopped guest, it attempts to stop only that
guest after UUID verification. A guest already running on entry is not forcibly
stopped during failure cleanup. If clean succeeded but a later step fails, its
old instance cache may already be gone: do not rerun blindly or clear pending.
Inspect the recorded phase and owned files before recovery.

Focused tests cover exact seed transitions, terminal/unit gating, both exact
warning forms, inspect-only nonmutation, configured clean paths/hooks/seed/state
refusals, invocation of plain clean without flags, preserved identities, and
successful/failed simulated selected-guest transport. No remote inspection,
clean, guest boot or live repair is executed by the tests. Live inspection is
the first step after the parent/reviewer approves and pins the source.

## Actual Execution Evidence

The parent reported the following completed live operations on `ichikawap1`,
using reviewed source SHA-256
`1e205ef51716cef3edf24ce9f002cc0013af5af3f5e9fabcab293085ec625a80`
from commit `00ca13c8b20e891be354a7f375818f6f05bfa8a2`:

- Serial repairs of `hetero-dev-1`, `hetero-dev-2` and `hetero-dev-3` each exited
  zero with `cloud_init_verified: true` and `keys_rotated: false`.
- A subsequent regular `apply --confirm-create hetero-dev --image-directory`
  using the existing verified image directory exited zero. Its
  `guests_boot_verified` contained all three names, `guard_verified` was true,
  and `production_modified` was false.
- That apply reused existing owned resources and disks without resource
  recreation or key rotation. It passed journal ownership and boot gates after
  the repairs; no journal/hash reset was used to obtain success.

These are actual parent-operated results, distinct from the mocked focused tests.
They establish VM bootstrap and this warm idempotent apply, not an observed host
reboot or a comprehensive network isolation test. No native HeteroNetwork service
or Kubernetes installation has been performed in these guests. All three VMs
share one physical host and therefore **do not provide physical HA**.
