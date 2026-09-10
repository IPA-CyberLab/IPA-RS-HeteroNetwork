# Guarded Dev Libvirt Provisioning

The provisioner implements local root-only creation and bounded first-boot
verification. **Awaiting parent/Kepler review; no remote apply has occurred.**
Root access and the prepared image are available, not implementation blockers.

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
Never clear it blindly. There is no recovery/adoption command. Interruption
between guest start and recording normalized XML can also require manual review.
The lifetime lock serializes this script, not unrelated trusted administrators.

## Focused Verification

```sh
python3 scripts/provision-dev-libvirt.test.py
```

21 tests cover policy modeling, XML/budgets, collisions, exclusive writes,
durable intent, guard readback/drift, QCOW2 rejection, pinned bootstrap identity,
bounded subprocesses, partial boot cleanup, and complete mocked first/warm/cold
apply. They use temporary fixtures and synthetic subprocesses, not real libvirt,
nft mutations, SSH or guest creation.

Kepler review precedes live apply. Local unprivileged kernel nft validation was
unavailable: no live firewall, NAT, guest boot, isolation or Internet pass is
claimed. Apply checks kernel readback and boot, not a packet reachability matrix.
After reviewed creation, separately verify DHCP/DNS, public egress, denied
host/production destinations and IPv6 using only these guests. Kubernetes and
application bootstrap remain separate.
