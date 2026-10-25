# 2026-10-25 power-loss recovery

Status: core control plane and Coder recovered; registry storage still depends
on the unreachable `uc-k8sp4`. Do not treat a responding registry authentication
endpoint as a successful image pull.

## What prevented automatic recovery

1. After boot, p5 restored a bounded VPN cache containing only p4. With that
   peer unavailable, p5 could not reach the healthy control-plane peers over
   the overlay. The local API proxy and database/control-plane dependencies
   could not bootstrap themselves through that missing route.
2. All three Secret Manager voters restarted sealed. Flash containers waiting
   for their environment secrets could not complete initialization. There was
   no independent host service submitting the existing custodian credentials.
3. PostgreSQL kept strict synchronous replication enabled, but the only other
   configured database member was the unavailable p4. Commits waited in
   `SyncRep`, and application migrations/connections accumulated behind them.
   The third DCS voter on ichikawap1 was not an active PostgreSQL replica. A
   retired, enabled `db-a` Patroni configuration also reappeared on that host
   after boot, instead of the declared replacement identity.
4. A DNS cache on ichikawap1 inherited an empty upstream resolver file early
   during boot. Retrying the process inside the same Pod kept failing with
   `plugin/forward: no nameservers found`, even after the host resolver recovered.
5. Flow Redis could not load an AOF with an invalid 183-byte tail. Its intended
   five-Sentinel deployment required three votes but only had three eligible
   application hosts in total; p1–p3 are dedicated custodians and correctly
   reject these application Pods. Missing replicas and OrderedReady startup
   compounded the bootstrap problem.
6. Harbor requested three Longhorn replicas, but the registry volume actually
   had only one data replica, on p4. Its Longhorn metadata contained no backup.
   Configuration counts did not demonstrate actual redundancy. The remaining
   healthy nodes cannot reconstruct data that was never copied to them.

p4's last Kubernetes heartbeat was **2026-10-23 11:11:56 UTC**, before this
power outage. Its public SSH, overlay and Tailscale paths did not respond during
recovery. This is an observation, not proof of whether its power, OS or network
has failed. Physical or out-of-band access is required to distinguish them.

## Changes and recovery actions

- `overlay-boot-recovery.tf` installs an identity-validated, bounded server
  roster and an Agent `ExecStartPre` hook. It restores direct host routes to
  the other five declared servers before control-plane polling. Production
  private keys and registration identities are retained. The hook was installed
  on p1, p2, p3, p5 and ichikawap1; p4 remains pending access.
- The separate Secret Manager repository owns `custodian-unseal.py` and the
  standby restart E2E. Terraform installs independent host credential timers
  on the three dedicated custodians. Each supplies only its own encrypted
  systemd credential, directly over verified TLS. Two custodians remain
  necessary; shares are not aggregated into Kubernetes or Terraform storage.
  The host-to-Pod policy admits only the custodian host addresses on TCP 8200.
- `database-sync-replica.tf` declares `db-h` as a full database member on the
  existing third DCS host. The authority extension preserves existing keys and
  credentials. Retired db-a configuration and data were moved aside and retained.
  A new replica cloned the current primary. HA elected db-h primary and db-b
  synchronous standby. Both surviving database proxies now know all three
  declared members. Strict synchronous commits were not disabled.
- CoreDNS and NodeLocal DNS read the persisted, provisioning-managed
  `/etc/kubernetes/resolv.conf` through a read-only mount, instead of depending
  on the Pod resolver file captured before host DNS was ready.
- The Flow Application declares three Redis/Sentinel replicas and a two-vote
  majority, with the dedicated hosts still excluded. The running healthy Redis
  primary was preserved and the two reachable Sentinels aligned to it. The
  original AOF set was copied and verified under a root-only host backup before
  the Redis checker repaired its invalid 183-byte tail. Future recovery is
  bounded to a 4 KiB corrupt tail; larger corruption must fail for inspection.
- HyperEVM used the exact same immutable image digest already cached on
  ichikawap1. An encrypted SSH stream imported it into p5's image cache while
  Harbor storage was unavailable. No user filesystem was copied this way.
  The existing PVC and **8192 MiB memory** setting were retained, and the
  existing disk headroom policy was kept. The normal ReplicaSet then created
  a healthy replacement on p5.

## Verification

- p1, p2, p3, p5 and ichikawap1 returned Ready. No user Pods were placed on the
  three dedicated custodians.
- Database role checks found a primary and streaming synchronous standby with
  zero `SyncRep` waiters.
- All three Secret Manager voters were unsealed with the same Raft cluster
  identity. A real standby recreation observed sealing, automatically unsealed
  without operator key access, retained the PVC, and became Ready in **42.549 s**
  using the published test. The earlier probe took 47.682 s.
- A gVisor cache fixture ran the exact HyperEVM image on p5 and exited successfully.
- The authenticated Chromium test opened `/root/projects/HyperEVM`, opened its
  README in the editor, exchanged WebSocket traffic, and passed a full reload.
  Its two checks returned HTTP 200 and held connections for five seconds each.
  The temporary incident credential was revoked after testing.
- Anonymous command-line HTTP 403 responses from the HeteroCloud public site
  carried Cloudflare error 1010. They must not be reported as origin HTTP 503.

## Remaining recovery dependency

Restore access to p4 and inspect its registry disk before changing or salvaging
the volume. Preserve the original replica, registry PVC, and retained database
directories. Once readable, rebuild registry copies on independent eligible
hosts, verify actual healthy copies and an authenticated image pull, and take
an independent registry backup. No empty replacement volume was substituted.

After p4 returns, apply its pending host recovery hook and database proxy
configuration, then repeat the storage and public endpoint checks. The system
is not fully redundant while a required replica host remains unreachable.
