# 2026-10-25 power-loss recovery

## 要点

- 原因は、VPNの起動先が停止中の1台だけになっていたこと、DBの同期相手不在、
  シークレット基盤の封印、起動直後の空のDNS設定、Redisの末尾破損が連鎖したことです。
- レジストリは「3コピー設定」に対し実際はp4の1コピーだけでした。
  実コピーの検証と独立したバックアップの確認が不足しており、HAとして扱えない状態でした。
- 到達できる5台のVPN・DB・シークレット基盤を復旧し、Coder／HyperEVMの実ブラウザ試験、
  新規VPN接続、シークレット基盤の自動復旧、VPNの状態消失からの再起動試験が通りました。
- 実コピー数・ホスト・ディスクの状態を毎分検査します。コピー不足を正常扱いしません。
- **未復旧はp4に依存するレジストリです。p4の電源・LAN／管理コンソールでの確認が必要です。**
  元のディスクを保全したまま復旧し、その後に独立したコピーとバックアップを検証します。
- 以下の詳細記録と隣接するJSONに、実施した修正・検証結果・未完了の対策を記載しています。

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
   Longhorn's `allow-volume-creation-with-degraded-availability` was enabled;
   its Scheduled condition was reset to True under that setting even while the
   data volume was faulted. Configuration counts and Scheduled=True therefore
   did not demonstrate actual redundancy. The remaining
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
- `storage-recovery-audit.tf` installs a one-minute check of actual healthy
  replicas, Ready hosts, Ready disks and independent host counts. A configured
  count of three does not pass with one actual copy, and inventory errors fail
  closed. The check currently reports the registry as critical; installation
  does not declare unavailable data recovered. Its systemd service fails visibly
  while copies are missing. It does not delete, salvage or replace volumes.
- CoreDNS and NodeLocal DNS read the persisted, provisioning-managed
  `/etc/kubernetes/resolv.conf` through a read-only mount, instead of depending
  on the Pod resolver file captured before host DNS was ready. CoreDNS prefers
  spreading across physical hosts while permitting a rollout when one host is
  unavailable; user applications remain excluded from the dedicated custodians.
  A legacy `heteronetwork-dns` field manager retained its old hard anti-affinity
  rule when Argo added the preferred rule. A guarded Terraform adoption removes
  only that exact legacy rule, and spreading honors taints so dedicated masters
  are not counted as eligible empty placement domains.
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
- The actual deployed native Agent was started in two isolated Linux network
  namespaces with newly generated fixture keys and no control plane. Its dead-only
  bootstrap cache failed as expected. Both Agents were stopped, their kernel
  WireGuard interfaces deleted, and the approved-roster hook applied. Cold start
  then restored real bidirectional kernel handshakes and ping in **2.061 s**.
  No production Agent or VM was restarted. Terraform runs this E2E on the
  bootstrap host, and the Actions workflow requires the same test with checked
  helper digests.
- A newly registered temporary VPN client established a real WireGuard
  handshake, exercised split DNS and Chromium, and opened the canonical internal
  console in **252 ms**. All ten HTTP 80/9781 checks over the five reachable
  gateways passed in 138–266 ms. Grafana and Prometheus returned HTTP 200 on
  both reachable monitoring hosts. The temporary client was removed afterward.
- Public Chromium checks returned HTTP 200: HeteroCloud home **583 ms**, login
  **349 ms**, Coder **1622 ms**.
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

## Storage follow-up gates

Do not disable degraded-volume attachment during this recovery: it is also used
when reattaching an existing volume with a surviving partial replica set. The
installed Longhorn controller and [upstream implementation](https://github.com/longhorn/longhorn-manager/blob/v1.12.1/controller/volume_controller.go)
use it when no current attachment exists. Turning it off while p4 is absent
could prevent existing workloads from recovering on the two surviving workers.

After recovering the registry source, restore independent copies and verify
capacity for the declared replica count before enforcing strict provisioning.
The [Longhorn setting reference](https://longhorn.io/docs/1.13.0/references/settings/#allow-volume-creation-with-degraded-availability)
recommends disabling degraded creation in production. That policy transition,
registry backup/restore verification and a full storage-host loss drill remain
open; a minute-by-minute block-copy audit is detection, not a replacement for
those durability checks. Application-level replication (for example Garage) is
separate from the block-copy audit and must be assessed at its own quorum layer.
