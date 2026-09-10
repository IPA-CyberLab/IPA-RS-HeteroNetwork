# Cloud Recovery, 2026-09-10

## Confirmed Recovery

The public DNS inventory retains the reviewed `.53` and `.61` front doors
independently of transient Gateway address withdrawal. Public Chromium checks
reach the homepage and the actual Keycloak form through normal DNS and TLS.

Agents had persisted a discovered control-plane directory reachable only over
the broken overlay. Existing local promoted control planes were healthy, but
were not used to renew membership. Recovery used the existing authenticated
agent override, without changing node identity, trusted issuers, or membership.

Commit `bed2a7af` retains operator-trusted seeds and puts the promoted local
control plane in the managed agent service drop-in. The public-service helper
also retains staged services during transient local-agent status failures.

At 05:16 UTC, Kubernetes reported `.10`, `.6`, `.5`, and `.8` Ready. `.3`
remained NotReady; `.4` remained NotReady and cordoned. API readiness and an
etcd committed health proposal were verified. This is not full fleet recovery.

## Rollout

The daemon built from the recovery source has SHA256
`d14ac32194ed055156645177b0ce036394818030a42dd93a27d239afe8b3dfd5`.
Its build report is `0.1.0`, commit `bed2a7a`; this is a recovery build, not a
new versioned release. The helper SHA256 is
`0f4d3bbcf9437ca1e8fe07d8cf86a9534434316988c1c103a8001523f1ab03fd`.

- `.6` and `.8`: installed atomically; normal helper reconciliation restarted
  the agent; managed `40-public-control-services.conf` contains the local CP;
  API readiness and Node Ready confirmed afterward.
- `.6`: the temporary `60-local-control-plane-recovery.conf` was removed only
  after verifying the equivalent managed `40` setting; daemon-reload followed.
- `.5`: permanent artifacts installed; build `bed2a7a`, agent active and API
  readiness verified. Temporary `60` removed after matching managed `40` was
  confirmed, followed by daemon-reload.
- `.10`: labelled artifact installed atomically; one bounded agent restart;
  build `bed2a7a` and API readiness verified afterward.
- `.3` and `.4`: no deployment; management access is unavailable.

Roll one agent at a time, verify quorum/API and fresh paths between changes,
and do not restart tenant containers as part of this repair.

## Browser And Functional Evidence

The credentialed browser sweep requires actual JSON read models and Ready
service details, not just successful HTML responses. It fails on Syouyu's
provisioning state and credential API 409. Optional Cloudflare analytics blocked
by the existing CSP is recorded separately; production CSP was not weakened.
Navigation waits for outstanding reads, including Flow metrics/history, rather
than aborting them with the next route change.

The 05:14 UTC sweep authenticated and passed 14 of 15 pages; Syouyu detail
failed. An earlier callback at 05:10:47 returned 503 after approximately ten
seconds on `.5`. Historical logs do not distinguish discovery, token exchange,
and JWKS, so a definitive substage cause is not established. A subsequent
success does not establish reliable authentication under failover.

Independent own-fixture checks verified Flow room create (201), join (200),
read-back (200), and automatic idle expiry (subsequent 404 and absence from the
room list; no room-delete endpoint is exposed).
Both temporary access contexts were revoked (204). Flash Web Shell executed
`pwd` and disconnected without page errors. These checks do not constitute a
new full WebRTC media/NAT traversal test.

Private browser reports and credentials are not committed. The existing escape
Pod retained UID `08942b6b-7a5d-408d-9a88-16acfbe24b40`, Running, restart count 1
from before this recovery. No tenant workload restart was requested.

## Syouyu Recovery Blocker

Garage has one reachable original member on `.10`; the other original data/meta
pairs are strict-local volumes on `.3` and `.4`. Both hosts and their Longhorn
instance managers/disks are unavailable. All four affected volumes are faulted
and detached, with queued but unexecuted automatic salvage. No last-backup
reference is recorded. Replacing these pairs with empty storage is not recovery.

Restore approved access to an original host, inspect its original disk mount,
UUID, replica directories and readable metadata/data, then restore stable node
and storage-controller connectivity. Review the pending salvage before allowing
it to proceed. Preserve Garage member identities and verify synchronization and
normal write quorum. Do not force a one-member quorum, new layout, volume
deletion, or empty replica substitution.

The separate API egress bug is fixed in `fa16e220`: policy now allows the
reviewed post-DNAT Kubernetes API node addresses. Registry health is restored,
but this network-policy repair cannot restore missing Garage data members.

Full authenticated E2E remains failed until Syouyu recovers. Redis failover data
continuity remains unverified; see `flow-recovery-evidence-2026-09-10.md`.
