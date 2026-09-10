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

The committed `heterocloud-functional-e2e.mjs` was rerun after these checks and
completed successfully at approximately 05:33 UTC, including the full idle
expiry wait and cleanup verification. Three independent fresh-context browser
sweeps also authenticated and passed 14/15 pages each, with only Syouyu failing.
This does not turn the complete browser suite into a pass.

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

## OIDC Deployment

HeteroCloud `1160279` adds sanitized failure-stage diagnostics and bounded
retries for idempotent discovery/JWKS reads only. Authorization-code exchange
is never replayed; redirects, issuer/signature validation and response-size
bounds remain enforced. Independent review found no production-code defect;
the shared-deadline regression assertion was subsequently strengthened.

Releases 0.1.68 and 0.1.69 did not publish images because their validation gates
failed on lint/formatting. They were marked prerelease and never deployed.
Release 0.1.70 passed all release validation, image publication, and CLI jobs
for Linux, macOS and Windows. GitOps commit `9de6bf84` pins its image index:
`sha256:ca9cbefeb0ad2573b607c92b33bcc02d29271a0d1a6ad2576ee4e33ee429f5ec`.

At 05:49 UTC, all four API, three owner-console and four worker replicas were
Ready on this image. Argo CD reported Healthy/Synced. A browser sweep during
the rolling update authenticated and passed 14/15 pages; only Syouyu failed.
Tenant Flash workload specs and containers were not changed by this rollout.

## Remaining Capacity Risk

A later cold login exceeded the browser's 15-second wait for the Keycloak
authentication POST. The runner originally left that response promise
unhandled while awaiting the click; `416b85bc` fixes evidence collection,
without suppressing the timeout. `08caff80` records sanitized form destinations
and POST timing. Subsequent sweeps authenticated, but these successes do not
prove that the historical tail-latency problem is eliminated.

Read-only diagnostics found `.5` withdrawn from the Keycloak edge pool at
05:50:49 after a 2,003 ms health timeout, returning at 05:51:25. The host has
roughly 4 GiB RAM and a shared rotational disk, elevated I/O PSI, and about
614 MiB swap in use. System processes consumed about 1.28 GiB and Pods 1.77 GiB.
API-server RSS was about 1.09 GiB, with no corresponding Pod memory request;
existing requested memory was already 96% of allocatable. System/kube
reservations total 1 GiB. This is a capacity-accounting gap, not evidence that
the authentication POST itself was conclusively attributed to one process.

At the diagnostic snapshot, the PostgreSQL primary had 110 idle connections
against a 300 limit, no blocked sessions/ungranted locks, and two synchronous
replicas with 12--30 ms lag. Keycloak's `.10` and `.5` pools had no waiters;
the cache view contained the expected three members. No database restart or
primary switch was performed.

`.8` has substantially more free memory, but its legitimate database bundle is
proxy-only and lacks the Keycloak provisioning secrets. It is selected by the
database autopilot, but reciprocal underlay eligibility has not converged;
its latest reachability list contained only itself. The 32-member ceiling is
not the blocker. Do not remove `.proxy-only`, copy full-member credentials, or
start a replica outside the authorized provisioning path. No placement or
static-Pod memory change was forced during this incident.

## Final Checkpoint, 06:12 UTC

The extended functional run completed at 06:11:42 with exit 0. Two Chromium
peers exchanged and verified an exact 13-byte payload in both directions with
normal ICE (selected host/host) and a diagnostic relay-only run (selected
relay/relay), confirmed using DataChannel and candidate-pair statistics.
Flash `pwd` succeeded without page errors. The room subsequently returned 404
and disappeared from its scoped list; all four issued contexts were revoked.
This is not a load test, a separate-LAN NAT matrix, or SFU media coverage.

An earlier media attempt failed because the test omitted `flow.signal.connect`;
it was diagnosed as `permission_denied`, not a production signaling defect.
Its room also expired and its contexts were revoked. The corrected runner adds
an explicit permission preflight and preserves failed-run evidence.

The final three cold browser sweeps all authenticated, with observed Keycloak
POST responses in 3,085 ms, 866 ms and 199 ms. Each passed 14/15 pages; each
failed Syouyu readiness and its credential API 409. HeteroCloud remains on
0.1.70, Argo Healthy/Synced, with all expected API/owner/worker replicas Ready.
Escape retained the same Pod UID and restart count.

No complete-suite pass or complete-HA claim is justified. Approved management
access to the original Syouyu storage host is still required, and the `.5`
capacity risk described above remains. Pre-existing local Registry/Argo resource
edits were not committed, reverted, or applied by this recovery.
