# Front Door Recovery, 2026-09-15

The previous master-join verification covered Kubernetes API and DNS smoke
checks. It did not run the application or browser E2E suites. The reported
console connection refusal and HeteroCloud 503 were reproduced during this
recovery; a successful join was not evidence that either application worked.

## Applied Recovery

The console Agent served the overlay UI on port 80 while the reported URL used
9781. On the four reachable gateways (10.250.0.2, .4, .6, and .10), a systemd
Agent drop-in now sets `HETERONETWORK_AGENT_OVERLAY_WEB_UI_PORT=9781`.
`heteronetwork-console-proxy.service` also preserves the canonical portless
console URL by forwarding port 80 through HAProxy to the local Agent on 9780,
with the canonical Host check and the local Host/Origin rewrite.
Both listeners are enabled across restarts. Host overlay DNS now uses these
four reachable servers, excluding the unavailable .5 and removed .8.

PostgreSQL had lost DCS quorum. The db-d node's Tailscale address had changed
from 100.92.62.45 to 100.92.62.44, and the db-c/db-e voters were unavailable.
Recovery restored the existing quorum before changing membership; it did not
create a new etcd cluster. The live db-a/db-d/db-f DCS now has three voters,
with db-d's peer/client URLs and certificate updated to its actual address.
The original db-d data was backed up before Patroni reinitialization.
Autopilot control-plane URLs now try the healthy private endpoints first.

The standard PostgreSQL autopilot and node helper were installed on uc-k8sp5.
Its local proxy and Kubernetes connector passed PostgreSQL SSL negotiation.
Autopilot subsequently applied topology revision 10, adding db-b on uc-k8sp5
as a PostgreSQL streaming replica while retaining the three DCS voters.

uc-k8sp5's Agent explicitly disables the public web gateway, but automatic
public-IP discovery had made it eligible for Kubernetes ingress. A direct
origin check found port 443 refused on 163.220.236.45. The node now carries
`networking.heteronetwork.io/public-ingress-enabled: "false"`; its public
ingress label is false and .45 was withdrawn from the Gateway Service.
The master and its internal services remain registered.

The Kubernetes etcd endpoint on uc-k8sp1 could not complete health checks or
API operations promptly. After verifying quorum on .2/.6/.10 and saving a
snapshot, its process was restarted with the existing data and member identity.
Graceful shutdown stalled, so that process required SIGKILL. Startup replayed
the existing WAL and caught up, but health checks still timed out. The API
clients on uc-k8s3p, uc-k8sp1 and ichikawap1 were therefore configured through
the standard node helper to use the verified .10/.2/.6 etcd endpoints.
No Kubernetes voter was removed as part of this front door repair.

ichikawap1 returned healthy local application/reporter responses while their
Kubernetes Ready flags remained false. Its kubelet logged readiness updates
for unknown containers. CRI RuntimeReady/NetworkReady and container/sandbox
listing passed, so kubelet was restarted. Its own API also retained the
slow etcd endpoint, and the old API process continued using that setting after
the manifest update. That old API process required a forced stop after its
graceful shutdown stalled. The kubelet's live `/pods` view still held the old
file-source manifest even though its filesystem contained the new one; a second
kubelet restart was required to read the corrected manifest from startup.

The owner-console and node-reporter Pods were replaced individually after
their three old containers were explicitly stopped and CRI confirmed none
remained running. The new Pods were assigned to ichikawap1, but kubelet only
received them on its third restart and still failed to process subsequent
updates. A goroutine dump then identified the main sync loop blocked in
`cleanupOrphanedPodDirs`, calling `stat` on an abandoned Harbor registry Pod's
NFS volume. The blocked syscall waited for RPC from the old Longhorn NFS
endpoint 10.104.89.108. The old Pod UID was absent from the cluster and had no
running containers.

The abandoned mount was lazily detached with canonicalization disabled, so
the unmount command did not itself wait on NFS. Its shared mount propagation
also removed redundant stacked layers; the current registry Pod's mount and
the CSI global mount each retained their base layer. No PVC, PV, or volume
data was deleted. After a fourth kubelet restart, the main sync loop resumed.
A fresh Pod annotation and its removal were both observed in kubelet's live
`/pods` view. The new owner console is 2/2 Ready, the new node reporter is
1/1 Ready, and the existing network controller recovered to 1/1 Ready.
The Gateway Service now publishes .51/.53/.61.

The three running tenant Pods captured on this host retained their UIDs,
container IDs and restart counts across all four kubelet restarts. The
continuity report, goroutine dump and original mount table are preserved with
the node-state backup.

## Verification And Limits

| Check | Result |
| --- | --- |
| Console HTTP, each of four VPN gateways on 80 and 9781 | 8/8 HTTP 200 |
| Committed `heteronetwork-console-e2e.sh` | Pass: canonical DNS/UI, configuration, Device Authorization, verification page and owner-console link |
| Chromium at the exact console 9781 URL and portless URL | Both render the login UI; assets/configuration load; no JavaScript errors |
| Chromium console Device Login button | Opens the public HeteroCloud username/password form; no JavaScript errors |
| Committed public HTTP portion of `heterocloud-ha-e2e.sh` | Pass on .51/.53/.61: five health requests per origin, homepage, OIDC start, discovery and login form; normal public path passes 20 health requests and OIDC |
| `keycloak-ha-e2e.sh --public-only --attempts 10` | Pass, 10/10 login starts including assets/registration checks |
| Public Chromium diagnostic | Homepage 200 and actual login form, no errors; explicit diagnostic exit 2, not a full pass |
| Standard PostgreSQL HA verification, revision 10 | Pass: three DCS voters, one primary, three streaming replicas, at least one synchronous replica |
| Full `heterocloud-ha-e2e.sh` | Fail: mizuame-nucboxg5 and uc-k8sp2 are NotReady |
| Authenticated browser/service sweep | Not run in this initial recovery: archived E2E credentials were overlooked; see the subsequent console-auth recovery report |

The unauthenticated refresh request returning 401 in the console is expected;
it is followed by the rendered login screen. Opening an authentication form
does not verify a submitted login or the OIDC callback.

This is not full fleet recovery. API and worker deployments each have 3/4
Ready replicas, constrained by the two unavailable hosts and uc-k8sp1's
existing cordon. The owner-console deployment has 3/3 Ready replicas.
uc-k8sp1 remains cordoned; its etcd latency is unresolved.
Storage salvage and the previously documented Syouyu recovery were not
performed. Their previous failures must not be converted to a full E2E pass.

Private browser screenshots and machine-readable reports are saved under
`artifacts/recovery-2026-09-15/` and are not committed. The directory contains
the public diagnostic, exact console URLs, Device Login form, and a summary
that explicitly separates passing checks from unrun or failed suites.

## Preserved Backups

- uc-k8sp1: `/var/backups/heteronetwork/20260915T0255Z-db-d-pre-reinit/`.
- uc-k8s3p: `/var/backups/heteronetwork/20260915T0305Z-dcs-r8/`.
- ichikawap1: `/var/backups/heteronetwork/20260915T0415Z-kubernetes-etcd/`.
- uc-k8s3p, uc-k8sp1 and ichikawap1: `/var/backups/heteronetwork/20260915T0418Z-api-etcd-backends/`.
- ichikawap1: `/var/backups/heteronetwork/20260915T0422Z-kubelet-state/`.

Temporary compatibility routes, old-IP aliases, packet-filter exceptions,
Agent pauses/masks, and HTTP test servers were removed. Persistent backup
copies remain root-protected for recovery review.
Temporary SSH key copies and database bundle archives were removed, and the
test SOCKS tunnel and SSH sessions were closed. The original user-provided
archive remains in the workspace.

The later login failure and authenticated tests are recorded in
`docs/console-auth-recovery-2026-09-15.md`. That recovery corrects the console
issuer to the actual public Keycloak issuer while preserving private
backchannels and the configured owner identity.

The subsequent node-service recovery is recorded in
`docs/node-services-recovery-2026-09-15.md`. It enables uc-k8sp5's
HeteroNetwork public services and verifies all six updating assignments.
Its Kubernetes ingress override remains false. uc-k8sp2 still requires a
working host management connection.
