# Single-node reboot chaos test: 2026-08-14

## Scope

This test rebooted every node that was Ready at the start of the run, one at a
time, in a seeded random order. The next fault was not injected until the
Kubernetes API, etcd quorum, and application workloads had converged.

- Seed: `1786681997797262136`
- Fault: operating-system reboot of the VM or physical host
- Failure cardinality: one node at a time
- Ready nodes tested: 6
- Pre-existing unavailable node: `mizuame` (`10.250.0.2`), NotReady since
  before the test and unreachable over SSH; it was excluded from the fault pool
- Window: 2026-08-14 04:34-06:16 UTC

The external monitor sampled these endpoints every two to three seconds:

- `https://flow.heterocloud.mizuame.app/openapi.json` (expected 200)
- `https://heterocloud.mizuame.app/` (expected 200)
- `https://heterocloud.mizuame.app/api/v1/auth/oidc/start` (expected 303)

A second monitor sampled Kubernetes `/readyz`, Ready node count, Flow
Deployment readiness, and HeteroCloud available replicas from a node other
than the fault target.

## Randomized run

| Order | Node | Reboot started | Node recovery | Full workload recovery | Observed impact |
| ---: | --- | --- | --- | --- | --- |
| 1 | `uc-k8sp2` | 04:34:16 | about 4m12s | about 8m07s | API stayed ready; transient external 500/503 responses |
| 2 | `uc-k8sp1` | 04:43:32 | recovered automatically | about 8m52s; etcd 5/5 at about 9m40s | API stayed ready; OIDC was unavailable for about 42s and external errors recurred during convergence |
| 3 | `uc-k8s3p` | 04:53:54 | about 2m | OIDC stable after about 7m47s | API quorum survived; public Flow/Cloud had roughly one minute of interruption |
| 4 | `uc-k8sv1` | 05:14:44 | manual repair at 05:25:06 | recovered after repair | kubelet could not resolve its local API hostname after boot |
| 5 | `mizuame-nucboxg5` | 05:37:59 | Ready in 2m10s; SSH in 2m17s | all monitored workloads in 5m05s | API stayed ready; OIDC and public endpoints were intermittently unavailable during convergence |
| 6 | `ichikawap1` | 05:46:02 | Ready in 3m15s | 3m51s | API stayed ready; HeteroCloud fell from two replicas to one; public endpoints stabilized in about 3m30s |

The first run therefore passed control-plane quorum survival but did not pass
a strict zero-failed-request HA criterion.

## Defects found and repaired

1. Overlay hierarchy reconciliation could replace explicitly pinned
   infrastructure peers. Commit `ff19a96` preserves those peers as direct
   WireGuard peers.
2. Caddy active health checking treated a transient failure behind one
   Kubernetes Service VIP as failure of the whole Service. HeteroCloud commit
   `ce865db` uses the in-cluster Service name without that service-wide active
   health decision and removes stale public-IP backends.
3. `heteronetwork-overlay-dns.service` stopped with the agent and was not
   restarted. Commit `ab7e879` makes it restartable and orders kubelet after it.
4. Cloud-init rewrote `/etc/hosts`, removing the local kube-apiserver HAProxy
   name. Commit `515af89` added a lower-precedence cloud-init guard, but a
   NoCloud instance `user-data` value still overrode it. Commit `8dd9bfa` adds
   `heteronetwork-kube-api-host.service`, ordered after cloud-init and required
   before kubelet, to restore the entry on every boot.
5. Flow application Pods could be scheduled on a worker without a local
   PostgreSQL proxy while the proxy Service used `internalTrafficPolicy:
   Local`. Flow commit `14780e3` changes it to `Cluster`; Argo CD applied the
   change and the six crash-looping Pods recovered.

The first targeted regression reboot at 06:04:37 UTC confirmed that the
cloud-init guard in `515af89` was insufficient and again required manual host
entry repair. The final API-host service from `8dd9bfa` was then installed on
all six Ready nodes. A second targeted regression reboot of `uc-k8sv1` started
at 06:13:36 UTC. Without manual intervention:

- the boot ID changed;
- `heteronetwork-kube-api-host`, the agent, overlay DNS, and kubelet were active;
- `/etc/hosts` contained `127.0.0.1 k8s-api.heteronetwork.internal`;
- the host repair ran at 06:13:59 and kubelet entered active state at 06:14:00;
- Flow returned to full Deployment readiness by 06:14:25 (49 seconds);
- no external monitor state change was observed during that regression reboot.

## Post-test verification

- Kubernetes `/readyz`: passed
- etcd: 5/5 endpoints healthy, 15-93 ms in the final check
- Flow Deployments: all desired replicas Ready
- Flow Redis StatefulSet: 3/3 Ready
- HeteroNetwork Web UI over the VPN: 36/36 source/destination combinations
  returned HTTP 200 across the six Ready nodes
- Each direct Flow origin (`.51`, `.52`, `.53`, `.61`): 20/20 HTTP 200
- Each direct HeteroCloud origin: 20/20 HTTP 200 and 20/20 OIDC HTTP 303
- Flow WebRTC E2E, normal ICE policy: 2/2 rooms passed through DataChannel ping/pong
- Flow WebRTC E2E, forced relay policy: 2/2 rooms passed with relay/relay
  selected candidates

## Remaining HA gaps

1. `mizuame` is still offline. This run proves the six-node active set, not the
   unavailable seventh Kubernetes node.
2. HeteroCloud requests four API and four worker replicas, but only two of each
   are schedulable with the current capacity-tier constraints. A single reboot
   therefore leaves only one available replica.
3. Flow uses multiple direct A records because TURN cannot sit behind the
   normal Cloudflare HTTP proxy. DNS does not remove an unhealthy origin, so a
   client can still select a rebooting public node. Health-aware authoritative
   DNS or a separate health-managed API hostname is required for a strict
   zero-failed-request objective.
4. The initial public-node reboots produced 500/502/503 responses while Pods,
   etcd, Keycloak, and gateways converged. Retries reduce user-visible impact,
   but they do not make the current result zero-downtime.

## Result

- Single-node Kubernetes control-plane quorum: **PASS**
- Automatic node recovery after the final repairs: **PASS**
- Six-node HeteroNetwork all-to-all reachability after recovery: **PASS**
- Flow normal and TURN-relayed E2E after recovery: **PASS**
- Strict external zero-failed-request HA across the complete randomized run:
  **FAIL**
