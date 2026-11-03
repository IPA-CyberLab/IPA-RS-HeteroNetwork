# Coder workspace and HeteroCloud rollout, 2026-11-03

## Coder workspace

The `ramen` workspace reported that its agent was connecting, but Flash had no
workload pod. Its existing build still referenced an OCI index that was lost in
the previously approved registry reset. The current template instead uses the
verified platform image republished after that reset. The registry was serving
that image; this incident was a stale workspace build, not a registry outage.

The workspace was updated to its active template version. The image was the
only changed template variable, and the existing persistent volume retained
its identity and contents. Admission initially blocked the new workload: one
worker was below the configured disk reserve, and the other included a
short-lived reservation for the outgoing revision. After safely prefetching the
already verified image and expiry of that reservation, Flash started the pod.
The Coder agent became connected and ready.

Other stopped workspaces still using the discarded index can encounter the same
problem until they are updated to their active template version. They were not
started or modified as part of the `ramen` recovery.

## HeteroNetwork console acceptance

The GitHub-hosted VPN and Chromium test intermittently received HTTP 503 from
the authenticated `/v1/admin/overview` endpoint. VPN handshake, DNS and the
Grafana and Prometheus checks had succeeded. A repeat run passed, so a pass by
itself did not establish that the intermittent failure had been resolved.
During a failing run, the control plane logged a token-ledger read lasting
4.32 seconds; the agent's per-candidate administrative timeout is five seconds.
This timing is consistent with a timeout but does not by itself prove which
candidate produced the final 503.

The overview now fetches independent sections concurrently, obtains node
health and NAT classifications in batches, and calculates token counters in
PostgreSQL instead of transferring every token and its claims for each request.
On a read-only comparison against the live ledger, both implementations
produced the same counters while the returned payload fell from 1,467,787 to
19 bytes. A disposable PostgreSQL test checks expiry boundaries, revocation
precedence, tombstones, cluster isolation, and empty ledgers. The optimization
also passes a disposable PostgreSQL test with the return link restricted to
64 KiB/s: aggregate retrieval meets a three-second deadline while reading the
same full records exceeds it. The optimization reduces work; network and
database latency can still cause failures.

## Public API rollout

During a console rollout at 06:53 UTC, an external probe observed one HTTP 503.
Envoy recorded `no_healthy_upstream` during the transition between API
endpoints. A 75-second deployment readiness window was added and applied without
restarting API pods, allowing time for the observed 30-second DNS TTL and
gateway health checks before retiring an old replica.

The next rollout was still not fully clean: from 2,062 probes, 2,059 returned
200, two had transport errors and one returned 503 at 07:24:42 UTC. Envoy again
reported `no_healthy_upstream`; at approximately the same time Kubernetes
recorded an API readiness-probe timeout while one replica was being replaced.
Both serving API replicas were subsequently healthy. The readiness window
alone was therefore insufficient.

The gateway configuration now tolerates brief health-check failures, retains a
fallback when every endpoint is marked unhealthy, and limits passive endpoint
ejection to half of the pool. The OIDC callback still retries only connection
failures that occur before the request is accepted. Terraform published the
reviewed Git source and Argo CD applied both traffic policies.

An isolated `.invalid` test route exercised the live gateway with disposable
backends. Once Envoy had actually marked the only backend unhealthy, 127
requests succeeded with no errors while the backend still served traffic. A
second healthy backend was then introduced; after the unhealthy state was
observed, all 10 follow-up requests reached the healthy backend. The temporary
resources were removed. This tests the specific failure and failover behavior;
it does not guarantee zero errors under every node or network failure.
The live check is available as `scripts/e2e_heterocloud_gateway_failover.py`;
the policy invariants and its syntax are checked by infrastructure CI.

The subsequent HeteroCloud name-management rollout was monitored through the
public entrance. All 2,411 probes returned HTTP 200, with a maximum observed
response time of 1.002 seconds. This is evidence for that rollout only, not a
guarantee against other failures. Two replicas per component were serving;
the third desired replica remained pending while a worker node was offline.
