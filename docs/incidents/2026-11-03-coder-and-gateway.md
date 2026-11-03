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
Both serving API replicas were subsequently healthy. The readiness window is a
partial mitigation, not evidence that rollout-related 503s are eliminated.
The gateway's one-failure active health check and full endpoint ejection need
further investigation and a tested correction.
