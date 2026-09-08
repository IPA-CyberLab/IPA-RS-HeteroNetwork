# OIDC Recurrence After Initial Recovery

## Evidence

At the recurrence, public OIDC start returned 503 and all four Kubernetes
connectors were unready. On ichikawap1, Keycloak readiness on 19000 and realm
discovery on 18080 returned 200, while the edge proxy on 18079 returned 503.
The edge log reported no usable servers. Its recovery required 30 consecutive
checks at two-second intervals and a single passive connection error could
mark a backend down. Reconciliation also reloaded the proxy during this period.

Agent restarts at 13:56:57 and 13:58:30 UTC interrupted local identity discovery.
Autopilot then expired the assignment and stopped Keycloak; it started again
after authenticated reconciliation resumed. The cause of those Agent restarts
was not established, and they were not initiated as a fault test in this task.

The original connector implementation depended on edge-proxy health rather
than actual replica health. Therefore the previous successful short checks did
not establish that the original outage was durably fixed.

## Changes

- Kubernetes connectors now check and route directly to each node's Keycloak
  backchannel on 18080. The client-facing port and OIDC Host remain unchanged.
- The edge proxy requires two successful checks for recovery, has a ten-second
  slow start, and tolerates three passive errors before marking a server down.
  Single-use credential/code POSTs are still not retried.
- Connector DaemonSet rolling updates use surge with zero unavailable Pods.
  Nodes with no local replica no longer block updating healthy connectors.
- If Agent status is unavailable, autopilot can use a root-owned local control
  plane identity only after cluster, node, active service, exact listener,
  currently assigned VPN address, and node-derived credential validation.
  It still needs successful authenticated reconciliation to renew a lease.
  Missing identity/address, inactive CP, or failed reconciliation still enforce
  lease expiry; this is not an unbounded stale-state grace period.
- The systemd unit permits AF_NETLINK for read-only address inspection. Other
  sandbox restrictions remain in place.

The helper/autopilot/unit changes were installed on ichikawap1 and uc-k8s3p.
The connector change is managed by Argo CD. Existing Flash workloads were not
reconfigured for this work.

## Checks

- The bounded autopilot smoke suite covers the fallback, invalid identity,
  missing address, stopped CP, failed reconciliation, and secret handling.
- An isolated read-only systemd invocation validated local identity without
  calling Agent status, with address-family and filesystem restrictions enabled.
- The extended connector preflight verifies that every ready connector uses
  port 18080, not the old edge-proxy route, and checks exact OIDC metadata.
- `scripts/keycloak-login-soak.py` repeatedly runs the existing credential-free
  public login-page check for a bounded duration. It reports every failure and
  exits nonzero if any check fails; failures are not silently retried away.

```sh
python3 scripts/keycloak-login-soak.py --duration-seconds 600
```

This checks start redirects, login/registration pages and assets. It does not
submit user credentials, test an authenticated session, or prove complete
cluster HA. Direct-origin requests from the coding host did not pass ordinary
public-CA verification; TLS verification was not disabled for the public soak.

## Final Result

The public soak completed 600 seconds with 35 checks and zero failures. Final
internal preflight passed ten exact-metadata checks across three ready nodes:
ichikawap1, uc-k8s3p and mizuame-nucboxg5. The two updated control-plane nodes
retained active Keycloak replicas and renewed leases; the final five-minute
ichikawap1 autopilot log had no unavailable, failed or expired messages.
Existing tenant Pod UIDs/restart counts remained unchanged (nginx zero,
escape its previously recorded one). No production Agent restart was induced
for this verification.
