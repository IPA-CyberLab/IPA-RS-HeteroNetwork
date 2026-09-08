# OIDC Availability Recovery: 2026-09-08

## Observations

The public `/api/v1/auth/oidc/start` endpoint returned HTTP 503 with
`identity_provider_unavailable`. Internal metadata requests to healthy VPN
Keycloak edges succeeded with the expected issuer and backchannel endpoints.
The internal console DNS name could resolve to an edge returning 503; hostname
resolution was also intermittently slow. A healthy API Pod alone did not imply
that its identity-provider dependency was reachable.

An isolated public request recovered to 303 before the routing change, but the
third request of a subsequent three-attempt check failed with 503. Do not
attribute that transient recovery to the connector deployment.

Keycloak autopilot logs independently showed failed control-plane calls and
expired local assignment leases. Enrollment-time endpoints included unavailable
nodes and the local Agent gateway was not listening. The promotion file holds
a base secret, whereas enrollment uses a node-derived bearer; comparing those
raw values is not evidence of credential rotation. Local recovery must retain
the server's cluster/node-scoped derivation and authorization checks.

## Routing Change

`deploy/gitops/cluster-dns/keycloak-ha-connector.yaml` provides a private
ClusterIP Service and one small connector per eligible Linux node. Each derives
its upstream from `status.hostIP`, not a list of physical IPs. Its readiness
depends on successful Keycloak realm discovery through that node's edge.
Kubernetes removes unready connectors from Service routing and restores them
when their dependency recovers. Credential POSTs are not retried.

The reserved `10.96.180.79` address is a Kubernetes virtual Service address.
HeteroCloud API and owner-console Pods map the existing OIDC hostname to this
address via chart `hostAliases`. This preserves Keycloak Host/issuer checks and
does not alter public DNS or other machines' console hostname resolution.
The image remains 0.1.66; the Helm source is pinned to commit `b3e033b`.

Initially three connectors were ready and the failing node was excluded. Four
became ready after that edge recovered. This is dependency-aware routing, not
proof of four independent healthy Keycloak server processes.

## Verification

The autopilot fix also prefers an active, root-configured local control plane
whose cluster, node and VPN listener match the local identity. It derives the
node bearer using the existing control-plane protocol; the base secret is never
sent as a bearer. That credential is scoped to the exact local endpoint, while
configured remote fallbacks retain their enrollment credential. Failure logs
include sanitized endpoint, HTTP status and curl exit code, not secrets or
response bodies. The focused shell regression includes an independent SHA-256
golden value, credential scope checks and secret-leak checks.

The updated script was deployed to ichikawap1 and uc-k8s3p. Both automatically
started their previously stopped Keycloak replicas, returned readiness HTTP
200, and renewed assignment leases. Other nodes were not claimed as updated.
SSH verification for uc-k8sv1 was not bypassed when its host key differed from
the saved key; the separate Tailscale reauthorization prompt for the private
worker was not bypassed either.

Run from an operator host with VPN and Kubernetes access:

```sh
KUBERNETES_API_SERVER=https://10.250.0.10:6443 \
  python3 scripts/keycloak-connector-preflight.py
```

This checked the API/owner Pod hostname mappings, multiple ready connector
nodes, and ten successful metadata responses with exact issuer/token/JWKS URLs.

Run the external, credential-free login-page check:

```sh
bash scripts/keycloak-ha-e2e.sh --public-only --attempts 10
```

After switching the API and owner console, this passed ten consecutive public
OIDC starts and login-page checks, including login assets and registration page.
It does not submit user credentials or prove an authenticated callback/session.
A later repeat on the coding host failed while resolving the public hostname
for a CSS request, before an origin connection. Subsequent ten-attempt runs on
both the coding host and ichikawap1 passed; the isolated client-side DNS failure
is recorded rather than counted as a successful attempt.
After the two replica recoveries, another ten-attempt public check passed and
the internal metadata preflight passed with three ready connector nodes.

Existing Flash Pod UIDs and restart counts were unchanged: nginx remained at
zero and escape at its previously recorded one OOM restart. No tenant container
was restarted. The pre-existing two unavailable Kubernetes nodes remain outside
this recovery; full cluster HA is not claimed.
