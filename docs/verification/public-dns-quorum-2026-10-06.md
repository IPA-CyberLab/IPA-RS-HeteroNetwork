# Public gateway DNS majority verification — 2026-10-06

Public HTTP/HTTPS entry points now use a fixed three-observer majority to exclude
failed IP addresses and restore recovered ones. The production DNS pool contains
`163.220.236.54` and `163.220.236.61`. Its observers run separately on
ichikawap1, uc-k8sp4 and uc-k8sp5; two matching fresh votes are required.

Three new majority observations remove an origin; two restore it. Each observer
can patch only its own vote, and a sample cannot count twice. Lost, stale or
malformed observations retain existing DNS instead of lowering the denominator.
Two publisher replicas share a durable, fenced 45-second writer lease. ExternalDNS
uses the existing Cloudflare credentials to apply the resulting targets; no paid
load-balancer subscription was created.

Terraform created the Argo CD Application and target-field ownership rules.
The initial Git publication moved private Secret Manager DNS to a separate
DNSEndpoint before installing the target-field ignore rules, preventing an array
index change from copying private IPs into the Flash wildcard. The publishers
cannot patch the separate private resource. Issuer, certificate and user workloads
were retained. Both Applications are Synced/Healthy and the targeted Terraform
plan is unchanged. Omitting empty core API-group strings also removes recurring
plan differences caused by Argo normalizing those optional fields.

Production was first deployed with `enabled: false`. All three observers submitted
fresh votes and both entry points reached a healthy majority before publication
was enabled. HTTPS checks against `.54` verified the platform homepage, login,
OIDC start, Flow live health, Registry authentication response, S3's unauthenticated
response and a currently running Flash endpoint. Public Secret Manager access
still returns 403. The previously referenced nginx service URL returned 404 on
the new origin; the current Flash endpoint returned 200 on both origins.

One observer reports its own `.61` public entry point unreachable while the other
two reach it. The cause of that observer's route difference was not established
in this change; the majority correctly tolerates the single failed observation.
The final failure test therefore chooses the origin initially reachable from all
three observers, so isolating one observer actually introduces exactly one
negative vote.

Twenty offline regression tests passed. The final live acceptance passed nine
checks with real Pods, HTTPS gateways, ExternalDNS and authoritative Cloudflare
DNS. It verified separate physical nodes and actual RBAC denial, publication of
both origins, one-observer isolation, majority-driven removal, complete-outage
reporting, quorum loss, recovery and publisher failover with a changed writer
fence. The verifier blocks only its own observers' egress. It does not stop a
production gateway or alter a tenant Pod. Both fixture namespaces and their DNS
ownership records were removed.

The production `all_down_policy` is `retain`: when all origins are confirmed
unhealthy, DNS is retained and the status reports an outage instead of presenting
the origins as healthy. This avoids negative DNS caching delaying recovery.
Operators can explicitly select `withdraw` to empty the managed targets after
the full failure majority. That option has offline coverage; the production and
live complete-outage checks used `retain`.

The DNS TTL is 60 seconds. Normal exclusion also includes three 5-second samples
and ExternalDNS reconciliation; writer failover can wait up to its 45-second
lease. This is not an instantaneous failover guarantee, and three physical nodes
are not necessarily three independent networks or regions.

[Infrastructure acceptance on the enabled implementation](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/37438953556)
passed the real Actions VM VPN join, Chromium UI checks, actual identity-provider
login, session restoration and Grafana/Prometheus access. The canonical console
opened in 871 ms; gateway checks ranged from 530 to 2,703 ms, below the unchanged
3,000 ms gate. The previous run of the same code timed out while checking
monitoring after VPN route convergence; it removed its client. The successful
run was started after production deployment and is recorded separately.

Seven existing running Flash Pods retained their UID, node, restart count, limits
and persistent claims. Secret Manager's VPN-only addresses remained unchanged.
No credentials, TLS keys, user environment values, SSH keys or recovery archives
are included in the [sanitized result](public-dns-quorum-2026-10-06.json).

See [configuration and failure semantics](../../deploy/gitops/public-dns-quorum/README.md).
