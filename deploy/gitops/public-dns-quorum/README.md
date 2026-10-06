# Public gateway DNS with majority observations

Three observers run on distinct, explicitly selected physical nodes. Every five
seconds each checks the configured public IP directly, verifies HTTPS with the
probe hostname as SNI, checks the exact gateway response, and checks the HTTP
redirect. The probe traverses Caddy and Envoy without invoking a tenant container.

Each observer uses a separate ServiceAccount and can patch only its own vote
ConfigMap. Publishers can read these votes and update their own state and only
the public `heterocloud-web-gateways` DNSEndpoint. Secret Manager's VPN-only
DNS is a separate DNSEndpoint outside their RBAC permissions. No Cloudflare
token, private key or user credential is mounted into these workloads.

The electorate is fixed by `pool.json`, not by whichever observers are currently
reachable. With three members a decision needs two fresh, matching votes. Missing,
expired, malformed, future or differently configured votes are unknown, not failed.
They cannot lower the required majority or authorize DNS withdrawal.

Three new majority samples are required to remove an origin; two to re-add it.
The same sample cannot count twice, including across publisher replicas or restarts.
State is durable in a ConfigMap and updated with UID/resourceVersion preconditions.
Two publisher replicas elect a writer through a 45-second CAS lease. Each takeover
fences the DNS resource before consuming observations, preventing a delayed old
publisher from overwriting a newer writer. DNS patches test the resource UID,
version and original endpoint entries, then change only the managed targets.

ExternalDNS remains the only Cloudflare writer. Argo CD retains ownership of
the DNS names, TTL, provider settings and deployment inventory; it ignores only
the quorum publisher's target fields and writer annotation. Runtime vote/state
ConfigMap data is also ignored. Argo therefore does not undo a failure exclusion.

`enabled: false` observes and records decisions without changing DNS targets.
Production is staged in this mode and enabled only after all observers and public
probe routes are verified. The published pool contains the commissioned public
gateways; this does not automatically commission new public IP addresses.

If a majority is unavailable, published DNS is retained. If every origin is
confirmed unhealthy, `all_down_policy: retain` keeps the last DNS targets and
records `all_down: true` / `all_down_retained: true`; it does not label the targets
healthy. This avoids negative DNS caching delaying recovery during a complete
outage. `all_down_policy: withdraw` instead empties the managed target arrays
after the full failure quorum, if that behavior is required by the operator.

Normal failure exclusion takes three 5-second observations, plus ExternalDNS's
5-second reconciliation. DNS TTL is currently 60 seconds; resolvers can retain
older answers until their cache expires. Publisher failover can additionally wait
for its 45-second lease. This is DNS failover, not instantaneous traffic failover,
and three distinct nodes do not imply three independent ISPs or regions.

Observation timings, membership, probe name and addresses are configuration, not compiled
hostnames. After changing `pool.json`, regenerate `workloads.yaml` with
`python3 deploy/gitops/public-dns-quorum/render.py`. Configuration changes invalidate
old observations before they can affect the new membership or origin inventory.

Tests cover majority loss, an isolated observer, failure/recovery hysteresis,
sample replay, stale observations, configuration changes, field ownership,
least-privilege RBAC and placement outside Secret Manager's dedicated nodes.
The live verifier uses its own namespace/DNS record and blocks only its own
observer Pods' egress to simulate failure. It does not stop a production gateway,
alter a tenant container or require a paid load-balancer subscription.
