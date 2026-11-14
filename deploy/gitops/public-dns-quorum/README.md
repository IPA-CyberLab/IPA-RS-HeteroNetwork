# Public gateway DNS with majority observations

Observers run on distinct, explicitly selected physical nodes. Every five
seconds each checks the configured public IP directly, verifies HTTPS with the
probe hostname as SNI, checks the exact gateway response, and checks the HTTP
redirect. The probe traverses Caddy and Envoy without invoking a tenant container.

Each observer uses a separate ServiceAccount and can patch only its own vote
ConfigMap. Publishers can read these votes and update their own state and only
the public `heterocloud-web-gateways` DNSEndpoint. Secret Manager's VPN-only
DNS is a separate DNSEndpoint outside their RBAC permissions. No Cloudflare
token, private key or user credential is mounted into these workloads.

The electorate is fixed by `pool.json`, not by whichever observers are currently
reachable. Two observers run on the two worker hosts; an authenticated Cloudflare
Worker supplies a third, off-host observation only when the local votes cannot
already form a majority. Any two fresh, matching observations form a majority.
Missing, expired, malformed, future or differently configured votes are unknown,
not failed. They cannot lower the required majority or authorize DNS withdrawal.
The remote observer never writes DNS and has no Cloudflare API or Kubernetes
credentials. Its token is stored in the private operator directory, a Kubernetes
Secret and the Worker secret store, never Git or Terraform state. Fixed DNS-only
probe names point to individual gateway IPs; each is checked over HTTPS and HTTP.
Changing origins requires updating both the probe DNS records and the Worker's
declared inventory; the inventory test rejects mismatches.

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
and distinct nodes do not imply independent ISPs or regions. If the external
witness and either local observer are both unavailable, DNS retains its previous
targets rather than electing a smaller quorum. A working public gateway cannot
make an unavailable database or storage quorum available.

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

`scripts/public_dns_witness_e2e.py --output <private-report.json>` exercises the
current two-node plus external-witness configuration in a temporary namespace.
It only changes fixture NetworkPolicies and an `.invalid` DNSEndpoint, then
removes the namespace. It verifies disagreement, majority withdrawal, recovery,
one local voter lost, and loss of both the witness and one local voter. It uses
the actual authenticated external witness and production health endpoints, but
does not switch production DNS or stop production Pods.
Add `--simulate-remote-failure` when Wrangler is authenticated to create a
separate temporary Worker and token. It verifies withdrawal and restoration with
one local voter and the external witness, then deletes the temporary Worker.

The publishers expose `heteronetwork_public_dns_*` Prometheus metrics through a
private, annotated Service. The probe duration is the total time for the HTTPS
health check and HTTP redirect check from each voter; failed/stale votes are not
reported as healthy. `witness_available` is emitted only when it was actually
polled, so normal on-demand silence is not represented as a failed witness. The
status timestamp lets queries detect stale quorum data. Graceful publisher shutdown
releases its lease after any in-flight DNS update; if release fails, the ordinary
45-second lease expiry remains the safe fallback. Scraping access is limited
to the Prometheus namespace and the two host-network monitoring nodes.
The voter-only overlay DNS monitor also records per-voter, per-server query
attempts, failures and last latency. Its results are advisory: a DNS probe
failure or malformed monitoring data never removes a public gateway vote.
