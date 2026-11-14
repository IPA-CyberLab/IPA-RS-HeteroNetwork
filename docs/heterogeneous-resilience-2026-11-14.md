# Current heterogeneous failure handling

This is the observed configuration on 2026-11-14, not a guarantee that nodes
or networks are in different buildings, regions, power feeds, or ISPs. The
Kubernetes nodes do not currently declare region or zone labels. Do not infer
geographic independence from hostnames or IP addresses.

## Public gateways

- The two existing application workers, `uc-k8sp5` and `ichikawap1`, terminate
  public HTTPS. The dedicated control-plane and Secret Manager nodes remain
  excluded from the public gateway and its TLS synchronization Pods.
- TLS and verified custom-domain certificates are synchronized independently to
  both workers. The public legacy Secret Manager hostname returns 403 on both.
- Five Envoy replicas use a per-host spread constraint. On `uc-k8sp5`, Caddy
  prefers a local Envoy endpoint and falls back to the cluster-wide endpoint.
  A topology constraint affects new scheduling: Kubernetes does not rebalance
  already-running Pods when a previously unavailable worker returns. Check
  the actual replica distribution after recovery; do not call a one-node
  placement geographically redundant.
- Two on-node voters and a separately hosted, authenticated Cloudflare Worker
  form a fixed three-member DNS electorate. The external witness is queried only
  when it can complete a missing majority. No database credentials, user data,
  Kubernetes credentials, or Cloudflare API credentials are sent to it.
- DNS requires two fresh matching observations, three new failure samples to
  withdraw an origin and two recovery samples to add it. DNS TTL, resolver
  caching, ExternalDNS reconciliation and the publisher's 45-second lease can
  delay failover. Missing observers are unknown; a missing majority retains the
  previously published targets. A complete outage retains DNS by policy.
- The gateway health check verifies TLS, HTTP redirection, Caddy and Envoy's
  direct-response route. It deliberately does not declare the database, tenant
  applications, identity provider or S3 healthy. A reachable front door can
  still return errors if one of those dependencies is unavailable.

Run the isolated check documented in
[`public-dns-quorum/README.md`](../deploy/gitops/public-dns-quorum/README.md).
The `--simulate-remote-failure` mode uses a separately created temporary Worker
and verifies withdrawal and recovery with one local voter. The fixture only
changes its own `.invalid` DNS object and NetworkPolicies; it does not stop a
production node or change production DNS. A real power/site failure has not
been injected as part of this check.

The quorum status is in `heterocloud-dns/public-dns-quorum-state` under
`status.json`. Prometheus scrapes `heteronetwork_public_dns_*`, including
per-voter, per-origin probe durations and the observation timestamp. A duration
is the combined HTTPS health and HTTP redirect check, not an ICMP RTT or an
application request latency. Slow observations, missing metrics, stale status,
unknown origin status and loss of quorum have separate alerts.

## Remaining physical limits

- The application database has only the two current worker-host voting domains.
  Losing one can lose the database's majority. DNS failover cannot fix that.
- Syouyu Garage has three roles, but two of them run on `uc-k8sp5` and one on
  `ichikawap1`. Loss of `uc-k8sp5` leaves only one of the three Garage copies,
  below its two-of-three quorum. The individual Garage Longhorn PVCs have one
  copy each; those PVC counts must not be mistaken for the Garage object-copy
  count.
- The Longhorn audit on this date found 16 volumes, seven with fewer than two
  healthy host copies: six Garage PVCs and the `openbao/openbao-snapshots` PVC.
  The latter was detached and configured for three replicas, but only one
  healthy host copy was observed. This is a backup availability risk, not proof
  that the active secret store has lost its own quorum.
- Two workers and no additional failure domain cannot simultaneously provide
  a genuine independent three-way quorum and tolerate either worker's loss.
  Backups to an actually independent S3-compatible destination, and restore
  drills, reduce data-loss risk but do not restore online database or object
  storage availability. Do not place ordinary workload Pods or new auxiliary
  services on the three dedicated nodes to fabricate a third vote.

The external witness improves observation of Internet reachability; it is not a
third storage or database server, and its availability must not be confused with
an independently located HeteroCloud worker.
