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
  A topology constraint affects new scheduling. A separate ten-minute
  reconciler corrects existing placement after a worker returns: it evicts at
  most one gateway Pod per run through the PodDisruptionBudget and a UID
  precondition. It acts only when both workers have stable Ready status and
  fresh leases, both public gateways have a healthy fresh quorum, all five
  replicas are available, and the rollout is complete. During an outage or a
  partition it leaves the running replicas alone. An admission policy limits
  its eviction privilege to this gateway's Pods. Do not call host-level spread
  geographically redundant without verified site information.
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

Each worker also probes each worker's internal DNS over UDP. Per-path attempted
and failed query counters are exposed as `heteronetwork_overlay_dns_probe_*`;
these observations do not participate in public DNS voting. The failure alert
requires more than 10% failed queries over five minutes and enough samples.
On this date one run from `uc-k8sp5` to `ichikawap1` timed out twice in 30
queries; later measurements succeeded for 100/100 UDP and 100/100 TCP queries,
and a short ICMP check succeeded for 30/30. No cause was established from those
samples. A timeout can be caused by the DNS service, either direction of the
network path or host scheduling; this probe alone does not distinguish them.

## Remaining physical limits

- The application database has only the two current worker-host voting domains.
  Losing one can lose the database's majority. DNS failover cannot fix that.
- Syouyu Garage has three roles, but two of them run on `uc-k8sp5` and one on
  `ichikawap1`. Loss of `uc-k8sp5` leaves only one of the three Garage copies,
  below its two-of-three quorum. The individual Garage Longhorn PVCs have one
  copy each; those PVC counts must not be mistaken for the Garage object-copy
  count.
- The Longhorn audit on this date found 16 volumes, including six Garage PVCs
  with one Longhorn copy each. The `openbao/openbao-snapshots` PVC initially
  had only one healthy host copy; a read-only attachment let the existing
  Longhorn controller rebuild a second copy on the other worker. It now has two
  healthy host copies against its configured three, so it is still below its
  desired replica count. A daily, worker-only check keeps that encrypted backup
  volume attached read-only until two host copies are running or a bounded
  timeout fails the job. This is backup availability, not the active secret
  store's own quorum or a substitute for an offsite backup.
- Two workers and no additional failure domain cannot simultaneously provide
  a genuine independent three-way quorum and tolerate either worker's loss.
  Backups to an actually independent S3-compatible destination, and restore
  drills, reduce data-loss risk but do not restore online database or object
  storage availability. Do not place ordinary workload Pods or new auxiliary
  services on the three dedicated nodes to fabricate a third vote.

The external witness improves observation of Internet reachability; it is not a
third storage or database server, and its availability must not be confused with
an independently located HeteroCloud worker.
