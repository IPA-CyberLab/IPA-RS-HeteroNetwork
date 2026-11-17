# Current heterogeneous failure handling

This is the observed configuration on 2026-11-14, not a guarantee that nodes
or networks are in different buildings, regions, power feeds, or ISPs. The
Kubernetes nodes do not currently declare region or zone labels. Do not infer
geographic independence from hostnames or IP addresses.

## Update: 2026-11-17

The infrastructure module now accepts explicitly verified site assignments in
`node-localities.json` and applies them to Kubernetes and the HeteroNetwork
hierarchy. No assignment was inferred or applied while the physical sites are
unknown. Unknown nodes are left untouched; only explicitly listed removals
remove a HeteroNetwork override.

Flash controller revision `cfa16a90eb390c98ef5dfbbac52194b18dd4daf9` was
rolled out with zone spreading in `preferred` mode. Existing service
generations are left unchanged to avoid an involuntary restart; multi-replica
stateless services use the new policy on their next generation. The controller
reached two ready replicas, all five existing Flash services remained ready,
and their Pod UIDs and restart counts did not change during the rollout. The
optional `required` mode leaves excess replicas pending without two eligible
zones; it is not enabled in production. A single persistent ReadWriteOnce home
is not made into a multi-writer by this policy.

[Flash's isolated scheduler E2E](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/actions/runs/44020856579)
tested unknown zones, site unavailability and recovery using two real kind
workers. [HeteroNetwork's isolated E2E](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44020527068)
tested six real WireGuard agents with synthetic site labels, dropped traffic
between sites, verified local communication and checked recovery after healing.
The control plane remained reachable during that test; it does not establish
database quorum or storage availability during a real site partition.

Two live VPN/browser runs failed before handshake because the acceptance
client selected the cheapest gateway independently of the gateway placed first
by the control plane. In strict mode only the assigned gateway has that client
peer. Regression tests reproduced the mismatch; the acceptance client now
uses the assigned first gateway, matching the native client bootstrap.
[A subsequent live run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44022708170)
passed authentication and the three-second console budget. This was a test
client correction, not proof that every native-client failover case works.
The acceptance check was then made deterministic: it generates a signed test
identity that must be assigned away from the sponsoring node. The [live run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44023883591)
joined through `10.250.0.6`, authenticated and opened the canonical console
in 780 ms after route readiness; the temporary client was removed. Route
readiness itself took 32.97 seconds and is not part of that page-open time.

A [later live acceptance run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44024597974)
failed with HTTP 503 while obtaining the client peer map after the WireGuard
handshake. The test did not preserve the server's failure category, so its
cause is not established. At roughly the same time an agent rejected resolved
paths whose routing epoch differed from its neighbor map. This is a separate
observed defect, not proof of the cause of the 503: the old path resolver
discarded a destination after this rejection, even though the neighbor map
could subsequently catch up. The source fix requeues only epoch-mismatch and missing-map
failures and still refuses to install an inconsistent path. The acceptance
test records a sanitized category for HTTP failures and still fails on the
first error; it does not hide the incident with retries.

The same 503 reproduced after deploying the retry fix only to `uc-k8sp2` in
[the targeted live run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44028570311).
A further [targeted run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44029108961)
failed while an independent probe on that host reported both control-plane
endpoints unreachable from 06:10:49 to 06:10:58 UTC. Another gap was observed
from 06:11:05 to 06:11:14 UTC, immediately after test client removal. These
times are bounded by the probes' three-second timeout, not packet capture.
Each node insertion and deletion advances the cluster-wide routing epoch; on
epoch changes the agent currently invalidates all on-demand routes, not just
routes affected by that client. Agent logs show overlay peer proxies restarting
in the same interval. This behavior is a plausible contributor to the outage,
but has not yet been proven as its sole cause. The epoch-mismatch retry fix
alone must not be represented as resolving this 503 or as a guarantee that
enrolling a client cannot interrupt unrelated routes.

The independently tested retry fix was subsequently deployed through the
checksum-pinned Terraform/Ansible rollout to all five active nodes, one at a
time. All five Kubernetes nodes and all five Flash services reported ready
afterward. This is a fix for the separate discarded-retry defect; the
client-enrollment interruption above remains open. The [post-rollout run
targeting the same gateway](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44030594776)
again failed with both cached control-plane endpoints unreachable.

Kubernetes events from the earlier 05:25 UTC live run also show an etcd
connection to `uc-k8sp2` returning `no route to host` at 05:25:59, when the
Whisper authentication service Pod was deleted. Its replacement was created
at 05:26:39 and started at 05:27:11. The cause of the deletion is not established
by those events, so the timing is evidence of impact, not proof that the VPN
test caused the deletion. The service was ready in the later health check.
Do not repeatedly run production enrollment tests while this issue remains
unfixed; use isolated environments for investigation.

The [two-voter DCS partition E2E](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/44024432794)
used the production etcd version in isolated network namespaces. After all
peer TCP traffic was blocked and packet drops observed, neither voter accepted
a write; quorum and writes recovered after the partition healed. The first
test attempt only blocked traffic by destination port and allowed an existing
bidirectional stream; the fixture was corrected before the passing result.
This checks etcd behavior only, not a full Patroni/PostgreSQL site failover.

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
