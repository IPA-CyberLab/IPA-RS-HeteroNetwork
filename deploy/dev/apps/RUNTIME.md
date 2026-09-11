# Selected DEV Runtime

`deploy/dev/site.json` now contains the independently observed DEV and production
cluster UIDs, the verified internal DEV API origin, DNS and API backend ranges,
approved owner email and immutable dependency image pins. Email configuration
does not establish the owner's verified OIDC subject or sudo authorization.
Public DNS, ingress, owner enrollment and application rollout remain separate.

`prepare-runtime.py` uses the existing environment renderer and selected release
checkouts without changing channels, repositories or Kubernetes. All four chart
checks must pass before publishing an exclusive output directory. It includes
per-application Kubernetes Lists and a provenance manifest containing full source
commits, primary/companion images, dependency images, site/channel content hashes,
actual cluster identities and each output hash. Namespace normalization rejects
foreign namespaces and unknown scopes. Exact repeated publication verifies bytes
without replacing them. This initial preparation is not an Argo sync.

## Prepared Revision 15

All selected chart checkouts matched the real release commits and were clean.
Actual-site Helm checks passed: Cloud12, Flow31, Flash12 and Syouyu21 resources.
Manifest SHA256:
`57adfb9d4f123e77c486fd46a2fc9f83b7cb537f56d119ea796ee0afe3f671a3`.
The four application Lists are staged on DEV1 under
`/opt/heteronetwork-dev-runtime-9c76ee6d`; staging did not apply all applications.

Newly inspected upstream multi-platform digests on 2026-09-11:

- Coturn4.16.0: `sha256:01fc8655e7c262fa4ccfb8dca74ff80fb372b0ee021e80370a4d3e3dd01a951e`
- Garagev2.3.0: `sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690`

Registry inspection and successful render do not prove either service starts.

## Redis Applied And Verified

`apply-redis.py` selects exactly nine namespaced Redis subchart resources from
the selected Flow output. It checks the root-owned bundle, content hashes,
actual DEV cluster, existing credential, app PV reservations and per-node CPU/
memory request headroom before initial creation. Existing resources require the
same bundle annotation, matching desired fields and the expected field manager.
It performs server dry-runs, applies without force-conflicts, verifies readback,
and leaves all non-Redis chart resources untouched. No Secret, PVC or PV is
created, replaced or deleted by this helper; the StatefulSet controller creates
claims for the already reserved app PVs.

Actual deployment completed with three ready pods at StatefulSet revision
`heterocloud-flow-dev-redis-node-6b97fd545c`:

| Pod Suffix | Node | Observed Role |
| --- | --- | --- |
| 0 | hetero-dev-1 | master |
| 1 | hetero-dev-2 | replica |
| 2 | hetero-dev-3 | replica |

`verify-redis.py` completed actual checks from the pods: authenticated local PING,
all three Sentinel quorum checks and matching primary discovery, cross-pod
contact to the returned primary address, `SET` followed by `WAIT 2 5000` on the
same connection, and matching reads on every replica. The unique probe key was
deleted and also had a60-second fallback TTL. Credentials were read from the
existing in-pod Secret mount and were not printed or put in command arguments.
This proves replication and current discovery, not failover under node loss.
An actual second `--apply` completed successfully with all three pod UIDs,
StatefulSet generation and update revision unchanged; no replacement rollout
was triggered by repeating the same bundle.

Delivery archive SHA256:
`9c76ee6d24da7c56ee3721955e3259b6fb5a67129d04271fd0e831ee6b8cce1b`.
Verifier source SHA256:
`6ae1314cc7d4f3cfebfbd5f15c47b8192b14b0d8ec0ec5a5840d32291ad297c8`.
Focused tests passed: four Redis admission cases and seven bundle publication/
namespace/check-failure cases. No routine full repository suite was run.

## Garage Applied And S3 Verified

`apply-garage.py` admits only the exact revision15 bundle hash above and selects
18 storage/discovery/layout resources. It excludes the Syouyu API Deployment,
API Service and API NetworkPolicy. Before mutation it checks the actual DEV
identity, existing credentials, all six reserved Garage PVs, database health,
per-node request capacity and existing resource ownership. It dry-runs every
object, establishes the CRD before consumers, then applies the StatefulSet and
layout Job without force-conflicts. No disk is formatted and no existing
database or tenant workload is changed. This is an initial guarded deployment,
not an Argo sync or a generic admission controller.

Actual three-node placement on 2026-09-11:

| Pod Suffix | Node | Metadata / Data |
| --- | --- | --- |
| 0 | hetero-dev-1 | dev-app-garage-meta-1 / dev-app-garage-data-1 |
| 1 | hetero-dev-2 | dev-app-garage-meta-2 / dev-app-garage-data-2 |
| 2 | hetero-dev-3 | dev-app-garage-meta-3 / dev-app-garage-data-3 |

All three pods became Ready at revision
`heterocloud-syouyu-dev-garage-859f9b894d`, and all six claims are Bound. Initial
CRD discovery saw a transient Kubernetes storage-initialization429, then
discovered and connected all three peers. The layout bootstrap completed;
the authenticated status probe confirmed a nonzero layout version and three
up nodes with storage roles. The chart requests replication factor3 and
consistent mode. This is not evidence of availability during node loss.

An actual second apply preserved all three pod UIDs, StatefulSet generation1
and update revision. The TTL-cleaned bootstrap Job ran again and reported
`Garage layout already matches the requested three-node layout`; it did not
change the layout or restart Garage.

`verify-garage.py` creates an isolated, short-lived probe pod and a policy that
adds only access to Garage's S3/admin ports for that unique probe. The admin
credential stays in its existing Secret mount; curl credentials use stdin,
not argv. The probe creates a unique bucket and a ten-minute access key scoped
to that bucket, performs authenticated S3 PUT/GET/content comparison/DELETE,
and deletes its key and bucket. The actual successful result confirmed all
three operations, both cleanups, and the existing PostgreSQL cluster still
at three ready instances. Probe pod/policy deletion uses UID preconditions.

Initial probes exposed two client-side readiness/protocol issues: an initial
connection from a newly created pod was refused before a later GET succeeded,
and adding an explicit signed-payload SHA256 header resolved the observed S3
HTTP400. The initial connection timing is consistent with asynchronous policy
reconciliation but its precise cause was not independently isolated.
Only the initial status GET is retried; mutation requests
are not blindly retried. Payload hashes are explicit for PUT and empty-body
GET/DELETE, following the [curl signing API](https://curl.se/libcurl/c/CURLOPT_AWS_SIGV4.html).
No server authentication or network isolation was relaxed. Failed-probe logs
are root-only in `/var/lib/heteronetwork-dev-garage-probes`; an externally killed
probe may need cleanup of its uniquely named bucket even after its key expires.

Deployment archive SHA256:
`91a89f8ab40eeeb468a5a25c68bec0125fa39fb0b4a1e48ad88d00383fe8e760`.
Deployment source SHA256:
`36af889532d42138b6a619ff7ccfa72dc0697cfd3efbf1deaa21eb7a6b9c8ad9`.
Successful verifier archive SHA256:
`f98377f77f10a9286371640f1ee80c30a89a27fafc7747c552f449e7b6d4f313`.
Verifier source SHA256:
`46aedc7452e2e96a8f6f936c340248e5ca5d5ed04edf299c33b17a9eaa02b408`.
The successful verifier is installed on DEV1 at
`/opt/heteronetwork-dev-garage-verify-f98377f7/verify-garage.py`.
Ten focused selection/admission tests passed. Full S3 compatibility, multipart
operations, application-level quotas and node-loss recovery remain unverified.

## Syouyu API Applied And Verified

The API phase uses the same immutable revision15 manifest. `apply-syouyu-api.py`
selects only its Deployment, Service and NetworkPolicy after checking the DEV
cluster, three ready PostgreSQL and Garage instances, preinstalled service
account, referenced Secret keys, verify-full database URL and initial per-node
request headroom including one extra replica. Existing objects must match the
bundle stamp and field manager; mismatches are not overwritten. The Garage
helper is hash-pinned and reused only for structural readback comparison.

Actual DEV rollout on 2026-09-11 completed with three API pods under ReplicaSet
`heterocloud-syouyu-dev-api-67b747b49c`, one per DEV guest. The database migrations
ran on application startup. `verify-syouyu-api.py` independently confirmed:

- `/health/ready` returned `{"status":"ready"}` on each of the three pods;
  this handler calls both PostgreSQL and Garage health checks.
- An unauthenticated `/v1/service-overview` returned401 on each pod.
- `_sqlx_migrations` contains successful versions1 and2.
- PostgreSQL reports TLS for all application-user client connections, including
  connections from each of the three API pod IPs.
- The application PostgreSQL cluster still has three ready instances.

An actual second apply preserved all three API pod UIDs, and the complete
verifier passed again afterward. Eleven focused admission tests also passed;
no full repository suite was run.

These HTTP checks execute against each pod's loopback interface. They do not
prove Cloud-to-Syouyu Service routing, authenticated provider operations, public
DNS/TLS, browser login, quota enforcement or failure recovery. The selected API
chart still has its PDB disabled and placement preferences rather than mandatory
anti-affinity; actual current spreading is not a permanent scheduling guarantee.
Those HA configuration gaps remain open for the complete environment rollout.

Deployment archive SHA256:
`3e83ad31046a8e256b50bda970190a56a1fa1c85ef030a9eba5779462e3bf1ac`.
Deployment source SHA256:
`c3c5df0f7af8f95a99137144c7d579558b6ed96b91f1188bc9aa9751c0f65ccb`.
Verifier archive SHA256:
`05a530e2650f57b848a9166b34517d2254799f792db2012fd092822eede3b2b7`.
Verifier source SHA256:
`2d86854d2a667a700a170566371e546188b00d74da09d2cb9a285f829b68def3`.
Installed verifier on DEV1:
`/opt/heteronetwork-dev-syouyu-api-verify-05a530e2/verify-syouyu-api.py`.

## Flow Runtime Attempt And Migration Fix

`apply-flow.py` selects the22 remaining Flow resources from revision15, excluding
the already deployed Redis subchart. It verifies the immutable bundle, actual
DEV identity, three ready database/Redis instances, referenced credentials and
per-node initial request capacity. It admits host networking only for the
selected Coturn deployment. All five deployments require three replicas.
Support resources are applied first; the migration must complete before any
Flow runtime Deployment is created. This is not a production rollout.

Actual admission initially rejected `metadata.annotations: null` in the Helm
output before mutation. The helper now normalizes missing/null annotations
while preserving hook annotations; tests cover this case. The corrected apply
installed the16 support resources and migration Job, but stopped at the migration
barrier. No API, matchmaker, signaling, LiveKit or Coturn Deployment was started
by this attempt. The existing Redis and PostgreSQL pods remained running.

The actual migration container exited during configuration parsing with:
`REDIS_URL or REDIS_SENTINEL_URLS is required`. The selected chart supplied
neither to the Job, despite supplying them to API/signaling. This happens before
database connection/migration in `flow-api migrate`; it was not a DB outage.

Flow commit `38d5c8805e4b477af3efd9090eaab2a49e53fded` fixes the Job template
to use the same backend and authentication settings as the API. The Redis
chart tests now include migration, with six passing cases including direct
external Redis and authenticated Sentinel. HN's15 focused Flow admission tests
also pass. The immutable replacement prerelease is `v0.1.21-dev.7`:
[release workflow34580135357](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flow/actions/runs/34580135357).
It was observed in progress; no successful artifact or channel promotion is
claimed here. `deploy/releases/channels.json` remains revision15.

The known-invalid DEV migration was suspended using its exact UID and resource
version after checking its bundle annotation, missing Redis configuration and
zero successful completions. Job UID:
`b8f31a23-d5b8-4a27-bcd0-e3af56c552b1`.
Do not resume it unchanged: the old template cannot
succeed. The replacement requires a reviewed new release/bundle and deliberate
replacement of the immutable Job, not an in-place image or manifest overwrite.

Applied partial-bundle archive SHA256:
`2d0f233ff5510cf29c473223d878ebb461cbaeffe255eb1de1cf6c34e9798458`.
Installed helper on DEV1:
`/opt/heteronetwork-dev-flow-2d0f233f/apply-flow.py`.
Helper source SHA256:
`c9e9b35788e81970749321c7dbd23517f75aec8bffdb3b131505a55d5669aa31`.

`verify-flow.py` is prepared but has not run. It checks placement/readiness for
15 runtime pods,12 HTTP endpoints, three TCP TURN listeners, six migrations and
application DB TLS. It explicitly does not establish TURN allocations, WebRTC
data transport, public DNS or full client E2E. Its archive is staged only on the
physical host, not installed on DEV1:
`c90e04681a8801a3e28ce92914aadecc8231c429ac570421ae4840fabd2ba56f`.

`flow_transition.py` prepares admission for the specific dev6-to-dev7 repair.
Its CLI verifies the old manifest against the installed revision15 hash and
all input resource-file hashes, plus the explicitly supplied new manifest hash.
It requires revision16, the exact repair commit, unchanged site/cluster identity,
unchanged non-Flow components and unchanged other rendered application files.
The new Flow list must equal the old list with only four Flow image references,
one LiveKit image reference, and the migration's four Redis environment entries
changed. Redis values must match the API's existing values/Secret references.
Unrelated changes to resource specifications are rejected. Four focused fixture
tests pass, including negative cases for credentials, replicas, component and
identity changes. This checker is offline only: it does not suspend/delete Jobs,
apply Kubernetes resources, validate live ownership or authorize production.
It has not yet admitted actual dev7 artifacts; their release build was still
running when this transition check was added.

## Flow dev7 Actual Startup (2026-09-11)

The later release workflow34580135357 completed successfully. Channel revision16
selects Flow0.1.21-dev.7 at commit38d5c8805e4b477af3efd9090eaab2a49e53fded.
The previous section records the earlier failed attempt, not the current state.
The actual revision16 bundle passed the constrained transition checker; manifest
SHA256 is `3a6fb8239f19638765825c6363d5553beb317ebbf68ce88ed72faf30aa846011`.

The applicator replaced only the previously identified suspended migration Job,
with UID/resourceVersion preconditions. The new migration completed. Readback
now handles Kubernetes omitting empty EnvVar.value without accepting valueFrom
substitutions. All five runtime Deployments have3 Ready replicas, one per DEV
node: API, matchmaker, signaling, LiveKit and Coturn.

LiveKit initially failed because `turn.dev.heterocloud.mizuame.app` did not
resolve. `deploy/dev/identity/configure-dns.py --flow --apply` adds a DEV-only
CoreDNS rewrite to the existing TURN Service, preserving the Keycloak rewrite.
The update checks the exact CoreDNS identity/content and uses compare-and-swap;
repeat identity-only runs preserve the Flow rewrite. No public DNS change or
workload restart was used. LiveKit recovered through its existing restart loop.

`verify-flow.py` passed12 HTTP checks,3 TURN TCP listener checks, all6 successful
migrations, and TLS for all observed application DB connections, including all9
Rust API/worker/signaling Pod addresses. Matchmaker health is checked from a
LiveKit Pod on a different node: its policy admits cluster Pods, not remote
node hosts. A preliminary Syouyu-origin probe was rejected; no network policy
was widened to make the checks pass.

Repeat runtime/DNS apply succeeded and the verifier passed again. All15 runtime
Pod UIDs matched the first successful verification; DNS reported no change.
The namespace-wide UID assertion did not pass because the completed migration
Job had expired and was recreated by apply. The new migration also completed;
this is not a claim that ephemeral Job identities remain stable.

Installed root-only DEV1 helpers:
- Runtime: `/opt/heteronetwork-dev-flow-50eb6221/apply-flow.py`, archive SHA256
  `50eb6221bd379d10014cf7229465052f9763218ca8c6d01f3286ef8cab76b18f`.
- DNS: `/opt/heteronetwork-dev-flow-dns-87c9746c/configure-dns.py`, source SHA256
  `87c9746ce44a317f825c2af4beb3d5428ac579a855934aad914cd7d51f5124cd`.
- Verifier: `/opt/heteronetwork-dev-flow-verify-a59af1bb/verify-flow.py`, SHA256
  `a59af1bb9a3466bceafdcf9ba0b52d516b43672386e806643a154e7e1b2789a5`.

This establishes internal startup only, not authenticated TURN allocations,
WebRTC data transport, public ingress, owner login or physical-host HA.
All three DEV guests still share one physical host. Production was unchanged.

## Cloud Actual Startup (2026-09-11)

`apply-cloud.py` admitted and applied the12 Cloud resources from the same
revision16 bundle. The selected Cloud release is0.1.71-dev.5, commit
`c81681b89b2151a9ae3214d045c938d38b8f74df`, image digest
`70a41870b9e5c986512f2665bceb5a4d079dd7e1e0958ac36751b95e7928b9b3`.
API, owner-console and worker each run3 replicas, one per DEV node. The API
rollout completes before the other two Deployments are applied.

The applicator verifies the exact bundle hash,12 resource identities, DEV
namespace, image pins, required anti-affinity, nonroot/tokenless pods, Secrets,
database target and per-node remaining requests. Unknown existing ownership or
spec changes are rejected. Kubernetes omits `hostNetwork: false` on readback;
only that specific default is normalized, not privileged flags or token mounts.
The first attempt stopped before any resources because the TLS volume mounts
all Secret keys rather than declaring items. That check now requires exactly
`tls.crt` and `tls.key` for that specific Secret.

Before application, the existing credential provisioner verified all7 Secrets
against retained seeds: zero created, no rotation and no seed regeneration.
Inspection of both senders and receivers confirmed all provider/principal
issuer and audience settings agree. Syouyu's provider audience is intentionally
`heterocloud-syouyu` on both sides, separate from its DEV principal audience.

`verify-cloud.py` passed15 HTTPS requests across the three API Pods, including
live/ready, login HTML, unauthenticated session rejection and OIDC initiation.
It validates the private CA chain and hostname while dialing each selected Pod,
then checks the exact DEV issuer/client/callback, S256 PKCE, state/nonce and
Secure/HttpOnly/SameSite transaction cookie. Owner readiness passed from a
different node's Flow Pod, without widening the owner ingress policy.
All15 SQL migrations succeeded and DB connections from all9 Cloud Pods use TLS.
Repeat application preserved all9 Cloud Pod UIDs and the verifier passed again.

Installed DEV1 runtime bundle: `/opt/heteronetwork-dev-cloud-e255a8c3`, archive
SHA256 `e255a8c36799c9ac26a092648493e00bcc7646ac4a4c39338afd846b3b87c25d`.
Verifier: `/opt/heteronetwork-dev-cloud-verify-c205e497/verify-cloud.py`, SHA256
`c205e497365e717c96e1d8c24cce5b30b6eecbce7c80d607eee7d58d21a2e50f`.
Fourteen focused applicator tests and four redirect-validation tests passed.

These are internal startup and OIDC initiation checks, not a completed owner
login or browser E2E. Worker readiness alone does not prove provider operations.
Flash is still undeployed, registry integration disabled, and external DEV
DNS/edge/owner TLS unfinished. No owner identity was fabricated or inferred
from its configured email; no sudo approval policy was activated.

## Remaining Deployment

Flash APIs/controllers/workers, Cloud/Flow authenticated E2E, complete Syouyu integration, Flash gVisor and
edge services, DEV Argo, registry, monitoring, DNS/TLS entry points, real owner
login and complete E2E/HA checks are not established by these steps. Bootstrap
and registry integrations currently remain disabled in the DEV overlays; that
is unfinished provisioning, not the requested final state. Complete resource
admission must include those dependencies and tenant headroom, not only the
earlier19.25-CPU core stack estimate. No production deployment or channel
promotion occurred here.
