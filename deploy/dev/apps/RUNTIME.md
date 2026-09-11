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

## Remaining Deployment

All four application APIs/controllers/workers, Flash gVisor and
edge services, DEV Argo, registry, monitoring, DNS/TLS entry points, real owner
login and complete E2E/HA checks are not established by these steps. Bootstrap
and registry integrations currently remain disabled in the DEV overlays; that
is unfinished provisioning, not the requested final state. Complete resource
admission must include those dependencies and tenant headroom, not only the
earlier19.25-CPU core stack estimate. No production deployment or channel
promotion occurred here.
