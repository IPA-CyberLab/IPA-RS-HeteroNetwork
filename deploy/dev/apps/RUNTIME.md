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

## Remaining Deployment

Garage/layout, all four application APIs/controllers/workers, Flash gVisor and
edge services, DEV Argo, registry, monitoring, DNS/TLS entry points, real owner
login and complete E2E/HA checks are not established by these steps. Bootstrap
and registry integrations currently remain disabled in the DEV overlays; that
is unfinished provisioning, not the requested final state. Complete resource
admission must include those dependencies and tenant headroom, not only the
earlier19.25-CPU core stack estimate. No production deployment or channel
promotion occurred here.
