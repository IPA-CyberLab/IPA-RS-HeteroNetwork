# Offline GitOps Channels

`render.py` consumes the **same** `CHANNELS.json` maintained by
`scripts/release-channels.mjs`; it does not maintain a second lock or update
channel state. Select `--environment dev` or `prod`. The parent's exported
`transition` validates the complete replay chain in memory before rendering;
its return value is discarded and no state files are written.

Artifacts are keyed by `heterocloud`, `flow`, `flash`, and `syouyu`. Each
artifact's full commit becomes the chart source revision and its exact image
digest becomes the primary image override. `heteronetwork` is validated but
not rendered: **native VM deployment is separate and not performed here**.
Verified native byte preparation and selection are available through the
[native staging tool](../../../docs/NATIVE_RELEASE_STAGING.md), using this same
channel state. Actual VM activation is separate and is not performed here.

Promotion history proves artifact identity, not successful dev testing or
deployment. Operator verification is still required before promoting. There
are no seeded release selections or invented operational digests in this tree.

## Production

Rendering reads only the four corresponding existing Application files under
`deploy/gitops/applications/`. Existing destinations, Helm value files and values,
release names, sync settings, and ignore rules are retained. Changes are limited
to selected chart commits, image parameters, and channel annotations. Components
absent from the selected channel are not emitted or deleted. Registry and Argo
installation settings are not inputs. Existing files are never rewritten.

Production applications retain their automatic sync settings: **applying a
generated production Application can deploy it**. Stage/promote/rollback alone
are offline. Auxiliary pins must be reviewed separately; the five-component
catalog does not encode LiveKit, TURN, database, or Garage images.

## Dev Prerequisites

A **separate Kubernetes cluster**, with at least three suitable nodes, is
mandatory. Coturn uses host networking/ports, Garage requires cluster-wide RBAC,
and Flash references a fixed edge Gateway. Namespace separation alone is not
sufficient. Offline validation compares supplied API origins and `kube-system`
UIDs; operators must independently verify these identify distinct clusters.
It cannot prove network isolation or protect against false site configuration.

Provision independently, without copying production user state:

- Dev namespaces, storage class and fresh volumes; never restored production
  snapshots or existing production claims. Optional generated database/Redis
  infrastructure uses three-instance CNPG clusters for application Postgres.
  Redis remains a single-instance intermediate configuration, not HA.
- Dev edge/TLS/DNS, Flow forwarding infrastructure, and Flash's own
  `heterocloud-edge/heterocloud-edge` Gateway and gVisor runtime in the dev cluster.
- A separate dev OIDC realm and `heterocloud-dev-web` client. Its only console
  redirects are `https://dev.<domain>/api/v1/auth/oidc/callback` and
  `https://owner.dev.<domain>/api/v1/auth/oidc/callback`. Never extend production
  client redirects or import production accounts.
- New dev provider signing keys and matching verification keys for each service.
  Dev issuers and principal audiences differ; Syouyu's provider audience remains
  `heterocloud-syouyu` because its schema fixes that literal. Key and issuer
  isolation, not that audience alone, establishes the separate trust domain.
- Fresh secrets referenced by the dev values: HCloud's `heterocloud-dev-*`,
  Flow's `heterocloud-flow-dev-secrets` and `heterocloud-flow-dev-livekit-config`,
  Flash's `heterocloud-flash-dev-provider-auth`, and
  `heterocloud-syouyu-dev-secrets`. Follow each selected chart's secret-key contract.
  LiveKit configuration must use dev-only Redis, TURN hosts, and new credentials.

Optional generated CNPG clusters are `dev-postgres` in each API namespace
except Flash. Use the operator-managed writable Service `dev-postgres-rw:5432`,
never a selector spanning primary and standby instances. Database/user names
are the namespace with hyphens replaced by underscores. CNPG generates each
namespace's fresh `dev-postgres-app` Secret; the protected credential provisioning
step must build the corresponding API `database-url` Secret from it. The old
password-only `<namespace>-postgres-auth` contract is not used. The renderer
does not read, generate or copy secret values.

`auxiliary_images.postgres` must be a CNPG-compatible image supporting UID/GID
26, such as the independently pinned Postgres 18.6 image in the DEV identity
foundation, not an arbitrary Docker-library Postgres image. The CNPG operator
and CRDs must already exist. App clusters have required hostname separation,
one required synchronous standby and connection ceilings of 200 (HCloud/Flow)
or 100 (Syouyu), including headroom over current API/worker pools. These are
configuration choices, not a measured capacity or failover guarantee.

The operator receives a separate additive egress policy for exactly these three
DEV app namespaces and `cnpg.io/cluster=dev-postgres`, ports 8000/5432. Existing
identity policies, Cluster, credentials and volumes remain untouched.
`dev-identity-local` is explicitly rejected as app storage. App Postgres alone
needs nine fresh 5Gi PVCs; Garage and Redis require additional storage. Prepare
capacity and app-only PV reservations before apply. There is no automatic
migration or removal of older StatefulSets/Services: verify this is a fresh
application namespace before provisioning. This generator is not a DB migration.

Flow's intermediate standalone `redis` Service still uses the Flow secret's
`redis-password`. Its direct connection uses a full `redis://` URL. Authenticated
Redis/Sentinel, live failover, credential provisioning, and storage admission
remain required before calling the app infrastructure deployment-ready or HA.

## Site Configuration

Provide private operator JSON, not production values copied into a dev overlay:

| Field | Contract |
| --- | --- |
| `destination_server` | Dev HTTPS Kubernetes API origin |
| `production_destination_server` | Different, independently verified prod origin |
| `cluster_uid`, `production_cluster_uid` | Different verified kube-system UIDs |
| `domain` | Dev base hostname beginning `dev.` |
| `oidc_issuer` | `https://id.<domain>/realms/heterocloud-dev` |
| `oidc_client_id` | `heterocloud-dev-web` |
| `owner_email` | Dedicated dev owner's email |
| `storage_class` | Fresh-storage class in the dedicated cluster |
| `pod_cidrs`, `service_cidrs`, `dns_cidrs` | Nonempty dedicated-cluster CIDR lists, no catch-all ranges |
| `kubernetes_api_backend_cidrs` | Required nonempty explicit dev API backend CIDRs, no catch-all ranges; use observed backend addresses, not inferred Service IPs |
| `auxiliary_images` | Map of `{version, image}` with exact `repository@sha256:<digest>` |

Dev HCloud database, provider, registry, owner ingress, and proxy trust ranges
are explicitly derived from this site, not chart production CIDR defaults.
Public OIDC HTTPS egress remains enabled. The chart's namespace-based DNS policy
is retained. This is not a general cross-cluster firewall generator.
Syouyu API egress merges the service CIDRs with `kubernetes_api_backend_cidrs`,
normalizing and deduplicating exact CIDRs in stable order. Include the actual
dev control-plane backend addresses used after Service DNAT and verify policy
enforcement with the chosen CNI. Production rendering does not require this field.
Syouyu's namespace-local database selector uses `matchLabels` for
`cnpg.io/cluster: dev-postgres`.

Flow LiveKit is taken from `companions.livekit.image` in the selected Flow
release, not a site-specific override. Its digest is preserved through promotion.
Auxiliary image bindings: `coturn`, `garage`, `redis`,
`redis-sentinel`, `prometheus`, `prometheus-init`, `grafana`, `busybox`, `haproxy`.
Optional dev infrastructure also needs CNPG-compatible `postgres` and
Redis-compatible `redis` images. Disabled components do not need image
pins. `--helm-check` rejects any emitted container image absent from the selected
artifacts or supplied auxiliary pins, including mutable chart defaults.

Garage uses separate `garage.image.digest` and `garage.image.tag` parameters.
Supply its auxiliary pin with `version: "v2.3.0"`, retaining the schema's required
tag, and the real immutable image reference. The selected Syouyu chart revision
must support the optional digest field; older chart revisions reject it. The
updated local chart passes the strict digest render check. The renderer does not
modify sibling charts.

## Render and Check

Install `requirements.txt` in a local Python virtual environment; Node is also
required for shared channel validation. From the repository root:

```sh
python deploy/gitops/environments/render.py \
  --channels /private/CHANNELS.json --environment dev \
  --site /private/dev-site.json --output /private/dev-applications.json \
  --infrastructure-output /private/dev-infrastructure.json --helm-check
```

The application output includes a dev-only AppProject and manually synced
Applications. Infrastructure is a separate bundle for the **dev cluster**, not
the Argo management cluster. Neither output is applied by the tool. Repeated
rendering of identical inputs produces identical output suitable for declarative
server-side apply, using the appropriate explicitly verified context for each
bundle. Review the diff and cluster identity before any operator apply/sync.
Do not enable pruning against a partial channel selection.

`--helm-check` requires local Git checkouts at the **exact selected artifact
commits** under `--repository-root`. It checks HEAD and repository cleanliness
before and after each bounded Helm invocation. Tracked/staged changes, untracked
files, dirty submodules, and ignored files inside the chart (including downloaded
`charts/` dependencies) cause refusal. Supply separate clean checkouts; the
renderer never checks out commits, cleans repositories, downloads dependencies,
or calls Kubernetes. A chart requiring absent dependencies cannot pass until
those dependencies are supplied through a reviewed commit-bound packaging path.
Git checks have a 30-second bound and Helm a 90-second bound per chart. These
checks assume a trusted local checkout with no concurrent writers; they are not
an adversarial filesystem snapshot or remote provenance attestation.

```sh
HELM_CHANNEL_TESTS=1 HELM_CHANNEL_REPOSITORY_ROOT=/private/clean-checkouts \
  python -m unittest discover \
  -s deploy/gitops/environments -p test_render.py -v
```

Default focused tests use synthetic digests and disposable Git repositories to
check replay rejection, production preservation, fresh storage, selector shape,
explicit API CIDRs, and wrong-commit/dirty/staged/untracked/ignored-file refusal.
The opt-in Helm test reads the actual tracked channel selections and requires
matching clean checkouts; auxiliary image values remain synthetic test fixtures,
not deployment pins. It checks rendered selectors and image preservation, not
runtime image availability or Kubernetes admission.

## Remaining Deployment Blockers

These renderer fixes do not make the current dev configuration deployment-ready.
The selected HCloud dev.2 chart supports secure owner cookies and the DEV values
explicitly enable them. The rendered-owner check still rejects an insecure
HTTPS owner deployment. HCloud API, worker and owner each request three replicas
with PDB minimum availability two. Flash requests three API replicas and two
controllers, matching its chart's redundant defaults. The selected charts supply
required hostname anti-affinity; these settings are not observed runtime HA.
Fresh database redundancy and actual failure recovery remain separate requirements.
DEV Flow's host-network Coturn explicitly uses 13478 (UDP and TCP), leaving
3478/3479 to native DEV STUN. The chart derives listener arguments, host ports,
Service ports and advertised TURN URLs from `coturn.servicePort`. On 2026-09-11,
read-only socket inspection found 13478 unused on all three DEV guests and
3478/3479 in use on guest 1. This observation is not a port reservation.
DEV media/NAT mappings and access to the TURN listener and relay range still
need provisioning and live validation; no public TURN reachability is claimed.
The initial immutable Helm check refused untracked Flow dependency archives.
Flow dev.4 now vendors both archives in its selected source commit and verifies
their checksums during release CI. On 2026-09-11, channel revision 10 passed the
four-chart offline check with clean selected checkouts: Flash 12 resources,
Flow 22, HCloud 12, Syouyu 21. The rendered TURN listener/URL and cloud/Flash
replica, anti-affinity and PDB checks passed. These tests use a synthetic site
and auxiliary image fixtures; they do not attest actual site identities,
auxiliary image availability, live traffic or Kubernetes deployment.
Fresh secrets, dev IdP, DNS/TLS/edge resources, verified
cluster destinations, and runtime/network prerequisites above remain required.
