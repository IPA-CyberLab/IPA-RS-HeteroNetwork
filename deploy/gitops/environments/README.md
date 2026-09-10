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
  infrastructure uses fresh volume claim templates and one replica per DB.
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

Optional generated Postgres services are `dev-postgres` in each API namespace
except Flash. Database/user names are the namespace with hyphens replaced by
underscores, port 5432. Passwords come from `<namespace>-postgres-auth`, key
`password`; API database URL secrets must refer to that namespace's service and
matching credentials. Flow's separate `redis` service uses its own Flow secret's
`redis-password`. No Secret values are generated or copied.

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
| `auxiliary_images` | Map of `{version, image}` with exact `repository@sha256:<digest>` |

Dev HCloud database, provider, registry, owner ingress, and proxy trust ranges
are explicitly derived from this site, not chart production CIDR defaults.
Public OIDC HTTPS egress remains enabled. The chart's namespace-based DNS policy
is retained. This is not a general cross-cluster firewall generator.

Auxiliary image bindings: `flow-livekit`, `coturn`, `garage`, `redis`,
`redis-sentinel`, `prometheus`, `prometheus-init`, `grafana`, `busybox`, `haproxy`.
Optional dev infrastructure also needs `postgres` and `redis`, using official
Postgres/Redis-compatible entrypoints. Disabled components do not need image
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

`--helm-check` uses sibling **local working-tree charts**, including their local
dependencies, with a 90-second bound per chart; it does not fetch or attest the
catalog's remote commits. For release validation use clean checkouts at the exact
artifact commits under `--repository-root`, independently verify each HEAD and
chart/dependency provenance, and repeat the check. No chart dependency downloads
or Kubernetes API calls are performed by the renderer.

```sh
HELM_CHANNEL_TESTS=1 python -m unittest discover \
  -s deploy/gitops/environments -p test_render.py -v
```

Tests use clearly synthetic artifact digests only in memory, check replay-chain
rejection, production setting preservation, fresh dev storage, explicit CIDR
overrides, and actual local Helm output for all four services, including exact
Garage digest preservation. These local render tests do not attest remote chart
commits or runtime image availability.
