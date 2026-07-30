# Public customer resource plane

HeteroNetwork has separate operator and customer security domains. The
operator Web UI and `/v1/admin/*` remain private management surfaces. Public
customers authenticate against the dedicated `heteronetwork-customers`
Keycloak realm and can reach only the customer console and `/v1/customer/*`.

## Identity contract

Customer access tokens must satisfy every check:

- `iss` exactly equals `HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL`.
- `azp` exactly equals `heteronetwork-customer-console`.
- `aud` contains `heteronetwork-customer-api`; `azp` is not accepted as an API
  audience.
- Keycloak UserInfo accepts the token and returns the same exact `sub`.
- `realm_access.roles` contains `heteronetwork-customer`.

The durable identity key is the exact `(iss, sub)` tuple. Email and display
name are presentation data and never identify an account or authorize a
resource.

The customer and operator routers are not merged. A control-plane process can
serve three distinct listeners:

| Listener | Default | Routes | Intended exposure |
| --- | --- | --- | --- |
| Management | `0.0.0.0:8443` | protocol and `/v1/admin/*` | HeteroNetwork/VPN only |
| Customer API | `127.0.0.1:19881` | `/healthz`, `/v1/customer/*` | loopback behind the customer BFF |
| Controller API | `127.0.0.1:19882` | `/healthz`, `/internal/v1/customer/*` | HeteroNetwork/VPN only |

Do not publish the management or controller listener through the public
customer reverse proxy.

## Durable resources

The first resource hierarchy is:

```text
Keycloak identity -> personal account -> project -> public service
```

SQLite and PostgreSQL stores enforce:

- cluster-scoped unique `(issuer, subject)` accounts;
- deterministic opaque account/project IDs and lifecycle-unique public-service
  IDs;
- account ownership in every project and service lookup/mutation;
- unique project and service names in their owner scope;
- transaction-serialized project and public-service quotas;
- cluster-wide limits of 10,000 projects and 10,000 public services;
- generated Kubernetes namespaces bound to their owning project;
- generation-checked, monotonic controller status updates.

Default quotas are 10 projects and 100 public services per account. Set
`HETERONETWORK_CUSTOMER_DEFAULT_PROJECT_QUOTA` and
`HETERONETWORK_CUSTOMER_DEFAULT_PUBLIC_SERVICE_QUOTA` before an account is
first created to change them. Re-authentication does not overwrite an existing
account's quota. Both per-account quota values are capped at 10,000. The
cluster-wide limits are independent safety bounds for one controller
reconciliation domain.

Organization membership is not synthesized from the Keycloak `org-admin`
role. That role is non-default and has no global resource authority. A future
organization API must persist and check project membership explicitly.

## Customer API

All routes require the customer access token:

```text
GET    /v1/customer/session
GET    /v1/customer/projects
POST   /v1/customer/projects
GET    /v1/customer/projects/{project_id}
DELETE /v1/customer/projects/{project_id}
GET    /v1/customer/projects/{project_id}/public-services
POST   /v1/customer/projects/{project_id}/public-services
GET    /v1/customer/projects/{project_id}/public-services/{resource_id}
DELETE /v1/customer/projects/{project_id}/public-services/{resource_id}
```

The two collection routes accept `limit` and `cursor` query parameters.
`limit` defaults to 100 and must be between 1 and 1,000. When a response has
more entries, `next_cursor` contains the last returned opaque resource ID; pass
that exact value as the next request's `cursor`. A missing `next_cursor` marks
the final page.

Create a project:

```json
{
  "name": "realtime"
}
```

Create a forwarded public service:

```json
{
  "name": "livekit-turn",
  "spec": {
    "traffic_mode": "forwarded",
    "protocol": "UDP",
    "public_port": 3478,
    "backend_service": "livekit-turn",
    "backend_port": 3478,
    "ingress_replicas": 2
  }
}
```

Use `"traffic_mode": "direct"` when the workload must run on the public-IP
owner without an extra Kubernetes hop. Use `forwarded` when placement on
private workers is more important than the extra forwarding path.

Deleting a project atomically deletes its public-service resource records.
The Kubernetes controller subsequently removes their controller-owned facade
Services. It does not delete the project Namespace or unrelated workload
objects.

Deleting and recreating a public service, including with the same name,
produces a new 128-bit resource ID. Delayed status from the deleted
controller lifecycle therefore cannot be committed to the replacement.

## Control-plane configuration

Generate one independent controller credential, then securely distribute the
same bundle to every HA control-plane replica and the corresponding Kubernetes
Secret:

```sh
sudo scripts/customer-resource-plane-node.sh \
  init-token /root/heteronetwork-customer-resource-plane
```

On each control-plane replica, enable the customer resource plane through the
validated systemd installer:

```sh
export HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=\
https://identity.example.com/realms/heteronetwork-customers
export HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN=10.250.0.4:19882
export HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE=\
/root/heteronetwork-customer-resource-plane

scripts/customer-resource-plane-node.sh plan
sudo --preserve-env=HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL,\
HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN,\
HETERONETWORK_CUSTOMER_RESOURCE_PLANE_TOKEN_BUNDLE \
  scripts/customer-resource-plane-node.sh install
```

The installer writes a root-only environment file and token, adds a systemd
credential drop-in, and restarts the control plane only when its unit is
already active. It refuses an implicit token rotation. Run `disable` before a
deliberate coordinated replacement.

The resulting settings are equivalent to:

```sh
HETERONETWORK_CUSTOMER_API_ENABLED=true
HETERONETWORK_CUSTOMER_API_LISTEN=127.0.0.1:19881
HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN=10.250.0.4:19882
HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=https://identity.example.com/realms/heteronetwork-customers
HETERONETWORK_CUSTOMER_OIDC_CLIENT_ID=heteronetwork-customer-console
HETERONETWORK_CUSTOMER_OIDC_AUDIENCE=heteronetwork-customer-api
HETERONETWORK_CUSTOMER_OIDC_REQUIRED_ROLE=heteronetwork-customer
```

Set the backchannel URL to a private customer Keycloak replica when public DNS
does not resolve locally:

```sh
HETERONETWORK_CUSTOMER_OIDC_BACKCHANNEL_BASE_URL=http://127.0.0.1:28080/realms/heteronetwork-customers
```

Every configured backchannel belongs to the same exact issuer. Never use an
operator Keycloak endpoint as a customer fallback.

## Kubernetes controller

Enable the chart integration with a Secret containing the same controller
credential:

```yaml
kubernetesPlugin:
  customerResources:
    enabled: true
    internalUrls:
      - http://10.250.0.4:19882
      - http://10.250.0.5:19882
      - http://10.250.0.6:19882
    pollIntervalSeconds: 15
    bearerTokenSecret:
      name: heteronetwork-customer-controller
      key: token
```

The controller does not read Secrets through the Kubernetes API. The selected
Secret key is mounted read-only. It polls the configured internal control-plane
endpoints with failover and remembers the last healthy endpoint. Each poll
reads projects and public services independently from
`/internal/v1/customer/public-services` using `kind=projects` or
`kind=public_services`, a page size of 1,000, and the returned `next_cursor`.
An endpoint that fails or returns an invalid page partway through a poll is
discarded as a whole before failover. For every project, including a project
with no public services yet, the controller creates and labels the generated
Namespace. It refuses to adopt a pre-existing Namespace that lacks the exact
HeteroNetwork project ownership metadata.

For each desired public service it creates a controller-owned facade Service
in that Namespace, while leaving the named backend Service unchanged. The
facade uses:

- `loadBalancerClass: heteronetwork.io/public`;
- `externalTrafficPolicy: Local` for direct or `Cluster` for forwarded;
- the requested protocol, public port, backend port, and ingress replica count;
- resource ID and generation ownership metadata.

Deleted resources cause stale controller-owned facade Services to be removed.
The controller reports Pending, Ready, or Error plus public addresses through
the generation-checked internal API.

Public addresses currently belong to HeteroNetwork nodes. They are not
floating VIPs, Elastic IPs, or a promise that an address survives node loss.
Multiple healthy public nodes provide multiple ingress addresses; clients or
DNS must retry a surviving address after failure.

See [Customer Keycloak](CUSTOMER_KEYCLOAK.md) for the identity-plane
deployment, [Customer console](CUSTOMER_CONSOLE.md) for the public BFF, and
[Kubernetes plugin](KUBERNETES_PLUGIN.md) for the underlying direct/forwarded
data-path contract.
