# Public customer Keycloak identity plane

HeteroNetwork uses two independent identity planes:

| Property | Operator plane | Public customer plane |
| --- | --- | --- |
| Purpose | HeteroNetwork administration | Customer and organization resource access |
| Exposure | Private HeteroNetwork overlay only | Public HTTPS through a dedicated TLS ingress |
| Realm | Existing operator realm | `heteronetwork-customers` |
| PostgreSQL database | Existing `keycloak` database | `heteronetwork_customer_identity` |
| PostgreSQL schema | Existing operator schema | `customer_identity` |
| PostgreSQL role | Existing `keycloak` role | `heteronetwork_customer_identity` |
| Keycloak HTTP | Existing `127.0.0.1:18080` | `127.0.0.1:28080` |
| Management | Existing `127.0.0.1:19000` | `127.0.0.1:29000` |
| Cache transport | Existing port `7800` | Private address port `27800` |
| systemd service | Existing operator units | `heteronetwork-customer-keycloak*` |

The customer installer never reads or writes the operator Keycloak
configuration, data directory, database, realm, clients, ports, or units. It
shares only the existing synchronous PostgreSQL HA infrastructure and its
local primary-selecting proxy.

## Provisioned authorization contract

The bootstrap reconciler creates:

- Realm role `heteronetwork-customer`, assigned through the realm's default
  composite role and required for customer application access.
- Independent realm role `org-admin`, used only as an organization-scoped
  modifier after application-level membership checks.
- Public client `heteronetwork-customer-console`, using Authorization Code with
  PKCE S256. Implicit flow, password grants, and service accounts are disabled.
- Bearer-only resource client `heteronetwork-customer-api`.
- An audience mapper that adds `heteronetwork-customer-api` to access tokens
  issued for the console.

Self-registration is disabled in the baseline realm. Provision a customer
administratively or connect a reviewed external identity provider before their
first login. The resource plane creates the corresponding personal account on
the first valid customer login; email and display name never become ownership
keys. Enable public self-registration only together with verified email,
working SMTP, recovery policy, rate limiting, and abuse controls.

It does not create or map `heteronetwork-admin`,
`heteronetwork-operator`, or `heteronetwork-viewer`. Reconciliation fails if
any of those operator roles appears in the customer realm.

`org-admin` is intentionally neither a default role nor a composite of
`heteronetwork-customer`. It never substitutes for the baseline application
role and never grants global resource access. A resource-management service
must grant it only after validating organization ownership, and must scope each
use to an organization membership stored in application data. Organization
membership, quotas, resource ownership, billing state, and resource policy
remain application data; Keycloak provides identity and coarse roles, not that
domain state.

Customer APIs must validate all of the following before authorizing a request:

1. `iss` exactly matches the configured public customer issuer.
2. `aud` contains `heteronetwork-customer-api`.
3. `azp` is exactly `heteronetwork-customer-console` for console-issued access
   tokens. The audience and authorized-party IDs are deliberately distinct.
4. Signature and time claims validate against the customer realm JWKS.
5. `realm_access.roles` contains `heteronetwork-customer`. `org-admin` alone is
   never sufficient.
6. The authenticated subject has access to the requested organization or
   resource in the resource-management database.

## Prerequisites

- The existing HeteroNetwork PostgreSQL/Patroni HA cluster is healthy.
- Every customer Keycloak replica has
  `heteronetwork-db-proxy.service` on `127.0.0.1:25432`.
- Replica hosts are PostgreSQL HA members, or PostgreSQL `pg_hba` has an
  equivalent explicit rule for the replica source address and dedicated
  customer database role.
- At least two, preferably three, independent customer Keycloak replica hosts.
- A public DNS name and valid TLS certificate.
- A same-host TLS proxy on every replica. Keycloak itself is deliberately
  loopback-only; a remote load balancer cannot connect directly to port 28080.
- TCP port `27800` is reachable only between customer Keycloak replicas.

The default PostgreSQL administrator credential path is:

```text
/etc/heteronetwork/postgres-autopilot/bundle/secrets/superuser.password
```

It must be a root-owned, single-linked file with mode `0600`. Override it with
`HETERONETWORK_CUSTOMER_KEYCLOAK_DB_ADMIN_PASSWORD_FILE` when a separate
provisioning credential is used.

## Create the customer secret bundle

Create one bundle on a trusted host:

```sh
sudo scripts/customer-keycloak-node.sh \
  init-secrets /root/heteronetwork-customer-keycloak-secrets
```

The command is idempotent and never replaces an existing valid secret. Securely
distribute the same two files to every replica. Do not run `init-secrets`
independently on each node: all replicas share one customer database credential
and one bootstrap credential.

If the database role already exists, provisioning verifies the supplied
database secret instead of changing its password. A replica with a mismatched
bundle therefore fails closed without invalidating healthy replicas. Credential
rotation is a separate coordinated operation and is not performed by
`install` or `provision-database`.

The bundle is independent of the PostgreSQL HA bundle and operator Keycloak
secrets:

```text
db.password
bootstrap-admin.password
```

## Validate and install a replica

Use the exact same issuer, callback list, origins, and secret bundle on every
replica. Only the private cache bind address changes. Install and validate the
first replica before adding the remaining replicas one at a time:

```sh
export HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL=\
https://identity.example.com/realms/heteronetwork-customers
export HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS=10.250.0.21
export HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS=\
https://console.example.com/cloud/callback
export HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS=\
https://console.example.com
export HETERONETWORK_CUSTOMER_KEYCLOAK_SECRET_BUNDLE=\
/root/heteronetwork-customer-keycloak-secrets

scripts/customer-keycloak-node.sh plan
sudo --preserve-env=HETERONETWORK_CUSTOMER_KEYCLOAK_ISSUER_URL,\
HETERONETWORK_CUSTOMER_KEYCLOAK_CLUSTER_BIND_ADDRESS,\
HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_REDIRECT_URIS,\
HETERONETWORK_CUSTOMER_KEYCLOAK_CONSOLE_WEB_ORIGINS,\
HETERONETWORK_CUSTOMER_KEYCLOAK_SECRET_BUNDLE \
  scripts/customer-keycloak-node.sh install
```

`plan` is non-mutating and does not print secrets. `install` is idempotent. It:

1. Verifies or installs the pinned Keycloak 26.6.4 release in a customer-only
   path.
2. Installs root-only configuration and customer-only secrets.
3. Reconciles the dedicated PostgreSQL role, database, and schema through the
   existing HA primary proxy.
4. Starts the customer Keycloak replica.
5. Reconciles the realm, roles, clients, role scopes, and audience mapper.

The installed boot order is:

```text
heteronetwork-db-proxy.service
  -> heteronetwork-customer-keycloak-database.service
  -> heteronetwork-customer-keycloak.service
  -> heteronetwork-customer-keycloak-bootstrap.service
```

The database and realm bootstrap operations use existence checks, ownership
checks, and an advisory lock, so rerunning them does not duplicate resources.

## Public TLS contract

Publish only the configured HTTPS origin on port 443. The same-host TLS proxy
must:

- Terminate a publicly trusted TLS certificate for the issuer DNS name.
- Forward `/realms/heteronetwork-customers/*`, `/resources/*`, and
  `/robots.txt` to `127.0.0.1:28080`.
- Set `X-Forwarded-Proto: https`, the original `Host`, and port `443`.
- Use a source address included in
  `HETERONETWORK_CUSTOMER_KEYCLOAK_TRUSTED_PROXY_CIDRS`.
- Never publish `127.0.0.1:29000`, metrics, health, or Keycloak administration
  endpoints. Do not publish the `master` realm.
- Health-check
  `/realms/heteronetwork-customers/.well-known/openid-configuration`.

The default trusted proxy is only `127.0.0.1/32`. Additional entries must be
private CIDRs. The installer rejects HTTP issuers, private/internal issuer
names, wildcard callbacks, non-443 issuer ports, and globally routable trusted
proxy ranges.

The public load balancer or DNS layer should remove a replica when discovery
fails. Keycloak session and cache state use the dedicated PostgreSQL database
and JDBC-discovered Infinispan cluster. Sticky sessions are optional for
correctness but reduce cross-node cache traffic.

## Verification

After public DNS and TLS are active:

```sh
sudo scripts/customer-keycloak-node.sh validate-live
sudo scripts/customer-keycloak-node.sh status
sudo scripts/customer-keycloak-bootstrap.sh validate
```

`validate-live` requires both local and public discovery documents to advertise
the exact issuer, verifies the dedicated database login and schema privilege,
and checks the reconciled realm contract.

Do not point operator consoles or operator APIs at this issuer. Conversely,
public customer services must never accept tokens from the private operator
issuer.
