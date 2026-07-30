# Public customer console edge

The customer console is a separate public service plane. It runs
`webconsole/server.mjs` with `HETERONETWORK_CONSOLE_MODE=customer` and does not
inherit any operator console configuration. The operator/admin Keycloak,
operator Web UI, management listener, and `/v1/admin/*` remain private.

## Fixed contract

| Item | Value |
| --- | --- |
| Public UI namespace | `/cloud` |
| Public API namespace | `/v1/customer` |
| Local Node listener | `http://127.0.0.1:28088` |
| Default customer API upstream | `http://127.0.0.1:19881` |
| Keycloak realm | `heteronetwork-customers` |
| OIDC client / `azp` | `heteronetwork-customer-console` |
| API audience / `aud` | `heteronetwork-customer-api` |
| Required application role | `heteronetwork-customer` |

The issuer is an exact deployment input, for example
`https://identity.example.com/realms/heteronetwork-customers`. Tokens are
accepted only when `iss` equals that value, `azp` equals the console client,
`aud` contains the API audience, and the realm roles contain
`heteronetwork-customer`.

`org-admin` is an organization-scoped modifier for future persisted
organization membership. It is not accepted as a replacement for
`heteronetwork-customer` and does not grant global application or operator
authorization.

## Prerequisites

- Node.js 20 or newer is installed as `/usr/bin/node`.
- This repository checkout contains `webconsole/server.mjs`, `customerui/`,
  and `webui/noto-sans-jp-ui.ttf`.
- A dedicated customer Keycloak realm is available at the exact HTTPS issuer.
- The console host can reach the customer API upstream.
- Public DNS, a publicly trusted TLS certificate, and a reverse proxy are
  configured before public validation.

The Node process binds only to loopback. The installer does not configure a
reverse proxy, request a certificate, publish a port, or enable the
control-plane customer API.

## Install

Set exact origins without a path, trailing slash, wildcard, credentials, or an
explicit `:443`:

```sh
export HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL=https://cloud.example.com
export HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=\
https://identity.example.com/realms/heteronetwork-customers
export HETERONETWORK_CUSTOMER_API_URL=http://127.0.0.1:19881

scripts/customer-console-node.sh plan
sudo --preserve-env=HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL,\
HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL,\
HETERONETWORK_CUSTOMER_API_URL \
  scripts/customer-console-node.sh install
```

`HETERONETWORK_CUSTOMER_API_URL` is optional and defaults to
`http://127.0.0.1:19881`. Plain HTTP is accepted only with a literal loopback
address and an explicit non-privileged port. Use HTTPS for a non-loopback
upstream.

Installation is idempotent. It:

- creates the non-login `heteronetwork-customer-console` user and group;
- installs a content-addressed, root-owned release under `/opt/heteronetwork`;
- writes the three deployment inputs to a root-owned `0600` environment file;
- installs a launcher that starts Node through `/usr/bin/env -i`;
- enables and restarts `heteronetwork-customer-console.service`.

The `plan` command is non-mutating and also checks the Node runtime, required
source assets, JavaScript syntax, and systemd unit source.

The clean environment launcher passes only customer-plane variables. It does
not read `HETERONETWORK_WEB_*`, an operator control-plane URL, operator roles,
or an operator token.

## Public TLS proxy

Expose only the two customer namespaces. Do not expose the loopback Node port
directly. This NGINX example assumes certificate lifecycle is managed
separately:

```nginx
server {
    listen 443 ssl;
    server_name cloud.example.com;

    ssl_certificate     /etc/letsencrypt/live/cloud.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloud.example.com/privkey.pem;

    location = /cloud {
        return 308 /cloud/;
    }

    location ^~ /cloud/ {
        proxy_pass http://127.0.0.1:28088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location ^~ /v1/customer/ {
        proxy_pass http://127.0.0.1:28088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        return 404;
    }
}
```

The matching Keycloak client must use the exact redirect URI
`https://cloud.example.com/cloud/callback` and exact web origin
`https://cloud.example.com`. Do not use wildcard redirect URIs.

OIDC state and its PKCE verifier are bound to a five-minute, host-only,
HttpOnly, SameSite callback cookie. They are not held in one Node process, so
`/cloud/login` and `/cloud/callback` may reach different console replicas.
The callback clears the cookie before returning the access token bootstrap
page.

## Control-plane contract

Control-plane customer API enablement is managed separately from this console
installer. Every enabled replica must use these customer-plane settings:

```ini
HETERONETWORK_CUSTOMER_API_ENABLED=true
HETERONETWORK_CUSTOMER_API_LISTEN=127.0.0.1:19881
HETERONETWORK_CUSTOMER_CONTROLLER_LISTEN=127.0.0.1:19882
HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL=https://identity.example.com/realms/heteronetwork-customers
HETERONETWORK_CUSTOMER_OIDC_CLIENT_ID=heteronetwork-customer-console
HETERONETWORK_CUSTOMER_OIDC_AUDIENCE=heteronetwork-customer-api
HETERONETWORK_CUSTOMER_OIDC_REQUIRED_ROLE=heteronetwork-customer
HETERONETWORK_CUSTOMER_DEFAULT_PROJECT_QUOTA=10
HETERONETWORK_CUSTOMER_DEFAULT_PUBLIC_SERVICE_QUOTA=100
```

Keep the customer API on `127.0.0.1:19881`; only the local customer BFF should
reach it. The controller listener defaults to `127.0.0.1:19882`. If the
Kubernetes controller is on another HeteroNetwork node, bind this listener to
that control-plane node's overlay address instead and firewall the port to the
overlay/controller source. Never publish the controller listener through the
customer reverse proxy.

The quota defaults are 10 projects and 100 public services per customer. The
accepted upper bound is 10,000 for either resource kind. Quotas are captured
when an account is first created; changing defaults does not rewrite existing
accounts. The resource plane additionally caps the entire reconciliation
domain at 10,000 projects and 10,000 public services.

### Controller credential

Use an independent token containing 32 to 512 printable, non-whitespace ASCII
bytes. Store the source as a root-only regular file with no links:

```sh
sudo install -d -o root -g root -m 0700 \
  /etc/heteronetwork/customer-service-plane
openssl rand -hex 32 \
  | sudo install -o root -g root -m 0400 /dev/stdin \
      /etc/heteronetwork/customer-service-plane/controller.token
```

Prefer a systemd credential so the unprivileged control-plane process does not
need direct access to the root-only source. Add this line to the applicable
control-plane service drop-in:

```ini
[Service]
LoadCredential=customer-controller.token:/etc/heteronetwork/customer-service-plane/controller.token
```

The daemon automatically reads the `customer-controller.token` credential
when the customer API is enabled. Do not also set
`HETERONETWORK_CUSTOMER_CONTROLLER_BEARER_TOKEN_PATH` in this configuration.
Mount the same token read-only into the Kubernetes customer-resource
controller. Treat the controller endpoint and token as internal
service-plane credentials, not customer credentials.

## Validate

After the customer API, customer Keycloak, TLS proxy, and console are live:

```sh
sudo scripts/customer-console-node.sh status
sudo scripts/customer-console-node.sh validate-live
```

`validate-live` checks the dedicated service, customer config, loopback API
health, public TLS, exact issuer discovery, unauthenticated customer API
rejection, and absence of operator UI/API/metrics routes.

Run the repository-level static and route smoke test with:

```sh
scripts/customer-console-smoke.sh
```
