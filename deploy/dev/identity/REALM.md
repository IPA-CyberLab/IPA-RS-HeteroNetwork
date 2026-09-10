# Dedicated DEV Realm

`realm.json` defines only `heterocloud-dev`, with no imported users or identity
providers. It requires HTTPS, disables self-registration/password reset pending
the separate account setup, and enables bounded brute-force protection. It sets
three-minute access tokens, a 30-minute idle SSO session and an eight-hour maximum.
This does not change production session settings.

There are two separate public OIDC clients:

- `heterocloud-dev-web`: authorization code with required PKCE S256 and only the
  DEV console and DEV owner console's exact HTTPS callback URLs. No wildcards,
  implicit grant, password direct grant or service account is enabled.
- `heteronetwork-dev-web`: device authorization only, with no browser callback
  URLs, implicit grant, password direct grant or service account. This client
  matches the HeteroNetwork device-login flow, not the Cloud callback flow.

Both include the `profile` and `email` client scopes. Clients request `openid`
as a protocol scope; it is not configured as a named Keycloak client-scope object.
Neither client's creation grants sudo or pins an owner subject.

## Guarded Application

Deliver `configure-realm.py` and `realm.json` to root-only
`/opt/heteronetwork-dev-identity` on DEV1 after checking their reviewed hashes.
The helper pins the realm JSON and existing foundation helper, repeats its DEV
cluster/guest guards, and reads the actual Service IP from that cluster. Requests
connect to that private IP while validating HTTPS SNI/hostname against the DEV CA.
It reads the temporary bootstrap credentials only from the private root state.
The temporary admin authenticates through Keycloak's built-in `admin-cli`; these
credentials and the resulting admin token are never printed, placed in arguments,
or used as a sudo owner's credentials.

```sh
sudo python3 -B /opt/heteronetwork-dev-identity/configure-realm.py
```

The helper creates an absent realm using the official
[Keycloak Admin REST API](https://www.keycloak.org/docs-api/26.7.3/rest-api/index.html).
An existing realm must carry the expected DEV cluster UID marker and match all
managed settings. Each client is read back and checked. Different or unmarked
resources are rejected, not adopted, overwritten or deleted. Repeated successful
runs do not rewrite realm/client configuration. This is not a general drift-repair
tool; review changes and extend the lifecycle before changing existing settings.

Each run also checks the new realm's discovery and begins one device authorization
request. Its pending device/user codes are not printed or redeemed and expire
according to Keycloak's device-flow policy. Consequently the validation run has
bounded temporary authentication-session side effects, even when no configuration
changes occur. It is not an authenticated device-login or token-grant test.

## Observed Result

On 2026-09-10 the first actual run returned `created: true` and verified both
clients. Discovery returned issuer
`https://id.dev.heterocloud.mizuame.app/realms/heterocloud-dev` and device
authorization initiation returned HTTP 200 with the matching verification URI.
No owner user was created or authenticated.
A second actual invocation returned `created: false`, verified the same two
clients and successfully repeated discovery/device initiation without rewriting
the realm or clients.

Source SHA256: `861e280b0890bae6a0c9a59e02e17af753268eb422ddd7bf24d7fd3732dae67f`.
Realm JSON SHA256: `6cdddc89e98e6a0bbbc44a29d42efa5ad93a117590ac97b909cdb38a5778e5ba`.
Four focused fixture tests cover existing-resource verification, foreign markers,
client restrictions and rejection of drift without mutations. They do not prove
browser login, public DNS, real-user authentication, token claims or signer access.

Owner email confirmation, account enrollment, exact issuer/subject/UID policy
mapping, DNS and client trust/routing, authenticated login/refresh and majority
sudo issuance/enforcement remain unfinished. Do not create a dummy owner, use the
temporary master-realm administrator, or copy a production subject to bypass them.
