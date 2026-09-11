# Dedicated DEV Realm

`realm.json` defines only `heterocloud-dev`, with no imported users or identity
providers. It requires HTTPS, disables self-registration/password reset pending
the separate account setup, and enables bounded brute-force protection. It sets
three-minute access tokens, a 30-minute idle SSO session and an eight-hour maximum.
This does not change production session settings.

There are two separate OIDC clients:

- `heterocloud-dev-web`: confidential client using `client-secret`, authorization
  code with required PKCE S256 and only the
  DEV console and DEV owner console's exact HTTPS callback URLs. No wildcards,
  implicit grant, password direct grant or service account is enabled.
- `heteronetwork-dev-web`: public client for device authorization only, with no browser callback
  URLs, implicit grant, password direct grant or service account. This client
  matches the HeteroNetwork device-login flow, not the Cloud callback flow.

Both include the `profile` and `email` client scopes. Clients request `openid`
as a protocol scope; it is not configured as a named Keycloak client-scope object.
Neither client's creation grants sudo or pins an owner subject.

## Guarded Application

Deliver `configure-realm.py` and `realm.json` to root-only
versioned tooling on DEV1 after checking their reviewed hashes. Keep the original
foundation bundle at `/opt/heteronetwork-dev-identity` unchanged. The realm JSON
is read beside the invoked script; the foundation helper remains separately pinned.
The helper pins the realm JSON and existing foundation helper, repeats its DEV
cluster/guest guards, and reads the actual Service IP from that cluster. Requests
connect to that private IP while validating HTTPS SNI/hostname against the DEV CA.
It reads the temporary bootstrap credentials only from the private root state.
The temporary admin authenticates through Keycloak's built-in `admin-cli`; these
credentials and the resulting admin token are never printed, placed in arguments,
or used as a sudo owner's credentials.

```sh
sudo python3 -B /opt/<reviewed-versioned-tools>/configure-realm.py
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

## Confidential Cloud Client Transition

The initial DEV realm incorrectly used a public Cloud web client. The selected
Cloud API requires a client secret of at least 16 characters and authenticates
the token exchange with HTTP Basic client authentication. An empty or invented
Secret cannot make that client contract correct.

The reviewed tooling supports the explicit `--upgrade-cloud-client` option for
only this known transition. It checks the DEV marker and all previously managed
settings, changes only the Cloud client's public/authenticator settings, omits
any returned secret from the update body, and reads the client back. Unrelated
drift is rejected. A repeat on the desired confidential client is read-only for
configuration. The device client stays public. No secret rotation or account
creation is performed by this option.

This transition has eight focused fixture tests. It was applied to the running
DEV realm on 2026-09-11: the first invocation reported
`cloud_client_upgraded: true`, and the second reported `false`. Both verified
the two clients, discovery and device authorization initiation. No owner was
created or authenticated.

The hash-verified tools reside at `/opt/heteronetwork-dev-realm-b4f13fa7` on DEV1.
Archive SHA256:
`b4f13fa7dd24c88c5a5fdb69248828c826f9aa14cdc50b408f831df87a9677d3`.
Script SHA256:
`d1b20c180f8cdc49605b83d6b96ed25f0bbef378e14b1e287a6715a38d10e57c`.
Desired realm SHA256:
`77b1c2ffd870e5d369b432a490bf82ea71471ef43263e42c4e515d22cf06bd03`.

`provision-oidc-secret.py` subsequently obtained the existing Keycloak client
secret over the pinned private TLS connection and created
`heterocloud-dev/heterocloud-dev-oidc`, key `client-secret`. It does not generate
or rotate client credentials. The first invocation reported `created: true`;
the second reported `created: false`. Both verified the stored credential equals
Keycloak's current value without emitting it. Existing secrets must match the
DEV/client ownership annotations, managed-by label and exact data; conflicting
state is rejected rather than overwritten. Creation uses server dry-run, create
and readback. No other application Secret or workload was changed.

The provisioning helper on DEV1 is
`/opt/heteronetwork-dev-oidc-7af0ed51/provision-oidc-secret.py`, SHA256
`7af0ed51a479729373f2fbc54a7c5bad562f0a6a261171e91b6db39c94f21548`.
Three focused fixture tests cover idempotent verification, foreign/changed
secrets and invalid credential handling. Real Cloud callback/token exchange,
owner login and majority sudo enforcement remain unverified.

## Original Observed Result

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
