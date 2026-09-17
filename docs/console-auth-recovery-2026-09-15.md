# Console Authentication Recovery, 2026-09-15

The reported session-expired screen was reproduced through the exact
`http://console.heteronetwork.internal:9781/ui/` URL in Chromium.
Keycloak Device Authorization completed and refresh returned 200, but both
`/v1/admin/overview` and `/v1/admin/keycloak-placement` returned 401 after
the initial token and after its refresh. The UI then cleared its session.

The access token's issuer was
`https://heterocloud.mizuame.app/id/realms/heterocloud`. All three serving
control planes still expected
`http://console.heteronetwork.internal:18079/realms/heterocloud`.
The control-plane issuer check rejected the different scheme, port and path
before contacting Keycloak userinfo.

## Change

The root-owned public-services bootstrap issuer was updated on uc-k8s3p,
uc-k8sp1 and ichikawap1. Each was reconciled individually by the standard
public-services autopilot. The public issuer now matches the actual tokens;
the authorization/token endpoints and private userinfo backchannels retain
their existing internal addresses. The configured owner restriction was
unchanged and is identical across the three hosts.

Original configuration is preserved on each host under
`/var/backups/heteronetwork/20260915T0605Z-console-oidc/`.

`scripts/reconcile-owner-console-auth.sh` now derives the canonical issuer
from the configured verification origin and preserves the private auth base.
The corrected helper and smoke script were installed on the three hosts.
`scripts/heteronetwork-console-e2e.sh` now validates these distinct addresses.

`scripts/heteronetwork-console-browser-e2e.mjs` requires owner credentials and
only passes after an authenticated overview, reload, and cookie restoration
in a new tab all return 200. It also checks that the refresh cookie is HttpOnly
and that the restored UI has no session-expired message. A briefly rendered
authenticated UI or a Keycloak form cannot satisfy this test.

Example from an operator connected to the overlay:

```sh
HETERONETWORK_CONSOLE_BROWSER_E2E_CREDENTIAL_FILE=/path/to/private-owner-credentials.json \
  npm run test:heteronetwork:e2e
```

The private JSON file contains `username` and `password`. It must belong to
the existing configured console owner. The optional
`HETERONETWORK_CONSOLE_BROWSER_E2E_PROXY` supports an operator's SOCKS tunnel.
Reports contain HTTP statuses and screenshots, not passwords, cookies or tokens.

## Verification And Limits

- All three serving control planes advertise the canonical public issuer.
- All four gateway `/ui/config` responses return 200 with that issuer.
- The updated committed console smoke script passed.
- The reconciler fixture passed for the default and a custom verification
  origin, preserved private endpoints and owner restrictions, and rejected
  an invalid origin before changing the file.
- Authenticated console E2E did **not** pass with the archived E2E account.
  That account is a tenant and its email does not match the configured owner.
  After the issuer fix, its management request returns 503; the existing
  authorization code treats the owner-email mismatch as unavailable.
  Owner login, reload and new-tab restoration remain unverified without
  the owner's authentication. The owner's login email was requested.
- The archive did contain E2E credentials. They were overlooked in the
  initial front-door recovery; the previous missing-credentials statement
  must not be used to imply that the archive had none.
- Using those tenant credentials, the public HeteroCloud browser sweep
  authenticated successfully and passed the main pages, Flow detail and
  Flash detail. It failed at Syouyu bucket detail with a 409 credentials
  response. The sweep is a **failure**, not a full authenticated E2E pass.

Private reports are under `artifacts/console-auth-recovery-2026-09-15/`.
The previous Kubernetes availability and storage limitations remain recorded
in `docs/front-door-recovery-2026-09-15.md`.

Temporary copies of test credentials and tokens, the diagnostic SOCKS tunnel,
and SSH sessions were removed after verification. The original archive and
SSH key remain in the workspace.
