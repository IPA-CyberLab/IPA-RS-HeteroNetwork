# GitHub Actions VPN console E2E

The `live-overlay-browser-e2e` job in
`.github/workflows/infrastructure-validation.yml` runs on a GitHub-hosted
Ubuntu VM. It registers a fresh HeteroNetwork client, creates a kernel
WireGuard interface, waits for a real handshake and gateway return routes,
and opens the canonical internal console URL in Chromium. The canonical UI
must render within three seconds, and both console ports are checked through
all declared gateways.

The same Chromium run signs in through the public Keycloak Device
Authorization page with the dedicated
`heteronetwork-console-e2e@heteronetwork.invalid` identity. A pass requires
HTTP 200 from the authenticated overview, the overview after a reload, the
refresh endpoint in a new tab, and the restored overview in that tab. The
refresh cookie must be HttpOnly and the restored page must not show the
expired-session message. The temporary HeteroNetwork client is deleted even
after a failed check.

The `heteronet-e2e` GitHub Environment is restricted to `master` and the
infrastructure branch. It stores the SSH key, sudo password, and dedicated
console password as environment secrets. The workflow writes the SSH key and
console credential JSON only under `$RUNNER_TEMP` with owner-only permissions,
passes credential values over encrypted stdin rather than process arguments,
and shreds both files in an `always()` cleanup step. Node receives only the
private credential file path, while Chromium receives no credential value;
unrelated job secrets are removed from both process environments. Reports
contain timing, HTTP status, and boolean session checks, without passwords,
cookies, tokens, or screenshots.

Before browser login, the workflow reconciles the dedicated Keycloak identity
through the existing protected SSH and sudo path. The Keycloak bootstrap
credential is read only on the Keycloak host. Its temporary admin session file
is mode 0600 and overwritten before deletion. Terraform installs a systemd
drop-in that adds only this dedicated email to the existing console owner
policy, preserving the normal owner identity.
