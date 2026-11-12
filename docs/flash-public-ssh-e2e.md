# Public Flash SSH E2E

The `Flash public SSH E2E` workflow connects from a GitHub-hosted VM with
ordinary OpenSSH and runs a harmless command. It verifies the host key against
the fingerprint from the Flash service details before authenticating.

Use a newly generated, temporary Ed25519 key, assign its public key only to a
test service, and enable that service's SSH setting. Create a unique uppercase
hexadecimal test ID and upload the private key as a temporary repository secret
named `HETERONET_PUBLIC_SSH_E2E_<ID>` through `gh secret set` on standard input.
Dispatch the workflow with that ID, the hostname and port shown by the service,
the `organization-id+service-id` username, and the displayed host fingerprint.

After the run, revoke the key's service assignment, delete the registered key,
delete the temporary repository secret with `gh secret delete`, and remove the
local temporary key. Do the same cleanup if a run fails or is cancelled. Never
put a private key, API token, or user credential in a workflow input or commit.
