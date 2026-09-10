# Release Channels

Release selection is separate from deployment. A release artifact identifies a
component, version, full Git commit and container content digest. The channel
tool never builds an image, calls Kubernetes, restarts a VM or modifies a tenant
container. Its JSON output is desired state, not proof of a successful rollout.

## Workflow

Download the release's `release-artifact.json` from the release publisher. Review
the repository, release commit and image digest before selecting it. Store channel
state in a trusted, writable deployment directory under version control; do not
put credentials in this file.

```sh
node scripts/release-channels.mjs stage channels.json release-artifact.json 0
# Deploy the selected dev artifact in the isolated development environment.
# Record successful health, login and service checks before promoting it.
node scripts/release-channels.mjs promote channels.json release-artifact.json 1
```

The final argument is the expected current revision. Inspect the file after any
conflict; do not blindly retry with a new revision. A repeated identical selection
is a no-op. Production promotion requires the exact artifact currently selected
in dev, including both the commit and digest. Mutable tags such as `latest` are
rejected. The tool does not verify test evidence automatically: the operator must
review it before promotion.

The supported component names are `heteronetwork`, `heterocloud`, `flow`, `flash`
and `syouyu`. Releases from other repositories must supply the same schema before
being selected; this does not install release publishing workflows into those
repositories.

```json
{
  "schema_version": 1,
  "component": "heteronetwork",
  "version": "1.2.3",
  "commit": "FULL_40_CHARACTER_GIT_COMMIT",
  "image": "ghcr.io/ipa-cyberlab/heteronetwork@sha256:ACTUAL_64_CHARACTER_DIGEST"
}
```

The placeholders intentionally fail validation. Do not replace them with invented
hashes. A content digest identifies bytes; this file alone is not a publisher
signature or an authorization token.

## Rollback

```sh
node scripts/release-channels.mjs rollback channels.json previous-artifact.json 2
```

Only artifacts previously promoted to production are eligible. Rollback changes
production selection without changing dev. Deploy that selection using the normal
reviewed rollout process. Application rollback does not undo database migrations
or storage format changes; verify compatibility before deployment.

The channel file retains every selection with its previous artifact and timestamp.
Keep the file in Git for review and durable history. The local exclusive lock and
revision check protect cooperating writers on one filesystem, not independent
copies in different Git checkouts. Resolve Git conflicts before deployment. After
a process crash, inspect the owning process and state before manually removing a
stale `.lock` file. Never use an untrusted shared directory for this operation.

## Activation Limits

Container channel selection does not yet update the native VM binaries. Do not
describe a changed channel file as a VM upgrade. Production quorum enforcement
requires the complete intended signing roster to be provisioned and every control
plane upgraded before activation; see [ADMIN_QUORUM.md](ADMIN_QUORUM.md).

Development must have separate namespaces, storage, databases, credentials, DNS
names and OIDC clients. Merely changing a namespace while reusing production
secrets or database URLs is not staging isolation. Existing production applications
and unrelated dirty GitOps changes must remain untouched during preparation.

Focused tool checks:

```sh
node --test scripts/release-channels.test.mjs
```
