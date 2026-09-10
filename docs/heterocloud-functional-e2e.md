# Dedicated Fixture Functional E2E

`scripts/heterocloud-functional-e2e.mjs` reproduces the dedicated tenant's
successful public Flow create/join/read-back and Flash Web Shell `pwd` checks.
It is separate from the read-only browser page-sweep runner. It does not test
S3, change service specs, restart workloads, provision accounts, or touch
another tenant. A P2P join response is not proof of WebRTC media delivery.

## Inputs and Opt-In

Use the repository's installed Playwright/Chromium dependencies. The default
private inputs are owned regular files with mode `600`:

- `~/.config/heterocloud/e2e.env`: unquoted `E2E_USERNAME=value` and
  `E2E_PASSWORD=value` lines. Never print or shell-trace this file. The username
  must start with `heterocloud-e2e-`.
- `~/.config/heterocloud/e2e-fixtures.json`: `organization_id` plus a `resources`
  array containing exactly one entry for each of `projects`, `realtime/services`,
  and `flash/services`. Entries contain `collection`, `id`, and `name`.
  Additional fixture types such as Syouyu are ignored.

The authenticated account must be a normal tenant with exactly one membership:
owner/admin of the explicitly selected fixture organization, not owner-console
access. Both services must be ready, match the manifest's project and names,
have names beginning `e2e-`, and retain
`spec.metadata.purpose = "dedicated-browser-e2e"`. Flash must be private with
one replica. Flow must have no existing rooms; the script will not remove them
or increase quotas to make the test pass.

```sh
node --check scripts/heterocloud-functional-e2e.mjs
node scripts/heterocloud-functional-e2e.mjs --help

HETEROCLOUD_FUNCTIONAL_E2E_ORGANIZATION_ID='<own-fixture-organization-uuid>' \
  node scripts/heterocloud-functional-e2e.mjs --allow-own-fixture-mutations
```

Without the explicit flag the script exits `2` before reading credentials or
launching a browser. Optional path overrides:
`HETEROCLOUD_FUNCTIONAL_E2E_ENV_FILE`, `HETEROCLOUD_FUNCTIONAL_E2E_FIXTURES`, and
`HETEROCLOUD_FUNCTIONAL_E2E_ARTIFACT_DIR`. The two input files must remain mode
`600`. Credentials are read as data, never evaluated as shell code.

Only the canonical public HTTPS origins are used, with normal DNS and TLS
validation. No `.61` origin substitution, saved-session shortcut, certificate
bypass, or authentication/verification setting changes are supported. An OIDC
callback outage fails during `public_oidc_login`, before fixture mutations.

## Operations and Cleanup

The script checks the deployed `/openapi.json` room operations, obtains a
180-second signed context scoped to the fixture service, then calls the
documented operations:

1. `POST /v1/rooms`: one uniquely named P2P room, two-participant limit, and a
   per-run metadata marker.
2. `POST /v1/rooms/{room_id}/join`: one join; validate `flow-signaling.v1`, WSS,
   STUN, and TURN response data without recording tokens or ICE credentials.
3. `GET /v1/rooms/{room_id}`: verify read-back identity.
4. Open the dedicated Flash service's actual Web Shell UI, type only `pwd`,
   validate its output, and disconnect. No invented WebSocket frames are used.

Cleanup runs from `finally`, including after functional failures. Browser pages
close before waiting so shell connections do not remain open during cleanup.
Only contexts issued by this run are revoked. An ambiguous room creation is
recovered only by matching both the unique name and per-run marker in the
service-scoped list; uncertainty fails explicitly rather than deleting other
rooms or repeating a create request.

The deployed Flow contract has no room-delete endpoint. Its documented cleanup
is expiry after ten minutes without participants, once join credentials expire.
The script keeps no signaling/media connection open, waits 615 seconds after
room creation/recovery, then uses a short-lived read-only context to verify
`404` for that exact room and absence from its scoped list. It allows five
bounded checks for the cleanup sweep and revokes the verification context too.
Budget approximately 13 minutes. Do not terminate the process during cleanup;
an external kill cannot execute JavaScript `finally`. If interrupted, use the
private report's room ID/run marker for a scoped read-only expiry check. Never
delete the fixture service to clean up a room.

## Evidence and Result

Each run creates a mode-`700` directory under
`~/.config/heterocloud/functional-artifacts` by default. `report.json` and the
post-command `flash-pwd.png` screenshot are private (mode `600` via umask).
There are no login screenshots, traces, cookie dumps, raw exception stacks,
access headers, passwords, or join credentials in the report.

Exit `0` requires public login, both functional checks, verified room expiry,
and revocation of every issued context. Any missing check, callback failure,
cleanup uncertainty, or remaining context produces exit `1`. The report is
written after room creation and while awaiting cleanup, not only on success.

The original independent run on 2026-09-10 returned create `201`, join `200`,
read-back `200`, and verified room cleanup with `404` plus list absence. Both
temporary contexts were revoked with `204`. Flash returned `/root` for `pwd`,
disconnected, and produced no page errors. This historical evidence does not
replace rerunning the script after infrastructure changes.
