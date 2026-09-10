# HeteroCloud browser incident: 2026-09-10

## Observed failure

At approximately 04:14 UTC, real headless Chromium using normal public DNS and
TLS opened `https://heterocloud.mizuame.app/` and received HTTP 503 with an
empty document. No login or service interaction succeeded in that run.
This was not a mocked frontend test or a successful authentication test.

The extended runner was subsequently executed against the same public URL:

```bash
HETEROCLOUD_BROWSER_E2E_ATTEMPTS=1 \
HETEROCLOUD_BROWSER_E2E_TIMEOUT_MS=15000 \
npm run test:heterocloud:e2e -- --unauthenticated-diagnostic
```

It exited **1**, reporting `Homepage HTTP 503`. The final private evidence is in
`artifacts/heterocloud-browser-uhlgSF/` (not committed): `report.json`,
`1-homepage.png`, and `1-failed.png`. The report marks the authenticated console
routes as blocked, rather than passing checks that were never executed.

Subsequent origin diagnostics showed:

| Path | Result |
| --- | --- |
| Public Cloudflare URL `/` | 503 |
| `.61` host front door `/` | 200 |
| `.53` host front door `/` | 503 |
| `.61` internal proxy `:18082/` | 200 |
| `.61` internal proxy health | 200 |

Direct-origin diagnostics used the intended Host/SNI and bypassed certificate
verification only for the Cloudflare-origin certificate. The actual browser
test did not bypass DNS, TLS validation, or authentication.

## Infrastructure evidence

- ichikawa's Kubernetes API was connection-refused; its last API container had
  exited at restart attempt 66. Its logs contained API request timeouts.
- Its etcd container was running but repeatedly attempted elections; even an
  authenticated, bounded member-list request timed out. Running containers do
  not establish etcd quorum health.
- On uc-k8s3p, all five overlay paths were `UNREACHABLE`. Last observed
  WireGuard handshakes to `.10` and `.5` were 2026-09-09 23:34:14 UTC.
- That agent's control-plane refresh attempted an unreachable VPN endpoint;
  signaling rejected stale/missing membership authentication. These symptoms
  show a recovery dependency problem, but do not establish the initial cause
  of the partition.

## Scope and outstanding checks

The public entry point failure blocks a complete browser journey. Do not
interpret an origin health response, a rendered Keycloak form, or a diagnostic
run without credentials as a full E2E pass. Authentication, service lists,
service details, and reload/session checks must be rerun against the public
URL after connectivity recovery using a dedicated test account.

This investigation did not restart tenant containers, reset credentials,
change etcd membership, or force a new etcd cluster. No password, cookie,
authentication code, or state parameter belongs in this report.
