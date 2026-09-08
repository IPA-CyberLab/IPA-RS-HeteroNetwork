# Flash HTTP/HTTPS publication

Deployed on 2026-09-08:

- HeteroCloud `0.1.67`: API, console, owner console and workers.
- Flash `0.1.29`: HTTPRoute reconciliation and gateway-only ingress policy.
- Terraform provider `0.1.2`: web publication schema, validation and examples.
- cert-manager `v1.21.1`: two replicas each of controller, webhook and cainjector.

## Public path

`http://f-SERVICE-UUID.flash.heterocloud.mizuame.app/` redirects to HTTPS443.
The host Caddy terminates publicly trusted wildcard TLS, preserves the hostname,
and forwards through the existing Envoy gateway. The exact service HTTPRoute
selects a ClusterIP Service and its Pods. The external port is not TCP30000.
The web route sets forwarded scheme/port to HTTPS/443 after internal proxy hops.

The wildcard fallback returns 404 for unassigned service hostnames. ExternalDNS
derives its addresses from the Gateway status; there is no fixed IP list in
the wildcard DNS manifest. cert-manager uses the existing DNS provider Secret
for DNS01 issuance. The sync DaemonSet follows public-ingress node membership,
preserves unrelated Caddy configuration, and updates immutable certificate/key
paths on renewal without restarting Caddy or tenant Pods.

`exposure.endpoint_mode: web` requires public, forwarded exposure and exactly one
TCP port. Generic `ip` and `load_balancer` TCP/UDP modes remain available. Web
mode currently rejects nonempty source allow/deny CIDRs; it never silently
ignores them. Pod ingress is restricted to the selected Envoy gateway Pods.

## Existing nginx migration

Service `01a02a0c-c65f-7802-b5be-a4efe04d0f69` was changed from `load_balancer`
to `web`, generation 2 to 3. Only this field changed. An operator maintenance
transaction checked the expected generation, exact stored-spec fingerprint,
existing tenant owner, quota and port reservations before updating desired
state, outbox and audit together. A dry run rolled back successfully before
the committed application. No login session or IAM policy was created.
The ordinary worker delivered the reconciliation event and state returned to
`ready`. The maintenance script is in HeteroCloud's
`scripts/migrate-nginx-web.sql`; `scripts/psql-from-url.py` keeps connection
credentials out of process arguments.

## Verification

- DNS path and direct-origin paths via `163.220.236.61` and `163.220.236.53`:
  HTTP308, HTTPS200, public certificate verification enabled.
- Unassigned wildcard hostname: HTTP308, trusted HTTPS404 on both gateways.
- Chromium desktop/mobile: HTTP URL navigated to portless HTTPS, nginx page
  rendered with status 200 and no page errors.
- UI desktop/mobile edit/detail checks passed for generic LB and web modes.
- nginx Pod UID remained `6ba19dc3-2d93-44e7-88c5-2aa2ea8dbb67`, restart count 0.
- nginx PodTemplate SHA256 remained
  `1c490364e45c7aa53f043435f33ab24e52cd25ad2bc6725c3c573171398f4eef`.
- escape Pod UID remained `08942b6b-7a5d-408d-9a88-16acfbe24b40`, restart count 1
  unchanged from before this work.
- Existing Flow health returned 200 and OIDC start returned 303.
- Certificate sync fixture tests: 14 passed. Release workflows completed for
  HeteroCloud, Flash and the Terraform provider.

These checks do not claim cluster-wide fault tolerance or a live certificate
renewal/expiry chaos test. Existing failed nodes were not restarted by this work.

Repeat the external check:

```sh
python3 scripts/flash-web-preflight.py \
  --host f-01a02a0c-c65f-7802-b5be-a4efe04d0f69.flash.heterocloud.mizuame.app \
  --origin 163.220.236.61 --origin 163.220.236.53
```
