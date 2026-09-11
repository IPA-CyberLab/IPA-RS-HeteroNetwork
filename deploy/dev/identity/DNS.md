# Isolated DEV Identity DNS

`configure-dns.py` adds one exact CoreDNS rewrite:
`id.dev.heterocloud.mizuame.app` to
`dev-keycloak.hetero-dev-identity.svc.cluster.local`.
No Service IP, production name, wildcard or external DNS record is embedded.
The original query hostname remains the TLS/SNI identity.
See the [CoreDNS rewrite documentation](https://coredns.io/plugins/rewrite/).

The helper uses the existing pinned foundation guard, live DEV cluster UID,
observed CoreDNS ConfigMap UID and exact inspected baseline. It refuses unknown
Corefile edits. JSON Patch tests the UID, resourceVersion and original data before
replacement. The default only performs a server dry run; `--apply` changes the
ConfigMap and verifies readback. A repeat performs no mutation. No restart is
requested: CoreDNS's existing reload plugin observes the projected ConfigMap.

This admission policy is specific to the existing isolated cluster. A recreated
ConfigMap or cluster needs explicit inspection and reviewed pin updates; this
script must not automatically adopt another cluster's identity.

## Observed 2026-09-11

Installed on DEV1 at
`/opt/heteronetwork-dev-dns-5e180f40/configure-dns.py`.
SHA256 `5e180f405c667fedb832a57ce7c892978aa8a66f62dc4478ed1ee13e5c3cc9a9`.
Actual dry run, apply and repeat succeeded for cluster
`a39281cb-d273-4c5f-b7a7-fca722fb417b`; repeat reported no change.

The first query immediately after apply failed before reload had converged.
Subsequent `getent ahostsv4 id.dev.heterocloud.mizuame.app` in each existing
`heterocloud-dev/dev-postgres-{1,2,3}` container resolved only `172.30.58.34`,
matching the observed Keycloak Service. Those Pods ran on DEV1, DEV2 and DEV3.
No Pod restart was requested and no production configuration was changed.

This proves sampled cluster DNS resolution, not browser/public DNS or login.
Cloud's namespace still lacks `heteronetwork.dev/identity-client=true`, required
by the existing Keycloak ingress policy. The Cloud OIDC egress configuration also
needs to permit the backend TLS port 8443 with appropriate destination scoping.
Those application-network changes and real authenticated login remain pending.
