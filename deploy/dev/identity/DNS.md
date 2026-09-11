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
Cloud's namespace intentionally lacks `heteronetwork.dev/identity-client=true`;
the scoped policy described below replaces that namespace-wide permission.
Real authenticated login remains pending.

## Cloud Ingress Permission

`configure-cloud-access.py` creates and verifies the separate
`hetero-dev-identity/dev-keycloak-cloud-clients` NetworkPolicy. Both namespace
labels (exact Cloud DEV namespace and DEV channel) and Pod labels (Cloud name,
release instance, API or owner component) must match in the same peer entry.
Only Keycloak Pod ingress TCP/8443 is granted. Worker/Flash Pods do not match.
Other existing policies remain additive; this is not proof of global isolation.

Actual first create and second no-change verification succeeded on 2026-09-11.
No namespace labels, existing policies or workloads were changed. The root-owned
helper is at `/opt/heteronetwork-dev-cloud-access-33ae7d2d/configure-cloud-access.py`,
SHA256 `33ae7d2db9475e2a4d7a2da9ac7e18f03051829dee82fb604b7b5d243f333cd5`.

The tracked DEV Helm overlay changes API OIDC egress from unrestricted destinations
on port443 to DEV Pod/Service CIDRs on backend port8443. That chart change is not
deployed yet. It restricts destination ranges, not individual destination Pods;
the ingress policy above supplies the Keycloak client selection. The owner chart
currently has no Egress policy. End-to-end allowed/denied connectivity and actual
user login must still be exercised after application rollout.
