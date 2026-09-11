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

## Actual Ingress/TLS Probes

On 2026-09-11, `probe-cloud-access.py` completed nine sequential, short-lived Pod
checks across DEV1, DEV2 and DEV3. For each node:

- API labels: verified TLS succeeded (exit0 and `Verification: OK`).
- Worker labels: connection refused (exit1 with `connect:errno=111`).
- Owner-console labels: verified TLS succeeded after the negative check.

The fixed DEV hostname resolved through CoreDNS to the real Service. OpenSSL
verified the CA and hostname using only the public CA Secret. No user credentials,
service-account token or private key were mounted. Each Pod requested25m CPU and
32Mi memory, and was deleted before the next check. The successful run exited0
after all nine cleanup operations.

The first immediate-connection probes failed on the allowed API case. The final
probe permits bounded startup retries for allowed clients, accommodating selector
reconciliation; it still requires positive TLS verification. The exact cause of
the initial transient was not proven. Negative cases accept only a timeout or
explicit connection refusal, never arbitrary TLS/CA/DNS errors. Paired successful
clients bracket each worker check; no claim is made about arbitrary other labels.

Installed helper:
`/opt/heteronetwork-dev-access-probe-8c4e3424/probe-cloud-access.py`, SHA256
`8c4e3424873690f374775778e063f7cb62d8dd7763f736b9baa74066de623f84`.
It refuses to run once labeled Cloud Services exist, so probes cannot accidentally
enter application Service endpoints. These are ingress-policy/TLS probes before
application rollout, not tests of the eventual chart's egress rules, OIDC token
exchange, browser login, sudo authorization or failover.
