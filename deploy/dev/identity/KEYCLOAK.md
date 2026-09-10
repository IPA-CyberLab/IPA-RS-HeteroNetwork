# DEV Keycloak Server

`keycloak.yaml` defines three Keycloak servers on the three dedicated DEV VMs,
with required hostname anti-affinity, a two-available disruption budget and
one-at-a-time rolling replacement. This is VM-level redundancy on a single
physical host, not physical HA. It does not modify production Keycloak.

The official `quay.io/keycloak/keycloak:26.7.3` image was resolved on 2026-09-10:

- Index: `sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54`
- AMD64: `sha256:88943b6ad06d6293a239f0dfca5acec64218c9b3ab327bf9c936acf408a6ae3b`
- Image user: `1000`
- OCI source revision: `df15afa5a3a8a2b10021f879ffa93b30fb36c73a`

The deployment pins the index digest. The stock image uses `start`, not
`start-dev`; it performs build-time configuration during startup and requires a
writable container layer. This is intentionally not represented as a prebuilt
optimized image. A generous startup probe allows that initial configuration;
readiness and liveness use separate management health endpoints.

## Inputs And Rendering

Use the existing PyYAML virtual environment:

```sh
python3 deploy/dev/identity/render-keycloak.py \
  --origin https://id.dev.heterocloud.mizuame.app \
  --output /private/dev-keycloak.json
```

The origin must be HTTPS `id.dev.<domain>` without credentials, path, port,
query or fragment. Rendering is deterministic and refuses an existing output
file. It creates no users, passwords, certificates, DNS records or API objects.
The domain above was used for server-side dry-run only; this does not establish
that its DNS or HTTPS endpoint is provisioned.

Before actual deployment, provision these separate DEV inputs in namespace
`hetero-dev-identity` without copying production state:

- `dev-keycloak-tls`: a TLS Secret with `tls.crt` and `tls.key`, whose certificate
  covers the selected hostname and whose CA is trusted by actual DEV clients.
- `dev-keycloak-bootstrap`: fresh temporary administrator `username` and
  `password`. This is not the eventual owner identity. Complete bootstrap and
  remove the temporary admin through the supported Keycloak procedure.
- The existing CNPG-generated `dev-identity-postgres-app` credentials and
  `dev-identity-postgres-ca` certificate. Mount only `ca.crt`, not the CA key.
- DNS and TLS routing for the selected hostname. The Service exposes only
  ClusterIP port 443; there is no NodePort, public Ingress or global DNS change.

The PostgreSQL JDBC URL requires `sslmode=verify-full` and the CNPG CA. Three
servers each have a maximum pool size of 15, below the database's configured
100 connections, leaving room for replication/operator/maintenance connections.

Apply only after checking the same DEV cluster identity as `apply.py` and
reviewing the generated resources and secret inputs. The current foundation
`apply.py` deliberately does not accept this dynamically rendered bundle yet.
Do not bypass its environment checks or apply it to a default kube context.
The bundle orders NetworkPolicy before the Deployment, but applying a List is
not atomic and the whole apply must be checked for errors.

## Network And Authentication

The main listener is HTTPS-only. Management port 9000 is not exposed by the
Service. Ingress permits the explicitly identified DEV host sources for
administration/probes, and namespaces explicitly labeled
`heteronetwork.dev/identity-client=true` for HTTPS. That label is an administrator
grant and must not be assignable by untrusted tenants.

Only Keycloak Pods can use the cluster transport ports 7800 and 57800. Database
and DNS egress are scoped by namespace and Pod labels; public egress is not
enabled. External identity brokering/email therefore require separate reviewed
egress rules and are not implied by this configuration.

The `jdbc-ping` stack discovers peers through this DEV database and retains
Keycloak's default encrypted TCP transport. No Kubernetes API token is mounted.
See the official [cache guide](https://www.keycloak.org/server/caching),
[container guide](https://www.keycloak.org/server/containers) and
[management guide](https://www.keycloak.org/server/management-interface).

Realm/client provisioning, the real owner subject pin, OIDC login/refresh,
certificate trust, cluster formation and failure recovery still require live
validation. In particular, do not invent a subject or use the bootstrap admin as
the sudo owner just to make a policy validate.

## Observed Validation

The two focused contract tests passed. The generated five resources passed
server-side apply **dry-run** against DEV kube-system UID
`a39281cb-d273-4c5f-b7a7-fca722fb417b`, with the existing protected helper's
guest, node, API endpoint and CIDR guards. Nothing was applied or started.
Admission success does not validate Secret existence, database TLS, image
startup, readiness, DNS, browser authentication or HA.
