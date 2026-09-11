# DEV Cloud Serving TLS

`provision-cloud-tls.py` issues one RSA-3072 serving certificate using the existing
isolated DEV identity CA. It repeats the identity foundation's live cluster and
guest guards, verifies the existing CA manifest's cluster/origin and CA file
hashes, and does not change the CA or Keycloak certificate.

`cloud_tls.py` limits SANs to the DEV Cloud public name and its internal Service
names. No production hostname, wildcard, IP address or owner hostname is added.
The certificate is for server authentication, not CA signing. Validity is at
most 30 days and never exceeds CA expiry. Signature, key pair, exact SANs,
extended key usage, chain bytes and remaining validity are checked on repeat.

Private state is retained on DEV1 at `/var/lib/heteronetwork-dev-cloud-tls`.
The directory is root-only 0700 and files 0600. Files are written exclusively
and fsynced; a hash manifest is written last. Partial state causes refusal,
not regeneration. Preserve it when investigating an interrupted invocation.
The CA private key remains in its original protected DEV1 directory and is not
copied into Kubernetes.

Two Secrets are created in `heterocloud-dev`:

- `heterocloud-dev-tls`: serving leaf/CA certificate chain and serving private key.
- `heterocloud-dev-identity-ca`: public CA certificate only, for future client trust configuration.

Existing Secrets must match the exact data and DEV ownership markers. Missing
Secrets use server dry-run, create and readback; credentials are passed through
stdin, never displayed. No workload or production configuration is applied.

## Actual Execution: 2026-09-11

The first invocation created both Secrets and new serving-certificate state.
The second verified both Secrets with no creation or certificate regeneration.
Both reported `workloads_changed: false`. Two focused certificate tests passed,
covering the valid chain/exact DEV names and wrong CA/private-key rejection.

Tools on DEV1: `/opt/heteronetwork-dev-cloud-tls-e342d55a`.
Archive SHA256:
`e342d55aeb7c3e4797cb3a2636903895a26e7f2b8f87da3faafddba0918339ee`.
Provisioner SHA256:
`a3f329e881d640bb138fc81a525b9c5b74f033924fe77a363f4e9539b9385510`.

## Remaining Trust Work

Cloud has since been deployed from0.1.71-dev.5, and its chart consumes the
identity CA for OIDC. The runtime verifier passed private-CA hostname-validated
TLS connections and OIDC initiation on all3 API Pods; see [RUNTIME.md](RUNTIME.md).
This is not publicly trusted HTTPS or a completed authenticated login.
Owner/edge TLS, public DNS, browser trust, client authentication,
certificate renewal and rollout remain separate work. The helper refuses a
certificate with less than one day remaining rather than silently rotating it.
