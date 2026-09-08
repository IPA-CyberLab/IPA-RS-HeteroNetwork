# Flash wildcard host TLS sync

The cert-manager Application installs the certificate controller. The
AppProject permits `cert-manager` and `heterocloud-dns`. Issuance is declared
in `issuer.yaml` / `certificate.yaml` in this directory.
The Certificate must provision a DNS01-issued `kubernetes.io/tls` Secret named
`flash-web-tls` in `heterocloud-dns`, with SAN `*.flash.heterocloud.mizuame.app`
and an unencrypted private key. Kustomize intentionally requires those two
parent files; this helper neither creates nor modifies them.
`wildcard-route.yaml` is included here for the wildcard
fallback HTTPRoute and ExternalDNS publication from Gateway status addresses.
No DNS addresses are hardcoded by this helper.

## Scope and prerequisites

- The DaemonSet requires the existing
  `networking.heteronetwork.io/public-ingress=true` label (see
  `../envoy-gateway/envoyproxy.yaml`) AND hostname `uc-k8s3p` or `ichikawap1`.
  It does not label nodes or enable gateway roles. Expand only after review.
- The only writable host mount is `/etc/heteronetwork` (Directory, not
  DirectoryOrCreate). `/etc/group` is separately mounted read-only. There is
  no host network/PID namespace, privileged mode, Kubernetes API token or RBAC.
  Root plus CHOWN/DAC_OVERRIDE/FOWNER is needed for host ownership and modes.
  This workload consequently requires an appropriate Pod Security admission
  exception; it cannot run under the restricted profile.
- An existing root-owned, regular, non-symlink, single-link
  `/etc/heteronetwork/public-gateway-extra.Caddyfile` is mandatory. It and all
  ancestors must not be group/world writable. The existing
  `(heterocloud_envoy)` definition is mandatory. Missing prerequisites fail
  closed; no empty canonical extra file or snippet is synthesized.
- The installer unit in `crates/ipars-control-plane-http/src/lib.rs` uses
  `User=heteronetwork-gateway` and `Group=heteronetwork-gateway`, confirmed by
  on the live gateway. The numeric GID comes from each host's group file.
  Cert directories are root:GID 0750; certificate and key files root:GID 0640.
  Confirm that Caddy can traverse `/etc/heteronetwork` on both hosts.
  If the host group is recreated/renumbered, restart the pod to refresh the
  file bind mount and have an operator repair ownership before syncing.
- Runtime image must contain Python 3 and the OpenSSL CLI; the manifest uses
  the full Debian Python image, not slim, pinned to the tested image digest.
  Review the image for deployment approval and future security updates. There
  is no package installation or network use at runtime.

## Reconciliation and renewal

The loop polls the read-only projected Secret every 60 seconds. It pins one
`..data` directory for paired reads across kubelet rotation, validates the
wildcard SAN, hostname, key correspondence, PEM chain parsing, current validity,
and at least one hour remaining. It does not perform public trust-chain or
revocation validation; cert-manager issues the certificate and external probes
verify its public trust chain.
OpenSSL subprocess output, private keys and exception contents are never logged.

Both files are fsynced into an immutable SHA-256 generation directory under
`/etc/heteronetwork/flash-web-certs/` before a same-directory atomic replacement
of the extra file. The hash covers the complete cert/key pair. The helper
appends one marked wildcard HTTP :80 redirect and HTTPS :443 site; renewal
replaces only that block. Every byte outside the markers, including appended
operator content, is retained. Unmanaged wildcard occurrences, malformed
markers, unsafe existing files or tampered generation files stop publication.
The extra file's owner/group/mode are preserved, with the Agent's 256 KiB limit.

New certificate paths change the extra file digest. The existing Agent detects
that change and reloads Caddy; **no Agent or Caddy restart is required**.
Restarting the sync pod is idempotent and reuses the immutable generation.
Secret projection latency plus the 60-second poll and Agent reconciliation
interval determine renewal latency. A readiness probe checks recent successful
sync, not end-to-end HTTPS; monitor external HTTPS and cert-manager separately.
Failures retain the last published configuration and retry; they never remove
an old route or certificate. That last certificate may eventually expire, so
investigate prolonged unready state. No liveness restart loop is used.

Old generation directories are deliberately retained for active readers and
rollback. Operators may remove unreferenced generations only after confirming
Agent/Caddy loaded the new configuration and preserving rollback material.
Deleting the DaemonSet does not remove host routes or files.

The helper takes an advisory flock on
`/etc/heteronetwork/.flash-web-tls.lock`. Other writers of the canonical extra
file must use the same lock for the full read/edit/rename transaction. An
additional inode/metadata/content check detects concurrent edits before rename,
but no atomic compare-and-replace exists against an uncooperative root writer.

## Deployment review

1. Review the Certificate and Issuer, then render with
   `kubectl kustomize deploy/gitops/flash-web`. Review the generated ConfigMap,
   hostname allowlist, image and security context; do not apply until approved.
2. On each host, verify the existing extra, snippet, group, directory traversal,
   configured Agent extra path and service identity. Verify issued Secret
   readiness without printing key material.
3. Validate the candidate **complete Agent-rendered Caddyfile** with the host's
   `/opt/heteronetwork/bin/caddy validate --adapter caddyfile --config <candidate>`
   as `heteronetwork-gateway`, using readable staged certfiles. The extra alone
   is not the complete runtime configuration. Caddy syntax validation is a
   deployment gate, not implemented inside this Python container.
4. After approved deployment, confirm readiness, Agent digest/reload success,
   HTTP redirect and HTTPS certificate/route on both nodes. Exercise a renewal
   and verify a new immutable path/digest without restarting Caddy or the Agent.
5. To roll back, first stop the reconciler, then under the shared lock restore
   the reviewed previous extra atomically (or remove only the managed block).
   Keep all referenced generation files. The Agent will reconcile the digest.

Local tests (temporary fixtures under `/run`, no cluster calls or live host edits):

```sh
sudo python3 -B scripts/test_flash_tls_sync.py
```

External checks (certificate verification is never disabled):

```sh
python3 scripts/flash-web-preflight.py --host f-SERVICE-UUID.flash.heterocloud.mizuame.app
```

References: [cert-manager DNS01](https://cert-manager.io/docs/configuration/acme/dns01/),
[Caddy TLS](https://caddyserver.com/docs/caddyfile/directives/tls),
[Envoy direct responses](https://gateway.envoyproxy.io/v1.8/tasks/traffic/direct-response/).
