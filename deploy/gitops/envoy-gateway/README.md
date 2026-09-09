# Public web DNS ownership

`public-web-dns.yaml` is the ExternalDNS source of truth for the platform's
host Caddy front doors on ports 80/443. It is deployment inventory, not an
automatically discovered list of healthy Kubernetes LoadBalancer addresses.
The apex is Cloudflare-proxied; the other records are DNS-only.

Do not publish the same names from HTTPRoute or the internal Envoy
LoadBalancer Service. Its empty status during an eligibility outage caused
ExternalDNS `--policy=sync` to delete working public front-door records on
2026-09-09. Empty internal Gateway status must not remove this inventory.
ExternalDNS sync policy remains enabled so deliberate inventory removals
still delete obsolete records.

Before changing targets, verify the intended hostname using HTTPS with
`curl --resolve` against each new front door. Keep this list limited to
commissioned front doors; update it when decommissioning a host. This does
not implement health-based DNS failover and does not restore failed backend
services. Dynamic tenant L4 LoadBalancer DNS remains separately managed.

Verification:

- Render `kubectl kustomize deploy/gitops/envoy-gateway` and verify the five
  DNSEndpoint names have nonempty targets independently of Gateway status.
- Check ExternalDNS logs and query both authoritative and recursive DNS.
- Check public `/`, `/login`, `/api/v1/auth/oidc/start`, Flow health, and
  an existing Flash HTTPS hostname. A working login page alone is not a
  successful authentication check.
- Negative DNS caches may retain the prior missing-record response after
  authoritative records have been restored.
