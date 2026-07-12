# Security Model

This document describes the current IPA-RS trust boundaries and the operator controls that are implemented in the repository today.

## Trust Boundaries

- Control plane state is authoritative for node identity, VPN IP leases, WireGuard public keys, endpoint candidates, relay capability, ACL/policy, advertised routes, health, and pair-scoped path state.
- Signal coordinates endpoint exchange, NAT traversal strategy, hole-punch timing, and relay candidate selection. It does not forward data-plane payloads.
- Relay forwards opaque credentialed UDP frames. Relay admission and forwarding do not require payload decryption; WireGuard payload confidentiality remains end to end between peers.
- Agents own node identity keys, WireGuard private keys, local runtime state, route application, peer-map application, relay forwarders, and heartbeat reporting.
- Docker and Kubernetes integrations are route-intent integrations for underlay reachability. They do not replace the Kubernetes CNI and they do not rely on iptables-only rewrites as the primary integration contract.

## Join Tokens

Join tokens are Ed25519-signed claims containing the cluster ID, issuer node/key IDs, bootstrap endpoints, expiration, role/tags, relay permission, route allowlist, max-use policy, and nonce. Tokens are single-use by default unless `--max-uses` or `--unlimited-uses` is explicitly set.

Implemented controls:

- token TTL is capped at 30 days;
- tags are bounded and path-safe;
- bootstrap endpoints are typed and validated before signing;
- unsafe, duplicate, non-canonical, and overlapping route allowlists are rejected;
- relay permission is explicit;
- control-plane token ledgers persist max-use and revocation state;
- SQL token-use updates use compare-and-swap semantics so concurrent control-plane instances do not over-admit the same token.

Revoke a token with:

```bash
ipars token revoke --control-plane-url https://203.0.113.10:8443 --cluster-id <cluster-id> --nonce <token-nonce> --issuer-private-key-path ./issuer.key --issuer-key-id root
```

The CLI signs the cluster ID, nonce, issuer node/key IDs, and current timestamp with the existing issuer private key. The control plane rejects missing, malformed, tampered, untrusted-key, wrong-cluster, or stale signatures before changing the token ledger. Any trusted issuer key can perform cluster-level revocation, which keeps issuer rotation overlap usable. Revocation blocks new joins; existing data-plane sessions continue until policy, peer-map, route, or key changes are applied.

## Key Rotation

Issuer signing key rotation is overlap-based. Start control-plane instances with repeated trusted issuer public keys:

```bash
iparsd control-plane \
  --issuer-node-id issuer-a \
  --issuer-key-id next \
  --issuer-public-key <next-public-key> \
  --trusted-issuer-key issuer-a,root,<old-public-key> \
  --trusted-issuer-key issuer-a,next,<next-public-key>
```

Then mint new tokens with the next issuer key. Keep the old public key trusted until all unexpired old tokens have either expired or been revoked.

WireGuard data-plane keys rotate through the local agent API. The agent signs the previous-to-next public-key transition with the persisted node identity key, submits it to the control plane, persists the accepted private key with owner-only state-file permissions, and updates running state after acceptance.

Node removal uses the same node identity boundary. `DELETE /v1/nodes/{node_id}` requires a signed request from the registered node identity before the control plane removes the durable node record, clears health/path state, and releases the VPN IP lease for reuse.

## Signal Authentication

Signal node upserts, path negotiations, and hole-punch plan requests require an Ed25519 signature from the requesting node's persisted identity key. Each signed payload includes the complete request body, a bounded-fresh timestamp, and a random 192-bit nonce. Signal keeps a bounded accepted-nonce cache and rejects duplicates, stale signatures, body tampering, source-ID mismatches, and requests from nodes without fresh authenticated membership.

For each node upsert, Signal asks an ordered control-plane endpoint set to verify the signature against the registered identity public key. Signal stores the authoritative control-plane `NodeRecord` rather than trusting client-supplied role, policy, route, or relay attributes. `--node-auth-ttl-seconds` or `IPARS_SIGNAL_NODE_AUTH_TTL_SECONDS` bounds membership freshness; stale members are removed and cannot negotiate paths or request hole-punch plans until a signed upsert succeeds again. Configure control-plane failover with repeated `--control-plane-url` values or `IPARS_SIGNAL_CONTROL_PLANE_URLS`.

## Control-Plane Node Queries

Peer maps and node-scoped path status are available only through `POST /v1/peers/query` and `POST /v1/paths/query`. Requests require the queried node's Ed25519 identity signature over the node ID, operation kind, bounded-fresh timestamp, and random 192-bit nonce. The operation kind prevents a peer-map proof from being reused for path status. Each control-plane process keeps a bounded five-minute nonce cache and rejects same-instance replays; redundant instances independently verify every request. TLS remains required between nodes and control-plane endpoints to protect response confidentiality and cross-instance transport.

The agent signs peer-map polling requests with its persisted owner-only state. Direct `ipars peers`, `ipars routes`, or `ipars path status` queries against a control-plane URL require `--agent-state-path`; the CLI rejects state/node mismatches and never places the private key in the URL, request body, command arguments, or logs.

## Control-Plane Operator API

Control-plane policy and metrics are available through `GET /v1/policy`, `GET /v1/metrics`, and `GET /metrics` only when `--operator-api-bearer-token` or `--operator-api-bearer-token-path` configures a 32-512 byte printable non-whitespace ASCII credential. When no credential is configured, these routes are not registered and return 404. When configured, missing or rejected credentials return 401 with a Bearer challenge, and comparison runs over a fixed maximum size.

The CLI applies its distinct global `--control-plane-operator-api-bearer-token` or preferred `--control-plane-operator-api-bearer-token-path` source to `ipars status --control-plane-url`. Compose mounts a dedicated file-backed secret, and the Kubernetes live gate mounts a separate Secret key. Do not reuse issuer private keys, join tokens, node identities, Agent management credentials, or relay admission credentials. Bearer authentication does not encrypt policy or metric responses, so TLS remains required outside trusted private transport.

## Signal Operator API

Signal JSON and Prometheus metrics are available through `GET /v1/metrics` and `GET /metrics` only when `iparsd signal --operator-api-bearer-token` or `--operator-api-bearer-token-path` configures a separate 32-512 byte printable non-whitespace ASCII credential. Without one, both routes are unregistered and return 404. With one, missing or rejected credentials return 401 with a Bearer challenge and fixed-bound constant-time comparison. `/healthz` remains public; node upsert, path negotiation, and hole-punch routes continue to require node-identity signatures and never accept this operator token as a substitute.

Compose mounts the Signal credential from its own file-backed secret. Keep it distinct from Control Plane, Agent, issuer, join, node-identity, and relay credentials, and use TLS whenever metric traffic leaves trusted private transport.

## STUN Operator API

STUN JSON and Prometheus metrics use `GET /v1/metrics` and `GET /metrics` only when `iparsd stun --operator-api-bearer-token` or `--operator-api-bearer-token-path` configures a separate 32-512 byte printable non-whitespace ASCII credential. Without one, both metric routes return 404. With one, missing or rejected credentials return 401 with a Bearer challenge and fixed-bound constant-time comparison. `/healthz`, UDP Binding requests, and RFC5780 filtering probes remain public because clients need them before joining the overlay.

Compose mounts a distinct STUN operator secret. This Bearer control protects HTTP observations but does not encrypt them; use TLS for metric traffic outside trusted private transport and keep the credential separate from all node, issuer, relay, and other operator material.

## Relay Operator API

Relay Prometheus metrics are available through `GET /metrics` only when `iparsd relay --operator-api-bearer-token` or `--operator-api-bearer-token-path` configures a separate 32-512 byte printable non-whitespace ASCII credential. Without one, the route returns 404. With one, missing or rejected credentials return 401 with a Bearer challenge and fixed-bound constant-time comparison. `/healthz` and `/v1/status` remain public orchestration/capability routes; `POST /v1/sessions` retains its independently configured admission Bearer credential and abuse controls.

Compose mounts the Relay operator credential from a dedicated secret. Do not reuse the relay admission token: metric scrapers do not need session-admission authority, and admission clients do not need detailed counters.

## Agent Management API

The Agent HTTP listener defaults to `127.0.0.1:9780`. A non-loopback listener is rejected at startup unless `--api-bearer-token` or `--api-bearer-token-path` supplies a separate 32-512 byte printable non-whitespace ASCII token. When configured, Bearer authentication covers every `/v1/*` route and `/metrics`; only `/healthz` remains public for liveness and readiness probes.

The daemon bounds token-file reads and compares submitted credentials in constant time over a fixed maximum size. The CLI applies its global `--agent-api-bearer-token` or `--agent-api-bearer-token-path` source to every Agent API read and mutation. Prefer file-backed tokens, keep them separate from signed join tokens, and rotate them through the deployment secret mechanism. The Kubernetes chart uses a distinct Secret key and rejects reuse of the join-token key.

Bearer authentication is an authorization control, not transport encryption. Use TLS before traffic leaves a trusted host or private deployment network.

## Relay Abuse Controls

Relay eligibility requires policy permission, usable public endpoint/admission URL values, fresh healthy heartbeat state, capacity, and E2E-only relay mode. Public IP reachability alone is not enough to become a relay.

Implemented controls:

- optional Bearer token protection for relay admission;
- admission rate limits, including unauthorized attempts;
- global and per-participating-node active session caps;
- rejection of unsafe participant node IDs, self-relay, duplicate active node-pair, same-endpoint, unusable endpoint, expired, malformed, oversized, unsafe routed-frame node metadata, or wrong-credential frames;
- per-session throughput windows;
- cumulative admission and dataplane counters with failure reasons;
- agent-side relay candidate ranking by utilization, remaining capacity, and bandwidth;
- gated network-namespace relay fallback smoke coverage that sends an invalid relay credential before the accepted opaque payload.

## Operator Requirements

- Terminate TLS at a reverse proxy, load balancer, or Kubernetes Ingress before exposing control-plane, signal, relay admission, or agent APIs outside a private deployment network.
- Store issuer private keys outside the control-plane process where possible; pass only issuer public keys to redundant control-plane instances.
- When using `ipars init --spawn-daemons`, spawned bootstrap services receive a cleared environment with only a fixed system `PATH` and `C` locale so issuer-key environment variables are not propagated.
- Prefer file-backed join tokens through `--join-token-path` or Kubernetes Secrets over command-line token arguments.
- Keep Agent API Bearer tokens owner-only, separate from join tokens, and pass them through `--api-bearer-token-path`, Compose secrets, or a distinct Kubernetes Secret key.
- Keep the Control Plane operator API credential owner-only and distinct from issuer, join, node, Agent, and relay credentials; prefer `--operator-api-bearer-token-path` and rotate it through the deployment secret mechanism.
- Keep the Signal operator API credential owner-only and distinct from the Control Plane credential and all node/data-plane credentials; prefer `iparsd signal --operator-api-bearer-token-path` and rotate it through the deployment secret mechanism.
- Keep the STUN operator API credential owner-only and distinct from every other credential; prefer `iparsd stun --operator-api-bearer-token-path` while leaving UDP Binding publicly reachable.
- Keep the Relay operator API credential distinct from the relay admission token; prefer `iparsd relay --operator-api-bearer-token-path` and grant metric scrapers only that credential.
- Keep agent state directories and files owner-only. The daemon rejects symlinked or group/world-accessible key state.
- Enable relay admission Bearer tokens for public relays.
- Scope ACLs and route allowlists by role, tag, route, and protocol. Deny rules take precedence.
- Treat Docker API socket mounts as discovery-only and opt-in; the base Compose agent does not mount the Docker socket.
