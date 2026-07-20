# Security Model

This document describes the current HeteroNetwork trust boundaries and the operator controls that are implemented in the repository today.

## Trust Boundaries

- Control plane state is authoritative for node identity, VPN IP leases, WireGuard public keys, endpoint candidates, relay capability, ACL/policy, advertised routes, health, and pair-scoped path state.
- Signal coordinates endpoint exchange, NAT traversal strategy, hole-punch timing, and relay candidate selection. It does not forward data-plane payloads.
- Relay forwards opaque credentialed UDP frames. Relay admission and forwarding do not require payload decryption; WireGuard payload confidentiality remains end to end between peers.
- Agents own node identity keys, WireGuard private keys, local runtime state, route application, peer-map application, relay forwarders, and heartbeat reporting.
- Docker and Kubernetes integrations are route-intent integrations for underlay reachability. They do not replace the Kubernetes CNI and they do not rely on iptables-only rewrites as the primary integration contract.

## Join Tokens

Join tokens are Ed25519-signed claims containing the cluster ID, issuer node/key IDs, bootstrap endpoints, expiration, role/tags, relay permission, route allowlist, max-use policy, and nonce. Tokens are single-use by default unless `--max-uses` or `--unlimited-uses` is explicitly set.

Implemented controls:

- the signature envelope must be canonical standard Base64 encoding of exactly one 64-byte Ed25519 signature, so malformed, non-canonical, wrong-length, and oversized signatures are rejected before issuer lookup or cryptographic verification;
- token validity is positive and capped at the 30-day TTL plus the 5-second `not_before` clock-skew allowance used by the CLI;
- cluster, issuer, key, role, nonce, claim-tag, and policy-tag identifiers are path-safe and capped at 255 bytes;
- claim and policy tag sets are each capped at 64 entries;
- bootstrap endpoints are typed and validated before signing and after parsing: at most 32 total, 8 per service kind, and 2048 bytes per URL, with duplicate, control-character, userinfo, query, fragment, scheme/kind mismatch, and unusable numeric-address rejection;
- route allowlists are capped at 256 entries, and unsafe, duplicate, non-canonical, and overlapping CIDRs are rejected;
- the signer, verifier, CLI, Agent, and Control Plane share the same claim-shape validator, and every token-consuming boundary validates the complete signed envelope, with the Control Plane rejecting malformed signatures and claims before issuer lookup or token-ledger mutation;
- relay permission is explicit;
- control-plane token ledgers persist max-use and revocation state;
- SQL token-use updates use compare-and-swap semantics so concurrent control-plane instances do not over-admit the same token.

The optional Web UI enrollment path uses a dedicated online Ed25519 signer, not
the offline root issuer. The trusted-key entry carries an enforced enrollment
policy: only `edge`, `worker`, and `gateway` roles; identical claim and policy
tags; no route authorization; a finite maximum of 1,000 uses; the configured TTL
ceiling; and two distinct Control Plane, Signal, and STUN endpoints. Relay
permission additionally requires two distinct Relay endpoints. These checks run
after signature verification at every token boundary, so possession of the
enrollment signer cannot mint a control-plane, route-authorizing, unlimited, or
degraded-bootstrap token. The key is also rejected at the cluster-wide token
revocation boundary.
Control Plane startup rejects both public-key reuse with any unrestricted
trusted issuer and an enrollment issuer/key ID that collides with an existing
trusted entry. The packaged systemd unit obtains the enrollment signer through
`LoadCredential=` from a root-only credential store; sibling Signal, STUN, and
Relay services do not receive the service-scoped read-only copy.

The same signer can issue a distinct macOS client token only through the
authenticated client-enrollment endpoint. Server-side issuer policy forces role
`client`, one use, no tags, no allowed routes, no relay permission, at least two
active Control Plane endpoints, and a currently reachable gateway. A client
token is rejected by the normal node join endpoint without consuming it. The
dedicated client join endpoint rejects all non-client tokens.

After enrollment, the macOS app keeps its Ed25519 identity and WireGuard private
key in a device-only shared Keychain item available to the containing app and
packet-tunnel extension. Enrollment tokens are not persisted. Peer-map refresh
and removal requests carry bounded-fresh operation-specific Ed25519 signatures
and random nonces. The packet tunnel accepts exactly one gateway peer and
rejects default routes, malformed CIDRs, local or relay endpoint candidates,
and invalid WireGuard keys before starting WireGuardKit. This client identity is
explicitly denied access to heartbeat, Signal, path-reporting, normal removal,
and node key-rotation operations.

Enrollment issuance is an authenticated `/v1/admin/*` operation and inserts the
signed definition into the shared token ledger before returning it. Installer
and binary routes require the same signed token and confirm that the ledger
record remains active, unexpired, unrevoked, and unexhausted. Responses are
non-cacheable; the binary is pinned at startup by regular-file identity, size,
and SHA-256, and is revalidated before each download. The generated installer
keeps the token in an owner-only temporary file, removes it after one-time
enrollment, and never embeds it in the persistent service unit.

Revoke a token with:

```bash
ipars token revoke --control-plane-url https://203.0.113.10:8443 --cluster-id <cluster-id> --nonce <token-nonce> --issuer-private-key-path ./issuer.key --issuer-key-id root
```

The CLI signs the cluster ID, nonce, issuer node/key IDs, and current timestamp with the existing issuer private key. The control plane rejects missing, malformed, tampered, untrusted-key, wrong-cluster, or stale signatures before changing the token ledger. Any trusted issuer key can perform cluster-level revocation, which keeps issuer rotation overlap usable. Revocation blocks new joins; existing data-plane sessions continue until policy, peer-map, route, or key changes are applied. A durable tombstone makes this true even before the token's first admission. Admission and revocation share one per-token serialization point, so a racing join is either counted before the tombstone or rejected after it; it cannot commit on the far side of a completed revocation.

First admission of an unseen token uses insert-if-absent semantics rather than an upsert. This prevents redundant Control Planes from replacing a concurrently incremented single-use record with `uses = 0`. SQLite holds the writer transaction across tombstone lookup and use increment; PostgreSQL uses the same cluster/nonce advisory lock for issue, admission, and revocation. New records also retain the complete verified claims and reject the same cluster/nonce under different bootstrap, validity, role/tag, issuer, or policy claims; records written before the claims snapshot was introduced continue to use the persisted immutable ledger fields for compatibility.

## Key Rotation

Identity and WireGuard key material uses canonical standard Base64 encoding of exactly 32 bytes, which is 44 encoded bytes including padding. Oversized, malformed, non-canonical, and wrong-length keys are rejected before key construction. Ed25519 public keys flagged as weak are rejected, as are low-order X25519/WireGuard public keys that cannot contribute to a shared secret. Control Plane startup validates the primary and every overlapping trusted issuer public key before binding the service; node registration, request authentication, WireGuard rotation, and Agent command/netlink backends apply the same key boundaries.

Persisted Agent state is accepted only when the identity private key derives the stored identity public key and node ID, the WireGuard private key derives the stored WireGuard public key, and `updated_at` is not before `created_at`. File load, save, and runtime replacement all reject inconsistent state. Treat such rejection as state corruption or an invalid manual edit; restore a consistent owner-only state backup or deliberately re-enroll the node rather than copying individual key fields.

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

WireGuard data-plane keys rotate through the local agent API. The agent signs the previous-to-next public-key transition with the persisted node identity key, submits it to the control plane, persists the accepted private key with owner-only state-file permissions, and updates running state after acceptance. Peer-map application rejects one public key assigned to multiple active Node IDs or a remote peer that reuses the local interface key, obtains the actual WireGuard peer-key inventory before mutation, and removes keys outside the latest authoritative active/pinned set by public key, so an old remote key or a peer left in the kernel across an Agent restart cannot remain authorized merely because the new process lost its Node ID/key cache. Reconciliation runs only after an identity-signed peer-map query succeeds and fails closed before peer mutation when the interface inventory cannot be read.

Peer routes use Linux route protocol `240` as an ownership marker. After the same authenticated peer-map fetch, the Agent inventories both IPv4 and IPv6 main-table routes on its managed WireGuard interface, validates the complete desired route plan, and removes unknown protocol-240 routes plus shape-compatible legacy HeteroNetwork `boot`/`static` routes before changing peers. Kernel-connected routes, gateway/multipath routes, other protocols, interfaces, and tables are outside this cleanup boundary. A malformed HeteroNetwork-marked row, truncated command output, netlink failure, or deletion failure stops that map application before WireGuard mutation instead of trusting an incomplete inventory.

Docker and Kubernetes route reconciliation use separate numeric route protocols (`241` and `242`) and fixed policy-rule boundaries (`10064` for Docker routes/rules and `10050` for Kubernetes rules). Their live inventories cover both address families and all routing tables, but only the active owner protocol plus the documented legacy table/priority entries are eligible for deletion. Other protocols, interfaces, selectors, and route shapes remain outside the cleanup boundary. Reconciliation runs before applying the new plan, so an Agent or runtime-loop restart cannot preserve stale owner-marked non-main routes or policy rules merely because process-local state was lost.

Node removal uses the same node identity boundary. `DELETE /v1/nodes/{node_id}` requires a signed request from the registered node identity before the control plane removes the durable node record, clears health/path state, and releases the VPN IP lease for reuse.

Every signed management request uses the same fixed signature envelope as join tokens: canonical standard Base64 encoding of exactly one 64-byte Ed25519 signature, or 88 encoded bytes including padding. Heartbeat, WireGuard key rotation, node removal, token revocation, Control Plane node query, and Signal upsert/path/hole-punch verifiers reject malformed, non-canonical, wrong-length, and oversized envelopes before public-key parsing or cryptographic verification. Signature-shape rejection is distinct from a correctly shaped signature that fails authentication.

Heartbeat replay protection is enforced again at durable commit, not only during request validation. Candidates, relay capability, optional routes, health freshness, and the reporting node's complete path snapshot are committed in one transaction after the store serializes that node and confirms the signed timestamp is newer than durable health state. A stale request reaching another Control Plane replica can therefore neither overwrite one field nor leave a mixed-generation node snapshot.

## Signal Authentication

Signal node upserts, path negotiations, and hole-punch plan requests require an Ed25519 signature from the requesting node's persisted identity key. Each signed payload includes the complete request body, a bounded-fresh timestamp, and a random 192-bit nonce. Signal keeps a bounded accepted-nonce cache and rejects duplicates, stale signatures, body tampering, source-ID mismatches, and requests from nodes without fresh authenticated membership.

For each node upsert, Signal asks an ordered control-plane endpoint set to verify the signature against the registered identity public key. Signal stores the authoritative control-plane `NodeRecord` rather than trusting client-supplied role, policy, route, or relay attributes. `--node-auth-ttl-seconds` or `HETERONETWORK_SIGNAL_NODE_AUTH_TTL_SECONDS` bounds membership freshness; stale members are removed and cannot negotiate paths or request hole-punch plans until a signed upsert succeeds again. Configure control-plane failover with repeated `--control-plane-url` values or `HETERONETWORK_SIGNAL_CONTROL_PLANE_URLS`.

## Control-Plane Node Queries

Peer maps and node-scoped path status are available only through `POST /v1/peers/query` and `POST /v1/paths/query`. Requests require the queried node's Ed25519 identity signature over the node ID, operation kind, bounded-fresh timestamp, and random 192-bit nonce. The operation kind prevents a peer-map proof from being reused for path status. Each control-plane process keeps a bounded five-minute nonce cache and rejects same-instance replays; redundant instances independently verify every request. TLS remains required between nodes and control-plane endpoints to protect response confidentiality and cross-instance transport.

The agent signs peer-map polling requests with its persisted owner-only state. Direct `ipars peers`, `ipars routes`, or `ipars path status` queries against a control-plane URL require `--agent-state-path`; the CLI rejects state/node mismatches and never places the private key in the URL, request body, command arguments, or logs.

## Bearer Token Files

Every file-backed `iparsd` operator API, Agent management API, and Relay admission credential uses the same bounded secret loader. On Unix, the final path component must be a single-link regular file that is owner-readable and has no group or world permission bits; direct symlinks, hardlinks, directories, oversized input, and owner-unreadable or broadly accessible files are rejected. The daemon opens with `O_NOFOLLOW | O_NONBLOCK`, verifies the opened device/inode against pre-open metadata, and rechecks the descriptor after reading so a final-component replacement race cannot redirect or block startup on a substituted FIFO. Parent-directory symlinks are not prohibited, so those directories remain part of the operator's trust boundary.

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

Relay Prometheus metrics are available through `GET /metrics` only when `iparsd relay --operator-api-bearer-token` or `--operator-api-bearer-token-path` configures a separate 32-512 byte printable non-whitespace ASCII credential. Without one, the route returns 404. With one, missing or rejected credentials return 401 with a Bearer challenge and fixed-bound constant-time comparison. `/healthz` and `/v1/status` remain public orchestration/capability routes; `POST /v1/sessions` retains its independently configured 32-512 byte admission Bearer credential and abuse controls. Relay servers accept that admission credential from `--admission-bearer-token-path`/`HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_PATH`, and Agents accept the same bounded file through `--relay-admission-bearer-token-path`/`HETERONETWORK_AGENT_RELAY_ADMISSION_BEARER_TOKEN_PATH`; inline forms remain mutually exclusive compatibility options.

Compose mounts the Relay operator credential from a dedicated secret. Do not reuse the relay admission token: metric scrapers do not need session-admission authority, and admission clients do not need detailed counters.

## Agent Management API

The Agent HTTP listener defaults to `127.0.0.1:9780`. A non-loopback listener is rejected at startup unless `--api-bearer-token` or `--api-bearer-token-path` supplies a separate 32-512 byte printable non-whitespace ASCII token. When configured, Bearer authentication covers every `/v1/*` route and `/metrics`; only `/healthz` remains public for liveness and readiness probes.

The daemon bounds token-file reads and compares submitted credentials in constant time over a fixed maximum size. The CLI applies its global `--agent-api-bearer-token` or `--agent-api-bearer-token-path` source to every Agent API read and mutation. Prefer file-backed tokens, keep them separate from signed join tokens, and rotate them through the deployment secret mechanism. The Kubernetes chart uses a distinct Secret key and rejects reuse of the join-token key.

Bearer authentication is an authorization control, not transport encryption. Use TLS before traffic leaves a trusted host or private deployment network.

## Peer Probe Abuse Controls

The autonomous quality responder binds to the node's assigned VPN IP, not a
public or wildcard address. It accepts only exact fixed-width versioned request
packets from VPN source IPs present in the current peer map, returns one
same-size packet, and rate-limits each peer. Responses echo a random 128-bit
challenge and sequence number, so off-path packets cannot satisfy a sample and
the protocol has no amplification factor. A bounded protocol flag distinguishes
quality-only requests from wake intent; only wake intent from an authenticated
peer can transition a passive path to active. Unknown sources, malformed packets,
rate-limit drops, and send failures have separate metrics.

WireGuard cryptokey routing authenticates the overlay source address before the
UDP responder sees it. Quality observations are additionally covered by the
source node's Signal-request signature and include the measured path state,
candidate or relay fingerprint, sample counts, and timestamp. Signal rejects
inconsistent loss/sample values, future-invalid data, agent-supplied relay
load, and impossible path shapes; stale or nonmatching observations are
counted but ignored for scoring. A compromised member can still under-report
its own observed quality, so these measurements are path-selection hints, not
an authorization or billing trust boundary.

## Relay Abuse Controls

Relay eligibility requires policy permission, usable public endpoint/admission URL values, fresh healthy heartbeat state, capacity, and E2E-only relay mode. Public IP reachability alone is not enough to become a relay.

Implemented controls:

- optional Bearer token protection for relay admission;
- admission rate limits, including unauthorized attempts;
- global and per-participating-node active session caps;
- rejection of unsafe participant node IDs, self-relay, same-endpoint, unusable endpoint, expired, malformed, oversized, unsafe routed-frame node metadata, or wrong-credential frames; repeated admission for an active pair reuses its existing credential and refreshes only the pair's observed endpoints rather than allocating a replacement session;
- per-session throughput windows;
- cumulative admission and dataplane counters with failure reasons;
- agent-side relay candidate ranking by utilization, remaining capacity, and bandwidth;
- gated network-namespace relay fallback smoke coverage that sends an invalid relay credential before the accepted opaque payload.

## Operator Requirements

- Terminate TLS at a reverse proxy, load balancer, or Kubernetes Ingress before exposing control-plane, signal, relay admission, or agent APIs outside a private deployment network.
- Store issuer private keys outside the control-plane process where possible; pass only issuer public keys to redundant control-plane instances.
- If Web UI enrollment is enabled, use a separate enrollment signer on the Control Plane replicas; with the packaged systemd unit, keep its source root-only in `/etc/credstore` and let `LoadCredential=` expose it only to Control Plane. Never reuse the offline root issuer key, and rotate this online key as an independently scoped credential.
- When using `ipars init --spawn-daemons`, spawned bootstrap services receive a cleared environment with only a fixed system `PATH` and `C` locale so issuer-key environment variables are not propagated.
- Prefer file-backed join tokens through `--join-token-path` or Kubernetes Secrets over command-line token arguments.
- Keep Agent API Bearer tokens owner-only, separate from join tokens, and pass them through `--api-bearer-token-path`, Compose secrets, or a distinct Kubernetes Secret key.
- Keep the Control Plane operator API credential owner-only and distinct from issuer, join, node, Agent, and relay credentials; prefer `--operator-api-bearer-token-path` and rotate it through the deployment secret mechanism.
- Keep the Signal operator API credential owner-only and distinct from the Control Plane credential and all node/data-plane credentials; prefer `iparsd signal --operator-api-bearer-token-path` and rotate it through the deployment secret mechanism.
- Keep the STUN operator API credential owner-only and distinct from every other credential; prefer `iparsd stun --operator-api-bearer-token-path` while leaving UDP Binding publicly reachable.
- Keep the Relay operator API credential distinct from the relay admission token; prefer `iparsd relay --operator-api-bearer-token-path` and grant metric scrapers only that credential.
- Keep agent state directories and files owner-only. The daemon rejects symlinked or group/world-accessible key state.
- Enable file-backed relay admission Bearer tokens for public relays and distribute the same scoped secret only to authorized Agents.
- Scope ACLs and route allowlists by role, tag, route, and protocol. Deny rules take precedence.
- Treat Docker API socket mounts as discovery-only and opt-in; the base Compose agent does not mount the Docker socket. For remote Docker Engines, prefer `--docker-api-url` with HTTPS and use `--docker-api-ca-cert-path` only for a bounded, non-symlink PEM trust bundle; URL-backed installs do not bind a local Docker socket.
