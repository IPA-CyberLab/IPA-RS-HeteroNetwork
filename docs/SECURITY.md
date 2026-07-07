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
ipars token revoke --control-plane-url https://203.0.113.10:8443 --cluster-id <cluster-id> --nonce <token-nonce>
```

Revocation blocks new joins. Existing data-plane sessions continue until policy, peer-map, route, or key changes are applied.

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
- Prefer file-backed join tokens through `--join-token-path` or Kubernetes Secrets over command-line token arguments.
- Keep agent state directories and files owner-only. The daemon rejects symlinked or group/world-accessible key state.
- Enable relay admission Bearer tokens for public relays.
- Scope ACLs and route allowlists by role, tag, route, and protocol. Deny rules take precedence.
- Treat Docker API socket mounts as discovery-only and opt-in; the base Compose agent does not mount the Docker socket.
