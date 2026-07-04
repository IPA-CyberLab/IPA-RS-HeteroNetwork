# IPA-RS-HeteroNetwork Architecture

## Goal

Build a production-oriented Rust P2P VPN / overlay network where one or more globally reachable nodes provide bootstrap, control-plane, signal, STUN, and relay capability. Nodes behind NAT join with signed tokens. Data traffic uses direct peer paths whenever possible and falls back to relay only when direct public, IPv6, or NAT-traversed UDP paths are unavailable.

The data plane must continue after the control plane is unavailable. New joins, peer-map updates, policy changes, and route changes may depend on the control plane.

## Required Components

- `control-plane`: registration, token validation, VPN IP allocation, peer map, relay map, ACL, route, policy, health, and path-state management.
- `signal`: endpoint candidate exchange, UDP hole-punch coordination, and path negotiation.
- `agent`: identity/WireGuard key management, STUN probing, candidate collection, lazy connect, peer-map application, peer probing, WireGuard endpoint updates, route management, and health reports.
- `relay`: UDP relay that forwards opaque E2E-encrypted packets and cannot decrypt payload.
- `stun`: public endpoint detection for NAT traversal.
- `route-manager`: Linux routing, policy routing, Docker integration, and Kubernetes node-underlay integration.
- `cli`: entry point for cluster init, joins, status, path/relay inspection, and Docker/Kubernetes install output.

## Trust And Identity

Each node has two key families:

- Identity key: Ed25519 signing key used for node identity, token issuing, and control-plane authentication.
- WireGuard keypair: X25519 key material used by kernel WireGuard for data-plane encryption.

The node ID is derived from the identity verifying key. WireGuard keys can rotate independently from identity keys. Join tokens contain:

- cluster ID
- bootstrap endpoints
- expiration and not-before time
- role and tags
- token policy
- issuer node ID and key ID
- Ed25519 signature over typed claims

## Control Plane HA

The control plane is designed for multiple public nodes. Durable state lives in PostgreSQL in production and SQLite in tests/dev. Ephemeral session state is separated from durable cluster state:

- Durable: node records, VPN IP leases, identity public keys, WireGuard public keys, policy, ACL, routes, relay policy, token revocation, and latest accepted path state.
- Ephemeral: active signal sessions, transient endpoint candidates, probe windows, relay session counters, and short-lived health samples.

Control-plane nodes use the same durable store and advertise themselves through the bootstrap endpoint list. Relay/STUN/signal instances are separately discoverable and can be added or drained without invalidating existing WireGuard peers.

## VPN IP Allocation

The default pool is `100.64.0.0/10`. IP allocation is explicit and stored as durable lease state. Reclaiming a lease requires node removal, token/policy revocation, or administrative reassignment. Agents do not self-assign overlay IPs.

## Peer And Path Model

Path state is tracked per node pair, not per node. A node can be directly reachable from one peer, relay-only from another, and unreachable from a third.

Path states:

- `DIRECT_PUBLIC`
- `DIRECT_IPV6`
- `DIRECT_NAT_TRAVERSAL`
- `RELAY`
- `UNREACHABLE`

Path selection scores candidates using:

- latency
- loss
- jitter
- relay load
- policy permission
- route/relay cost
- stability

Direct paths are preferred when allowed and healthy. Relay paths remain encrypted end to end and are demoted automatically when direct paths recover. Important peers, Kubernetes control-plane nodes, relays, and route providers can be pinned so lazy connection cleanup does not tear them down.

## Lazy Connect

Agents do not establish a full mesh. They keep a compact peer map and only negotiate a path when:

- traffic for a peer or advertised route appears
- a pinned peer requires a standing path
- Kubernetes/API/service exposure needs an underlay path
- an operator runs an explicit path probe

Idle paths close after a configurable timeout unless pinned by role, tag, route ownership, or explicit policy.

## NAT Traversal

The default path discovery order is:

1. IPv6 direct candidate, if policy allows and both nodes have usable IPv6.
2. Public UDP endpoint candidate.
3. STUN reflexive endpoint with signal-coordinated UDP hole punching.
4. Relay fallback.
5. `UNREACHABLE`.

The signal service only coordinates endpoint candidate exchange and timing. It does not forward data-plane payload.

## Relay Design

Public nodes are relay candidates only when policy, health, and capacity permit it. Relay admission checks include:

- explicit relay permission in policy
- public UDP endpoint availability
- advertised capacity
- current session/load limits
- abuse/rate-limit status
- health status

Relay traffic is opaque WireGuard-encrypted UDP payload. Relays route by session metadata and never receive keys that can decrypt tenant payload.

## Docker Support

Docker support targets:

- container-to-container overlay reachability
- host-to-container reachability
- container-to-remote-node reachability

The route manager works from explicit network namespace, capability, and routing intents. The design avoids treating iptables-only rewrites as the primary integration mechanism. Rootful deployments use `NET_ADMIN` and `/dev/net/tun`. Rootless deployments require a userspace WireGuard backend once implemented.

The Compose bundle runs PostgreSQL, control plane, signal, relay, STUN, and an agent.

## Kubernetes Support

This project implements Kubernetes node underlay VPN support and does not claim to be a CNI. The Helm chart installs:

- DaemonSet agent on each node
- RBAC for node/service route discovery
- optional Service/API Server exposure helpers
- routing-peer configuration for node-to-node and node-to-service overlay routes

CNI-owned pod networking remains the responsibility of the cluster CNI.

## API Schema

The shared `ipars-types` crate defines typed request and response models for:

- node registration
- join registration with signed token claims
- heartbeat/health reporting
- peer map and relay map retrieval
- route publication
- signal path negotiation
- relay admission and status

The wire protocol can be exposed as gRPC or HTTP. The schema is Rust-first and serializes cleanly to JSON for CLI diagnostics and tests.

Initial control-plane HTTP routes:

- `GET /healthz`
- `POST /v1/join`
- `POST /v1/heartbeat`
- `GET /v1/peers/{node_id}`

Initial signal HTTP routes:

- `GET /healthz`
- `PUT /v1/nodes/{node_id}`
- `POST /v1/paths/negotiate`
- `GET /v1/hole-punch/{source}/{target}`

Initial relay HTTP routes:

- `GET /healthz`
- `GET /v1/status`
- `POST /v1/sessions`

Initial agent HTTP routes:

- `GET /healthz`
- `GET /v1/status`
- `POST /v1/stun-probe`

## Observability

All daemons emit:

- structured logs
- counters/gauges/histograms suitable for metrics export
- path-change events
- relay admission/refusal events
- token validation/revocation events

Critical events include path promotion/demotion, relay fallback, relay abuse refusal, VPN IP allocation, route publication, and policy denial.

## Security Model

- Join tokens are signed, scoped, expiring, and revocable by key ID/nonce.
- Identity keys authenticate nodes to the control plane.
- WireGuard keys provide data-plane confidentiality.
- Relays cannot decrypt payload.
- Public nodes are not automatically relays; policy, health, and capacity are required.
- ACLs are evaluated by tag, role, route, protocol, and relay permission.
- Key rotation supports identity and WireGuard key families separately.

## Failure Behavior

- Control plane down: existing WireGuard data-plane paths remain active until idle timers or kernel state changes remove them.
- Signal down: existing paths remain active; new NAT traversal and path renegotiation wait for signal recovery.
- Relay down: affected pairs demote to probing/direct candidates or another relay if available; otherwise `UNREACHABLE`.
- STUN down: known candidates remain usable; new NAT classification is degraded.
- Agent restart: identity and WireGuard keys are read from disk; the agent can re-register with a join token, refresh signal-service node state, report heartbeat state, then pinned routes and current peer map are rehydrated through explicit backend application and refreshed by continuous peer-map polling.

## Integration Tests

Required integration scenarios:

- 3-node topology: one public bootstrap/control/relay node and two NAT nodes.
- 10-node topology: mixed public, NAT, Docker, and route-provider nodes.
- NAT matrix: full cone, restricted cone, port-restricted, symmetric, and double NAT where reproducible with network namespaces.
- Relay fallback: forced direct-path failure and automatic direct promotion after recovery.
- Docker Compose: host/container/remote reachability.
- Kubernetes: DaemonSet agent route publication and node-underlay reachability.

## Scale Plan

### 3 Nodes

Target: direct path setup below 1 second on LAN-like RTT and relay fallback below 2 seconds. A single control-plane instance is acceptable for dev.

### 10 Nodes

Target: lazy connections only for active flows/pins. Peer-map updates are delta-based. Relay admission uses explicit capacity and health.

### 1000 Nodes

Target: no full mesh. Agents subscribe to relevant peer/route deltas by tag, role, and route interest. Control-plane state is partitionable by cluster ID and node ID. Relay maps are ranked by region/cost/load. Load tests must measure registration rate, peer-map fanout, signal negotiation concurrency, relay throughput, and path-state churn.

## Implementation Roadmap

1. Shared typed models, CLI surface, and signed-token primitives.
2. Control-plane store trait plus in-memory, SQLite, and PostgreSQL backends.
3. Long-running control-plane, signal, STUN, relay, and agent daemons.
4. Kernel WireGuard backend: initial Linux `ip`/`wg` command runner exists; add netlink/wgctrl-equivalent calls for production control.
5. Route manager for Linux policy routing, Docker namespaces, and Kubernetes node underlay: initial `ip route`/`ip rule` command backend exists; add netlink and namespace execution hardening.
6. NAT traversal integration tests with network namespaces.
7. Relay abuse controls, metrics, and production hardening.
