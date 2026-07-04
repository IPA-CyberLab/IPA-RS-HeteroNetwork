# Implementation Status

This file tracks the gap between the requested final system and the current repository state.

## Implemented In This Baseline

- Rust workspace with dedicated crates for types, crypto, control plane, signal, relay, STUN, agent, route manager, and CLI.
- Typed models for node, peer/path state, relay capability, token, policy, ACL, route, and health.
- Ed25519 signed join token creation and verification.
- X25519/WireGuard key generation primitive.
- Pair-scoped path scoring with direct/IPv6/NAT traversal/relay/unreachable states.
- In-memory control-plane registration and VPN IP allocation.
- SQLite and PostgreSQL control-plane store implementations with SQLite round-trip tests.
- Token ledger records, revocation state, and max-use enforcement for in-memory and SQL stores.
- Control-plane join service that validates signed join tokens, issuer keys, cluster/time constraints, ledger admission, and node registration.
- Control-plane HTTP crate with typed health, join, and peer-map routes backed by the join service.
- `iparsd control-plane` daemon that serves the control-plane HTTP router with in-memory, SQLite, or PostgreSQL storage.
- Signal registry, typed signal HTTP routes, and `iparsd signal` for endpoint candidate exchange, relay candidate lookup, path negotiation, and hole-punch planning.
- Lazy connect and pinning primitives in the agent crate.
- Relay session table that forwards only opaque payload frames.
- Docker Compose and Helm chart starting points.

## Remaining For Full Production Completion

- Long-running daemon binaries for control-plane, signal, STUN, relay, and agent.
- Long-running daemon binaries for relay, STUN, and agent.
- Kernel WireGuard netlink/wgctrl backend.
- Linux policy routing backend with netlink calls.
- Full STUN protocol support and NAT classification.
- Signal-coordinated UDP hole punching runtime.
- Relay abuse prevention with authenticated sessions and rate limits.
- Metrics export and structured path-change events.
- Docker namespace integration implementation.
- Kubernetes route discovery and service/API exposure implementation.
- Network namespace, Docker Compose, and Kubernetes integration tests.
- Scale/load test harness for 3-node, 10-node, and 1000-node scenarios.
