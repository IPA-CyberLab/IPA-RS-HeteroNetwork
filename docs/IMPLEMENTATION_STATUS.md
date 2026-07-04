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
- Token ledger records, control-plane revocation API, revocation state, and max-use enforcement for in-memory and SQL stores.
- Control-plane join service that validates signed join tokens, issuer keys, cluster/time constraints, ledger admission, and node registration.
- Control-plane HTTP crate with typed health, join, peer-map, and JSON/Prometheus metrics routes backed by the join service.
- `iparsd control-plane` daemon that serves the control-plane HTTP router with in-memory, SQLite, or PostgreSQL storage.
- Signal registry, typed signal HTTP routes, and `iparsd signal` for endpoint candidate exchange, relay candidate lookup, path negotiation, and hole-punch planning.
- RFC 5389 STUN Binding request/success response handling with `XOR-MAPPED-ADDRESS` decoding, multi-server NAT mapping classification, and `iparsd stun` daemon support for public endpoint detection.
- Relay admission/status HTTP API, Prometheus relay metrics, expiring credentialed opaque UDP forwarding loop with per-session rate limits, and `iparsd relay`.
- CLI `join <token>` creates node identity/WireGuard keys, builds `JoinNodeRequest`, and posts to the token's control-plane bootstrap endpoint; `token revoke` posts typed token revocation requests to the control plane.
- Persistent agent node state, STUN candidate collection, NAT classification status, agent status/STUN/NAT HTTP routes, and `iparsd agent`.
- `iparsd agent --join-token` startup registration that uses persisted agent identity/WireGuard keys, current candidates, and token bootstrap control-plane discovery.
- `iparsd agent` heartbeat reporting that posts current node health, candidates, and negotiated path-state data to `/v1/heartbeat` when a control-plane endpoint is known, retrying without stopping the agent.
- `iparsd agent` signal-service node registration that upserts the registered `NodeRecord` with refreshed endpoint candidates when a signal endpoint is known.
- `iparsd agent` signal path negotiation loop that fetches peer maps, calls `/v1/paths/negotiate` for each peer, stores pair-scoped `PathRecord`s, and includes them in heartbeat reports.
- `iparsd agent` relay admission for `RELAY` paths selected by signal negotiation, using relay-advertised admission URLs and keeping expiring relay credentials in transient agent runtime state.
- Agent relay session renewal-window handling and stale credential removal when path negotiation returns to non-relay states.
- Agent relay dataplane forwarder that proxies local WireGuard UDP packets through credentialed relay frames and preserves opaque WireGuard payloads.
- Agent peer-map application can bind active relay-selected peers to daemon-supervised per-peer local relay forwarder endpoints when applying kernel WireGuard peer settings; relay forwarders support namespace placement checks, capacity limits, dead-task reaping, stale endpoint removal, and restart backoff.
- Agent HTTP JSON/Prometheus metrics export and bounded structured path-change event export.
- UDP hole-punch executor and `iparsd agent` integration that fetches signal hole-punch plans for `DIRECT_NAT_TRAVERSAL` paths and sends coordinated UDP punch datagrams.
- `iparsd agent` Kubernetes underlay route application for Service/API CIDRs, with Helm DaemonSet wiring for node-name discovery and explicit route-provider configuration.
- `iparsd agent` Docker container CIDR route application from explicit namespace/interface/CIDR intents, with Docker Compose wiring for rootful bridge deployments.
- Control-plane heartbeat handling persists node health, refreshed endpoint candidates, and pair-scoped path state in memory, SQLite, and PostgreSQL stores.
- Linux WireGuard command backend for interface creation and peer upsert/removal through explicit `ip`/`wg` commands, with optional validated `ip netns exec` execution.
- Linux route-manager command backend for route replacement/removal and policy-rule add/delete through explicit `ip` commands, with optional validated `ip netns exec` execution.
- Gated Linux network namespace integration smoke test for applying and removing routes through the namespaced route backend.
- Agent peer-map applier that turns `PeerMap` records into WireGuard peer configs, endpoint choices, peer host routes, and advertised route plans.
- `iparsd agent --apply-peer-map` continuous peer-map polling that fetches the control-plane peer map, applies it through Linux WireGuard/route backends when explicitly enabled, supports `--linux-netns` namespace placement, and retries without stopping the agent when the control plane is temporarily unavailable.
- Lazy connect and pinning primitives in the agent crate.
- Relay session table that forwards only expiring credentialed opaque payload frames and enforces per-session throughput windows.
- Docker Compose and Helm chart starting points.
- `ipars-load` executable scale/load harness for 3-node, 10-node, and 1000-node in-memory control-plane/signal scenarios, loopback HTTP endpoint transport for control-plane join/peer-map and signal upsert/negotiate paths, and relay HTTP admission plus UDP forwarding throughput runs.

## Remaining For Full Production Completion

- Runtime backend selection and hardening for production deployments.
- Kernel WireGuard netlink/wgctrl backend.
- Linux policy routing netlink backend and namespace lifecycle/capability hardening.
- NAT filtering classification, extended STUN behaviours beyond Binding/XOR-MAPPED-ADDRESS, and topology validation.
- Network-namespace validation of signal-coordinated UDP hole punching across reproducible NAT topologies.
- Per-forwarder dataplane metrics and crash-loop policy tuning beyond current dead-task reaping.
- OpenTelemetry exporters plus deeper relay dataplane metrics coverage.
- Docker API/namespace discovery, rootless backend support, and multi-network Compose hardening.
- Kubernetes API discovery/RBAC-backed route discovery and service/API exposure hardening.
- Direct path, NAT traversal, relay fallback, Docker Compose, and Kubernetes integration tests.
- External multi-process daemon load orchestration across separate control-plane, signal, relay, and agent processes beyond the loopback in-process HTTP/UDP harness.
