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
- Control-plane join service that validates signed join tokens, issuer keys, cluster/time constraints, ledger admission, CIDR-containing route policy, relay-capability policy, and node registration.
- Control-plane HTTP crate with typed health, join, peer-map, and JSON/Prometheus metrics routes backed by the join service.
- `iparsd control-plane` daemon that serves the control-plane HTTP router with in-memory, SQLite, or PostgreSQL storage.
- Signal registry, typed signal HTTP routes, and `iparsd signal` for endpoint candidate exchange, relay candidate lookup, path negotiation, and hole-punch planning.
- RFC 5389 STUN Binding request/success response handling with `XOR-MAPPED-ADDRESS` decoding, RFC 5780 `CHANGE-REQUEST`/`RESPONSE-ORIGIN`/`OTHER-ADDRESS` support, multi-server NAT mapping/filtering classification, and `iparsd stun` daemon support for public endpoint detection.
- Relay admission/status HTTP API, Prometheus relay metrics, cumulative relay dataplane counters/drop reasons, expiring credentialed opaque UDP forwarding loop with per-session rate limits, and `iparsd relay`.
- CLI `init` and `token create` can sign join tokens with a reusable issuer private key and key ID, including relay permission, route allowlist, and max-use token policy flags; `join <token>` creates node identity/WireGuard keys, builds `JoinNodeRequest`, and posts to the token's control-plane bootstrap endpoint; `token revoke` posts typed token revocation requests to the control plane; `status`, `peers`, `routes`, `relay status`, and `path status` can query the agent, control-plane, and relay HTTP APIs when URLs are provided; `docker install` and `k8s install` emit typed operational install plans for Compose and Helm deployments.
- Persistent agent node state, STUN candidate collection, NAT classification status, agent status/path/STUN/NAT HTTP routes, and `iparsd agent`.
- `iparsd agent --join-token` and `--join-token-path` startup registration that uses persisted agent identity/WireGuard keys, current candidates, and token bootstrap control-plane discovery, with the Helm chart wiring the join token Secret into the file path form.
- `iparsd agent` heartbeat reporting that posts current node health, candidates, relay capability updates, optional relay status-derived capacity/session counts, and negotiated path-state data to `/v1/heartbeat` when a control-plane endpoint is known, retrying without stopping the agent.
- `iparsd agent` signal-service node registration that upserts the registered `NodeRecord` with refreshed endpoint candidates when a signal endpoint is known.
- `iparsd agent` signal path negotiation loop that fetches peer maps, calls `/v1/paths/negotiate` for each peer, stores pair-scoped `PathRecord`s, and includes them in heartbeat reports.
- Signal node registration and path negotiation carry optional NAT classification data, so signal selection avoids `DIRECT_NAT_TRAVERSAL` when either side has classified itself as relay-preferred or insufficient for hole punching.
- `iparsd agent` relay admission for `RELAY` paths selected by signal negotiation, using relay-advertised admission URLs and keeping expiring relay credentials in transient agent runtime state.
- `iparsd agent` relay capability advertisement for public nodes with explicit relay endpoint/admission URL settings, gated by join-token relay policy during control-plane registration.
- Agent relay session renewal-window handling and stale credential removal when path negotiation returns to non-relay states.
- Agent relay dataplane forwarder that proxies local WireGuard UDP packets through credentialed relay frames and preserves opaque WireGuard payloads.
- Agent peer-map application can bind active relay-selected peers to daemon-supervised per-peer local relay forwarder endpoints when applying kernel WireGuard peer settings; relay forwarders support namespace placement checks, capacity limits, dead-task reaping, stale endpoint removal, restart backoff, and configurable crash-loop cooldown policy.
- Agent HTTP JSON/Prometheus metrics export and bounded structured path-change event export.
- Agent relay forwarder per-peer dataplane metrics for outbound/inbound packets and opaque payload bytes, exported through JSON and Prometheus metrics.
- Shared `iparsd` observability bootstrap with formatted tracing output and optional OTLP HTTP/protobuf trace/log/metrics export to OpenTelemetry collectors, including relay capacity/dataplane and agent path/relay-forwarder metric recording.
- UDP hole-punch executor and `iparsd agent` integration that fetches signal hole-punch plans for `DIRECT_NAT_TRAVERSAL` paths and sends coordinated UDP punch datagrams.
- `iparsd agent` Kubernetes underlay route application for explicit Service/API CIDRs or RBAC-backed Kubernetes API Service discovery, with Helm DaemonSet wiring for node-name discovery, namespace/label filters, API server host-route discovery, explicit route-provider configuration, and optional agent/relay Service exposure templates.
- `iparsd agent` Docker container CIDR route application from explicit namespace/interface/CIDR intents or Docker Engine API bridge-network discovery, with network name/ID filters, rootless socket discovery, and Docker Compose wiring for rootful bridge deployments.
- Control-plane heartbeat handling persists node health, refreshed endpoint candidates, and pair-scoped path state in memory, SQLite, and PostgreSQL stores.
- Linux WireGuard command backend for interface creation and peer upsert/removal through explicit `ip`/`wg` commands, with optional validated `ip netns exec` execution.
- Selectable Linux kernel WireGuard netlink backend for peer-map application, using rtnetlink for interface creation/up state and WireGuard generic netlink for peer upsert/removal without invoking `wg`, in either the current namespace or validated `--linux-netns` placement.
- Linux route-manager command backend for route replacement/removal and policy-rule add/delete through explicit `ip` commands, with optional validated `ip netns exec` execution.
- Selectable Linux route-manager rtnetlink backend for peer-map, Docker, and Kubernetes route plans, including route replacement/removal and policy-rule add/delete without invoking `ip`, in either the current namespace or validated `--linux-netns` placement.
- Gated Linux network namespace integration smoke tests for applying and removing routes through the namespaced command and rtnetlink route backends.
- Gated Linux network namespace integration smoke test for creating a WireGuard interface and upserting/removing a peer through the kernel WireGuard netlink backend inside a target namespace.
- Gated Linux network namespace integration smoke test for signal-plan driven UDP hole-punch datagrams across direct-routed isolated namespaces.
- Agent peer-map applier that turns `PeerMap` records into WireGuard peer configs, endpoint choices, peer host routes, and advertised route plans.
- `iparsd agent --apply-peer-map` continuous peer-map polling that fetches the control-plane peer map, applies it through selectable `linux-command` or `dry-run` runtime backends when explicitly enabled, supports `--linux-netns` namespace placement for Linux command and kernel-netlink execution, and retries without stopping the agent when the control plane is temporarily unavailable.
- Linux command runtime preflight for `iparsd agent` that validates interface names, required `ip`/`wg` commands, `CAP_NET_ADMIN` when host networking will be mutated, and requested `/var/run/netns` namespace placement before starting data-plane application loops.
- `iparsd agent --runtime-backend dry-run` for peer-map, Docker route, and Kubernetes underlay loops using in-memory WireGuard state and dry-run route application without mutating host networking.
- Lazy connect and pinning primitives in the agent crate.
- Relay session table that forwards only expiring credentialed opaque payload frames and enforces per-session throughput windows.
- Docker Compose and Helm chart starting points aligned to the current plain-HTTP `iparsd` service listeners.
- `ipars-load` executable scale/load harness for 3-node, 10-node, and 1000-node in-memory control-plane/signal scenarios, loopback HTTP endpoint transport for control-plane join/peer-map and signal upsert/negotiate paths, relay HTTP admission plus UDP forwarding throughput runs, and spawned multi-process `iparsd` daemon transport across control-plane, signal, STUN, relay, and dry-run agent processes.

## Remaining For Full Production Completion

- Runtime backend hardening beyond current Linux command/kernel-netlink/dry-run selection and startup preflight.
- Privileged integration coverage beyond current namespace-aware route and WireGuard netlink smoke tests.
- Linux namespace lifecycle/capability hardening around command and netlink dataplane backends.
- NAT topology validation beyond current mapping/filtering probes and classification-aware signal selection across reproducible NAT behaviours.
- Network-namespace validation of signal-coordinated UDP hole punching across reproducible NAT topologies beyond the current direct-routed namespace smoke test.
- OpenTelemetry metrics coverage beyond current relay capacity/session, byte, packet, drop-reason counters, and agent path/relay-forwarder metrics.
- Full rootless Docker dataplane backend support and multi-network Compose integration hardening beyond current Docker API route discovery.
- Kubernetes service/API exposure hardening beyond current RBAC-backed Service route discovery.
- Direct path, NAT traversal, relay fallback, Docker Compose, and Kubernetes integration tests.
- External multi-process daemon load orchestration hardening beyond current loopback `iparsd` control-plane/signal/STUN/relay/dry-run-agent transport.
