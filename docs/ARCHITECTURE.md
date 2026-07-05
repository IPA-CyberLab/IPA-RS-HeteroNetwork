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
- `cli`: entry point for cluster init, joins, agent/control-plane status, peer/route queries, path/relay inspection, and typed Docker/Kubernetes install plans.

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

Operators can keep the issuer private key outside the control-plane process and pass only the issuer node ID, key ID, and public key to `iparsd control-plane`. Additional trusted issuer public keys can be supplied with repeated `--trusted-issuer-key issuer_node_id,key_id,public_key` values, or semicolon-separated `IPARS_TRUSTED_ISSUER_KEYS`, so key rotation can overlap old and next signing keys without stopping registration. `ipars init` can generate and persist the issuer private key with restrictive file permissions, emit the concrete `iparsd` commands for control-plane, signal, STUN, and relay bootstrap services, and optionally spawn those services with per-service logs. `ipars token create` can later sign additional join tokens with that same key or the next key ID after rotation. Both commands expose token-policy inputs for relay permission, route allowlists, and max-use or unlimited-use admission.

## Control Plane HA

The control plane is designed for multiple public nodes. Durable state lives in PostgreSQL in production and SQLite in tests/dev. Ephemeral session state is separated from durable cluster state:

- Durable: node records, VPN IP leases, identity public keys, WireGuard public keys, policy, ACL, routes, relay policy, token revocation, and latest accepted path state.
- Ephemeral: active signal sessions, transient endpoint candidates, probe windows, relay session counters, and short-lived health samples.

Control-plane nodes use the same durable store and advertise themselves through the bootstrap endpoint list. CLI and agent join registration try control-plane bootstrap endpoints in token order, so additional public control-plane nodes can take over initial registration when an earlier endpoint is unavailable. After registration, agents keep an ordered control-plane endpoint list for heartbeat reporting, peer-map polling, and signal path peer-map fetches, preferring the endpoint that accepted registration and falling back to the token bootstrap endpoints unless an operator pins `--control-plane-url`. Agents register their node/candidate state with every token signal bootstrap endpoint and fail over signal path negotiation plus hole-punch plan fetches across the ordered signal bootstrap list unless an operator pins `--signal-url`. Relay/STUN/signal instances are separately discoverable and can be added or drained without invalidating existing WireGuard peers.

## VPN IP Allocation

The default pool is `100.64.0.0/10`. IP allocation is explicit and stored as durable lease state. Reclaiming a lease requires node removal, token/policy revocation, or administrative reassignment. Agents do not self-assign overlay IPs. On registration, the control plane reads existing node leases from the store and skips already assigned VPN IPs before allocating the next address; SQL stores also maintain a VPN IP uniqueness index as a last-resort guard for restarted or overlapping control-plane processes.

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

## ACL And Peer Visibility

Control-plane peer maps and relay maps are filtered through cluster ACL rules when rules are configured. An empty ACL list preserves the default allow-all peer visibility. When ACL rules exist, deny matches take precedence over allow matches, and unmatched peers/routes are hidden. Rules match source role/tag, target role/tag, protocol, and advertised route CIDR containment; route-specific rules can expose only the allowed subset of a node's advertised routes.

Operators can load these rules into `iparsd control-plane` with repeated `--acl-rule '<json>'` arguments, or a semicolon-separated `IPARS_ACL_RULES` value. The JSON is the typed `AclRule` schema, so daemon configuration, control-plane policy, and API behavior all share the same role/tag/route/protocol/action model. `GET /v1/policy` returns the active cluster policy, VPN pool, and loaded ACL rules for audit and status tooling.

## Lazy Connect

Agents do not establish a full mesh. They keep a compact peer map and only negotiate a path when:

- traffic for a peer or advertised route appears
- a pinned peer requires a standing path
- Kubernetes/API/service exposure needs an underlay path
- an operator runs an explicit path probe

The agent runtime records peer activity through typed peer-activity and packet-flow APIs so packet detectors, probes, or operators can mark a peer active and optionally pin it. `POST /v1/path-probe`, exposed through `ipars path probe`, records operator or probe results as a pair-scoped `PathRecord` with the selected path state, selected candidate, relay node, recalculated `PathScore` from measured latency/loss/jitter/relay load/stability plus policy/cost, and optional path pin. Packet-flow observations resolve the destination IP against the latest peer VPN IPs and advertised routes, using peer VPN IP matches before longest-prefix route matches, and can carry optional source IP, protocol, source/destination ports, detector metadata, conntrack status flags, and TCP state for audit/debug output. The agent classifies observation metadata into inferred conntrack lifecycle buckets such as opening, unreplied, assured, established, closing, and closed, and exports those counts through JSON, Prometheus, and OTLP metrics. The daemon can poll Linux conntrack procfs tables with `--packet-flow-detector proc-net-conntrack`, dump the conntrack table through `NETLINK_NETFILTER` with `--packet-flow-detector conntrack-netlink`, or subscribe to conntrack NEW/UPDATE multicast events with `--packet-flow-detector conntrack-netlink-events`, then feed observed destination addresses plus conntrack tuple metadata into the same resolver after dropping unspecified, loopback, multicast, broadcast, and link-local destinations. Conntrack detector loops suppress duplicate flow observations for the configured `--packet-flow-dedup-ttl-seconds` window so repeated table polling does not inflate activity or metrics, but conntrack status or TCP state transitions are distinct fingerprints and remain visible. Signal path negotiation and peer-map application operate only on active peers, policy-pinned peers, relay-capable peers, and route providers. Idle unpinned peers close after a configurable timeout and are removed from WireGuard and relay-forwarder runtime state; pinned peers stay connected by role, tag, route ownership, relay capability, path pinning, or explicit activity pinning.

## NAT Traversal

The default path discovery order is:

1. IPv6 direct candidate, if policy allows and both nodes have usable IPv6.
2. Public UDP endpoint candidate.
3. STUN reflexive endpoint with signal-coordinated UDP hole punching.
4. Relay fallback.
5. `UNREACHABLE`.

STUN reflexive endpoint detection uses RFC 5389 Binding requests and success responses with `XOR-MAPPED-ADDRESS`. Agents can reuse one UDP socket across multiple STUN endpoints to classify NAT mapping behavior as no NAT, endpoint-independent, address-dependent, address-and-port-dependent, or unknown. STUN probes also understand RFC 5780 `CHANGE-REQUEST`, `RESPONSE-ORIGIN`, and `OTHER-ADDRESS` attributes so compatible STUN deployments can classify NAT filtering behavior as endpoint-independent, address-dependent, address-and-port-dependent, or unknown. Reproducible topology validation across network namespaces builds on these probes, including gated two-sided endpoint-independent SNAT topologies for signal-coordinated UDP punching with IP-only, fixed public-port, and mixed port-preserving/fixed-port mappings, plus an address/port-dependent non-traversal case where peer-destination SNAT ports differ from the advertised STUN reflexive endpoints.

Agents include their latest NAT classification when registering with signal and when requesting path negotiation. Registration is sent to all configured signal endpoints, while path negotiation uses ordered failover and fetches hole-punch plans from the signal endpoint that accepted the negotiation. The signal service uses that classification to avoid coordinated hole punching when either side reports relay-preferred or insufficient NAT data, falling back to relay candidates when policy and capacity allow. The signal service only coordinates endpoint candidate exchange and timing. It does not forward data-plane payload.

## Relay Design

Public nodes are relay candidates only when policy, health, and capacity permit it. The control plane includes a node in relay maps and relay-candidate metrics only after it has a healthy heartbeat newer than `relay_health_ttl_seconds` in the active cluster policy, and the signal registry applies the same fresh-healthy gate before offering relay candidates during path negotiation. `iparsd control-plane --relay-health-ttl-seconds` controls the control-plane window, while `iparsd signal --relay-health-ttl-seconds` controls the signal negotiation window. Relay admission checks include:

- explicit relay permission in policy
- public UDP endpoint availability
- advertised capacity
- current session/load limits
- abuse/rate-limit status
- health status

Relay traffic is opaque WireGuard-encrypted UDP payload. Relays route by an outer relay frame containing session metadata and an expiring bearer credential, enforce per-session throughput windows, strip the relay frame before forwarding, and never receive keys that can decrypt tenant payload.

Relay candidates advertise both a public UDP relay endpoint and an HTTP admission URL. When signal negotiation selects `RELAY`, the agent ranks admissible relay candidates by load and capacity, attempts admission in that order, fails over to the next candidate when an admission endpoint is unavailable or rejects the session, and keeps the returned credential in transient runtime state rather than reporting it back through control-plane heartbeat.

An agent only advertises a local relay service to the control plane when it is started with an explicit relay public endpoint and relay admission URL. The control plane still marks that relay capability enabled only when the join token policy allows relay, so public UDP reachability alone does not make a node a relay candidate.

Agent heartbeats can refresh relay capability and capacity fields, including active session counts from an optional relay status URL, but the control plane re-checks the node's stored token policy before accepting those updates and rewrites `enabled_by_policy` itself.

The agent-side relay dataplane forwarder wraps outbound opaque WireGuard packets in the relay frame and sends them to the selected relay UDP endpoint. Its UDP loop forwards packets from the local WireGuard socket to the relay and sends stripped inbound relay payloads back toward the local WireGuard endpoint.

Agents renew relay sessions before expiry and remove relay credentials when path negotiation selects a direct or unreachable non-relay state. This keeps relay bearer credentials short-lived without forcing admission churn on every negotiation tick.

When the agent is started with relay forwarder binding enabled, the daemon supervises per-peer local UDP forwarders for active relay sessions. Peer-map application consults negotiated path state, transient relay sessions, and the runtime forwarder endpoint table before configuring kernel WireGuard peers. Relay-selected peers with active credentials use their local forwarder endpoint as the WireGuard endpoint, allowing the forwarder to wrap opaque WireGuard packets before they leave for the public relay.

Relay forwarders default to the agent's `--linux-netns` placement when one is configured, or can be pinned with `--relay-forwarder-netns`. Because the workspace forbids unsafe code, the daemon validates that the process is already running in the requested Linux network namespace before binding the UDP socket instead of calling `setns` internally. Supervisors enforce a maximum number of per-peer forwarders, reap dead forwarder tasks, remove stale runtime endpoints, apply restart backoff after bind/start/runtime failures, and place repeatedly failing peers into a configurable crash-loop cooldown window.

## Docker Support

Docker support targets:

- container-to-container overlay reachability
- host-to-container reachability
- container-to-remote-node reachability

The route manager works from explicit network namespace, capability, and routing intents. The design avoids treating iptables-only rewrites as the primary integration mechanism. Rootful deployments use `NET_ADMIN` and `/dev/net/tun`; `iparsd agent --linux-netns` runs the Linux WireGuard and route command backends through validated `ip netns exec` placement. Peer-map application can instead use `--wireguard-backend kernel-netlink` to create the WireGuard link through rtnetlink and upsert/remove peers through WireGuard generic netlink without shelling out to `wg`, in either the current namespace or the requested `--linux-netns` namespace. Route/rule application can use `--route-backend kernel-netlink` to replace `ip route`/`ip rule` execution with rtnetlink for peer-map, Docker, and Kubernetes route plans in either namespace placement. Docker route application can be driven by explicit container namespace, host interface, and container CIDR inputs from Compose or agent flags, or by `iparsd agent --docker-discover-networks`, which queries Docker Engine bridge networks and derives IPAM subnets dynamically. When Docker host route exposure is enabled, the agent requests those container CIDRs during join so peer maps can carry Docker reachability subject to the signed token route allowlist. Discovery validates Docker API version, network filter syntax, discovered bridge-network names before using them in route intent namespace labels, and positive route intervals, rejects ambiguous use with explicit container CIDRs, requires discovery for `--docker-network` name/ID filters, and resolves Docker sockets from explicit `--docker-api-socket`, `DOCKER_HOST=unix://...`, `/var/run/docker.sock`, or rootless `$XDG_RUNTIME_DIR/docker.sock`; non-Unix `DOCKER_HOST` values are rejected so remote or TCP daemon settings cannot be accidentally ignored in favor of a local rootful socket. Rootless deployments still require a userspace WireGuard backend before host dataplane mutation can be fully rootless.

The Compose bundle runs PostgreSQL, control plane, signal, relay, STUN, and an agent. `ipars docker install` emits a JSON plan with the Compose manifest path, shell-quoted validation/apply commands, Docker route environment overrides for rootless socket discovery and multi-network filters, validated Linux interface/namespace names, host capability requirements, and private-network HTTP exposure notes. `ipars k8s install` emits matching shell-safe Helm commands and values for Service/API route discovery, namespace and selector filters, route-provider settings, join-token Secret wiring, and optional agent/relay Service exposure controls with Service type, port, source-range, and external traffic policy validation.

## Runtime Backends

The agent data-plane applier has an explicit runtime backend selector. `linux-command` is the default and applies peer maps, Docker route intents, and Kubernetes underlay intents through host `ip`/`wg` commands, optionally wrapped with validated `ip netns exec` placement. Within that runtime, `--wireguard-backend kernel-netlink` replaces `wg`/WireGuard link command execution for peer-map application with rtnetlink and WireGuard generic netlink calls in the current or requested Linux network namespace, and `--route-backend kernel-netlink` replaces route and policy-rule command execution with rtnetlink for peer-map, Docker, and Kubernetes route plans in the same placement model. Before host mutation starts, the daemon always validates static runtime configuration, including Linux interface names, requested namespace names, daemon poll/route/renew intervals, and relay-forwarder capacity, then validates required runtime commands, `NETLINK_ROUTE`, `NETLINK_GENERIC`, and `NETLINK_NETFILTER` socket readiness for selected kernel-netlink and conntrack detectors, `CAP_NET_ADMIN` when kernel networking is changed or conntrack netlink is used, `CAP_NET_RAW` when WireGuard peer-map dataplane application is enabled, `CAP_SYS_ADMIN` when Linux namespace placement is requested, and the requested `/var/run/netns` namespace entry. Namespace preflight rejects missing entries, symlinks, directories, and non-`nsfs` regular files, and warns when the entry resolves to the current process namespace. Operators can explicitly bypass the host command/netlink/capability/path preflight with `--skip-runtime-preflight` for constrained bootstrap flows, while static configuration validation remains active. `dry-run` keeps the same peer-map polling, relay-aware endpoint resolution, Docker route planning, and Kubernetes underlay route planning loops active while using in-memory WireGuard state and dry-run route application; conntrack netlink packet-flow detectors still participate in runtime preflight because they read kernel conntrack state even when route and WireGuard mutation are dry-run. This lets operators validate control-plane, signal, route, and relay decisions on hosts that should not yet mutate kernel networking state.

## Kubernetes Support

This project implements Kubernetes node underlay VPN support and does not claim to be a CNI. The Helm chart installs:

- DaemonSet agent on each node
- RBAC for node/service route discovery
- optional Service/API Server exposure helpers
- routing-peer configuration for node-to-node and node-to-service overlay routes

When Kubernetes underlay routing is enabled, the DaemonSet starts `iparsd agent` with the node name from the Downward API, a mounted join token Secret passed through `--join-token-path`, and either explicit Service/API CIDRs or RBAC-backed Kubernetes API discovery. The agent follows Kubernetes Secret symlinks but requires the token path to resolve to a regular file and rejects inline or file-backed token input larger than 64 KiB before parsing. With `--kubernetes-discover-services`, the agent uses its ServiceAccount token, validated namespace filters, and a bounded non-control-character Service label selector to list Services and derive cluster-IP host routes; namespace and selector inputs are not accepted without discovery. It can also derive the in-cluster API server host route from `KUBERNETES_SERVICE_HOST`. The resolved Service/API routes are requested during join and gated by the signed token route allowlist so peer maps can advertise the routing peer. The Helm chart only renders namespace and selector arguments when API discovery is enabled and fails template rendering for invalid route intervals, invalid namespace DNS labels, oversized selectors, and selector control characters. The agent periodically applies the resolved routes through the Linux route backend, optionally through `ip netns exec`, using either an explicit route-provider node ID or the local node identity.

Helm can optionally pass relay advertisement settings to the agent for public nodes that run a colocated relay service. Those settings remain inactive unless `agent.relayAdvertisement.enabled` is set and the join token policy permits relay. When relay advertisement is enabled, the chart and agent startup validation require the public UDP endpoint, absolute HTTP(S) relay admission/status URLs with hosts, and positive capacity values before rendering or advertising capability.

The chart can also render optional Services for the agent HTTP API and colocated relay UDP/HTTP endpoints. These are disabled by default so private underlay deployments do not publish node APIs unless an operator explicitly selects a Service type and annotations. The chart and install plan accept only `ClusterIP`, `NodePort`, and `LoadBalancer` Service types and only `Local` or `Cluster` external traffic policies. NodePort and LoadBalancer Service types additionally require an exposure acknowledgement value in the chart; `ipars k8s install` only sets that acknowledgement when `--allow-public-service-exposure` is supplied. Explicit NodePort values are accepted for the agent API and relay UDP/HTTP ports, must be in the Kubernetes default 30000-32767 range, require a NodePort or LoadBalancer Service type, and must not reuse the same relay NodePort for UDP and HTTP. LoadBalancer Services require source ranges for agent and relay exposure unless the operator also sets the explicit unrestricted LoadBalancer acknowledgement, and optional LoadBalancer class values must be Kubernetes qualified names and only apply to LoadBalancer Services. External Services default to `externalTrafficPolicy=Local`; selecting `Cluster` requires an additional acknowledgement because cross-node forwarding can obscure source addresses used for audit and allowlist enforcement. The install plan validates Helm release, namespace, join-token Secret name, and Secret key values before emitting namespace creation, join-token Secret wiring, Helm upgrade/install flags, Service/API route discovery values, optional Service exposure toggles, and Service type/NodePort/LoadBalancer-class/source-range/traffic-policy/annotation overrides, with CLI annotation keys validated as Kubernetes qualified names and values constrained to generated Helm-safe strings. The chart also validates join-token Secret name/key values, agent WireGuard interface names, Service annotation keys, required control/signal URLs, optional STUN/relay host:port endpoints, LoadBalancer classes, and relay-advertised public endpoints at render time for direct values usage. Relay exposure in that plan requires the public UDP endpoint and HTTP admission URL that should be advertised to peers.

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
- `GET /metrics`
- `POST /v1/join`
- `POST /v1/heartbeat`
- `GET /v1/metrics`
- `GET /v1/peers/{node_id}`
- `POST /v1/tokens/revoke`

Initial signal HTTP routes:

- `GET /healthz`
- `GET /metrics`
- `GET /v1/metrics`
- `PUT /v1/nodes/{node_id}`
- `POST /v1/paths/negotiate`
- `GET /v1/hole-punch/{source}/{target}`

Initial relay HTTP routes:

- `GET /healthz`
- `GET /metrics`
- `GET /v1/status`
- `POST /v1/sessions`

Initial agent HTTP routes:

- `GET /healthz`
- `GET /metrics`
- `GET /v1/status`
- `GET /v1/metrics`
- `GET /v1/paths`
- `GET /v1/path-events`
- `POST /v1/path-probe`
- `POST /v1/stun-probe`
- `POST /v1/nat-classification`
- `POST /v1/peer-activity`
- `POST /v1/packet-flow`

## Observability

All daemons emit:

- structured logs
- counters/gauges/histograms suitable for metrics export
- path-change events
- relay admission/refusal events
- token validation/revocation events

Critical events include path promotion/demotion, relay fallback, relay abuse refusal, VPN IP allocation, route publication, and policy denial.

The control plane exposes JSON and Prometheus metrics for registered nodes, relay-capable nodes, last reported health, and pair-scoped path state counts. Signal exposes JSON and Prometheus metrics for registered nodes, relay candidates, NAT classifications, health freshness, node upsert counts, path negotiation counts, and hole-punch plan counts. Agents expose typed JSON metrics, Prometheus scrape metrics, and a bounded structured path-change event buffer. The metrics include candidate, path, relay session, relay admission attempt/success/failure counters, relay forwarder, lazy-connect active/pinned/index gauges, path-probe, peer-activity and packet-flow counters, packet-flow lifecycle classification counters, filtered destination reason counters, per-forwarder outbound/inbound packet and opaque payload byte counters, and per-path-state counts. Relays expose Prometheus scrape metrics for capacity, active sessions, policy-enabled and e2e-only state, health, forwarded opaque payload bytes, UDP datagram counters, byte counters, and drop reasons. Path events record the previous and new path state, relay node, selected candidate, and score for create/change transitions.

Every `iparsd` subcommand shares root observability options. When `--otel-enabled` or `IPARS_OTEL_ENABLED=true` is set, `iparsd` configures OTLP HTTP/protobuf exporters for traces, tracing-backed logs, and metrics. `--otel-endpoint`/`IPARS_OTEL_ENDPOINT` accepts the collector base URL, with `/v1/traces`, `/v1/logs`, and `/v1/metrics` selected per signal. `--otel-service-name`/`IPARS_OTEL_SERVICE_NAME` overrides the default `iparsd-<component>` service name, and `--log-filter`/`IPARS_LOG_FILTER` controls both local formatted tracing output and exported telemetry. The control-plane daemon records node, relay-candidate, health, path, and per-path-state gauges into `ipars.control_plane.*` OTLP metrics. The signal daemon records node, relay-candidate, NAT-classification, health-total, health-state, stale-health, and request counter metrics into `ipars.signal.*` OTLP metrics. The relay daemon records active/capacity/e2e-only gauges and dataplane counter deltas into `ipars.relay.*` OTLP metrics; the agent records candidate/path/relay-session gauges, per-path-state gauges, relay-admission counter deltas, lazy-connect active/pinned/index gauges, path-probe, peer-activity, packet-flow, packet-flow lifecycle classification, filtered destination reason, and relay-forwarder counter deltas into `ipars.agent.*` OTLP metrics. `--otel-metrics-poll-interval-seconds`/`IPARS_OTEL_METRICS_POLL_INTERVAL_SECONDS` controls control-plane, signal, relay, and agent snapshot polling and must be positive.

## Security Model

- Join tokens are signed, scoped, expiring, and revocable through the token ledger by cluster ID/nonce.
- Token policy constrains relay permission, route advertisements contained within allowed CIDRs, allowed tags, and max-use admission.
- Identity keys authenticate nodes to the control plane.
- WireGuard keys provide data-plane confidentiality.
- Relays cannot decrypt payload.
- Public nodes are not automatically relays; policy, health, and capacity are required.
- Control-plane registration rejects relay capability advertisements unless the join token policy allows relay, and accepted capabilities are marked as enabled by policy by the control plane.
- ACLs are evaluated by tag, role, route, protocol, and relay permission, and control-plane peer maps hide peers or advertised routes that are not allowed.
- Key rotation supports overlapping issuer token-signing keys plus identity and WireGuard key families separately.

## Failure Behavior

- Control plane down: existing WireGuard data-plane paths remain active until idle timers or kernel state changes remove them.
- Signal down: existing paths remain active; agents retry registration and path negotiation against the remaining configured signal endpoints, and new NAT traversal waits for signal recovery only when all configured signal endpoints are unavailable.
- Relay down: affected pairs demote to probing/direct candidates or another relay if available; otherwise `UNREACHABLE`.
- STUN down: known candidates remain usable; new NAT classification is degraded.
- Agent restart: identity and WireGuard keys are read from disk; the agent can re-register with a join token, refresh signal-service node state, negotiate pair paths, execute UDP hole-punch plans, report heartbeat/path state, then pinned routes and current peer map are rehydrated through explicit backend application and refreshed by continuous peer-map polling.

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

The `ipars-load` harness provides executable `three`, `ten`, and `thousand` scenarios against in-memory control-plane and signal components, plus `--transport http` for driving loopback TCP HTTP control-plane and signal endpoints with the same workload. `--transport relay-udp` drives relay HTTP admission and loopback UDP forwarding with validated configurable packet count and payload size. `--transport daemon` validates the requested agent process count against the selected scenario, then spawns separate `iparsd` control-plane, signal, STUN, relay, and dry-run agent processes, writes signed agent join tokens with the selected scenario's relay and route-provider policy distribution into private run-time files, and passes `--join-token-path` instead of exposing token material through argv. It captures each child process stdout/stderr log under the run-time directory, watches child process liveness during readiness and measurement phases, reports log tails on liveness or readiness failures, registers agents through signed join tokens, negotiates paths through the signal daemon, and verifies relay UDP forwarding through the relay daemon. It reports registration count/time, peer-map fanout, advertised route count, sampled active pair negotiations, relay candidate count, HTTP request counts, daemon process counts, relay UDP packets/bytes/throughput, and selected path-state totals as JSON. The 1000-node scenario samples active pairs rather than negotiating all possible pairs so the harness exercises the lazy-connect assumption while still measuring current peer-map fanout.

The bundled Docker Compose and Helm manifests use HTTP service URLs for control-plane, signal, relay admission, and agent APIs because `iparsd` serves plain HTTP directly. Production deployments should terminate TLS at a reverse proxy, load balancer, or Kubernetes Ingress before exposing those APIs outside the private deployment network.

## Implementation Roadmap

1. Shared typed models, CLI surface, and signed-token primitives.
2. Control-plane store trait plus in-memory, SQLite, and PostgreSQL backends.
3. Long-running control-plane, signal, STUN, relay, and agent daemons.
4. Kernel WireGuard backend: Linux `ip`/`wg` command runner and namespace-aware kernel netlink WireGuard peer backend exist; broaden privileged namespace integration coverage.
5. Route manager for Linux policy routing, Docker namespaces, and Kubernetes node underlay: `ip route`/`ip rule` command backend, namespace-aware rtnetlink backend, and validated namespace command execution exist; harden namespace lifecycle.
6. NAT traversal integration tests with network namespaces. Gated route-backend, hole-punch, and relay fallback namespace smoke tests exist; extend this into reproducible direct and NAT traversal topologies with full path validation.
7. Relay abuse controls, metrics, and production hardening.
