# IPA-RS-HeteroNetwork

Rust implementation of an operations-oriented P2P VPN / overlay network for Linux hosts, Docker environments, Kubernetes node underlays, edge nodes, and large distributed clusters.

The repository is being built toward a complete system rather than an MVP. The current baseline contains:

- a Rust workspace split by control plane, signal, relay, STUN, agent, route manager, crypto, shared types, and CLI boundaries
- typed node, peer, path, relay, token, policy, ACL, route, and health models
- signed join token creation and verification primitives
- pair-scoped path state and scoring primitives
- initial control-plane registration/IP-allocation service with in-memory test backend
- SQLite and PostgreSQL control-plane store implementations
- token ledger primitives and control-plane revocation API for revocation and max-use enforcement
- control-plane join service that verifies signed tokens, issuer keys, cluster/time validity, and token-ledger admission before registration
- typed control-plane HTTP routes for health, join registration, peer-map retrieval, and JSON/Prometheus metrics
- `iparsd control-plane` daemon for serving the control-plane HTTP API with in-memory, SQLite, or PostgreSQL stores
- signal registry, typed signal HTTP routes, and `iparsd signal` for endpoint candidate exchange, path negotiation, and hole-punch planning
- RFC 5389 STUN Binding request/response handling, RFC 5780 change-request/other-address probes, multi-server NAT mapping/filtering classification, and `iparsd stun` daemon for public endpoint detection
- relay session admission/status HTTP API, Prometheus relay metrics with cumulative dataplane/drop counters, expiring credentialed opaque UDP payload forwarding with per-session rate limits, and `iparsd relay`
- `ipars join <token>` now builds a typed join request, generates node keys, and posts to the token's control-plane bootstrap endpoint
- persistent agent node state, agent status/path/STUN probe/NAT classification HTTP API, and `iparsd agent`
- `iparsd agent --join-token` startup registration using persisted agent identity/WireGuard keys and token bootstrap control-plane discovery
- `iparsd agent` heartbeat reporting to `/v1/heartbeat` with current health and endpoint candidates, retrying on control-plane errors
- `iparsd agent` signal-service node registration that refreshes the registered NodeRecord and endpoint candidates when a signal endpoint is known
- `iparsd agent` signal path negotiation loop that records pair-scoped path state and reports it in heartbeat payloads
- `iparsd agent` relay admission for signal-selected relay paths, storing expiring relay credentials only in transient agent runtime state
- relay session renewal window handling and stale relay credential removal when paths return to direct/non-relay states
- agent relay dataplane forwarder that proxies local WireGuard UDP packets through credentialed relay frames while keeping payload opaque end to end
- relay-aware peer-map application and daemon-supervised per-peer forwarder endpoints with namespace placement checks, capacity limits, dead-task reaping, and restart backoff for active relay sessions
- agent JSON and Prometheus metrics plus bounded structured path-change event export
- `iparsd` root observability options for structured tracing output and optional OTLP HTTP/protobuf trace/log/metrics export to an OpenTelemetry collector
- UDP hole-punch executor and `iparsd agent` integration for signal-provided NAT traversal punch plans
- Kubernetes underlay Service/API route application from explicit Helm CIDRs or RBAC-backed Kubernetes API Service discovery through command or kernel netlink Linux route backends
- Docker container CIDR route application from explicit Compose/agent route intents or Docker Engine API network discovery through command or kernel netlink Linux route backends
- control-plane heartbeat handling for health, candidate refresh, and pair-scoped path-state persistence
- Linux WireGuard command backend for explicit interface creation and peer upsert/removal through `ip`/`wg`, plus a selectable kernel netlink backend for current or validated `--linux-netns` WireGuard interface and peer management
- Linux route-manager command backend for overlay routes and policy rules through `ip route`/`ip rule`, plus a selectable rtnetlink backend, both with validated namespace placement
- agent peer-map applier that converts control-plane peers into WireGuard peer configs and route plans
- `iparsd agent --apply-peer-map` continuous peer-map polling for fetching `/v1/peers/{node_id}` and applying peers/routes through selectable runtime backends, including Linux command execution with `--linux-netns` namespace placement and a `dry-run` backend for validation without host mutation
- CLI command surface for `init`, `join`, `status`, `peers`, `routes`, `token create`, `token revoke`, `relay status`, `path status`, `docker install`, and `k8s install`, with HTTP API-backed status/peer/route/relay/path queries when URLs are provided
- Docker Compose and Helm chart starting points
- architecture, operations, security, load-test plan, and `ipars-load` scale/load harness

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete target design and implementation roadmap.

## Build

```bash
cargo test --workspace
```

Linux network namespace integration tests are gated because they create host network namespaces and require `iproute2` plus `CAP_NET_ADMIN`:

```bash
IPARS_RUN_NETNS_TESTS=1 cargo test -p ipars-route-manager --test netns_route_backend
```

Scale/load harness scenarios run against in-memory control-plane and signal components by default,
against loopback HTTP control-plane/signal endpoints with `--transport http`, through relay
HTTP admission plus UDP forwarding with `--transport relay-udp`, or across spawned `iparsd`
control-plane/signal/STUN/relay/agent processes with `--transport daemon`:

```bash
cargo run -p ipars-load -- --scenario three
cargo run -p ipars-load -- --scenario ten
cargo run -p ipars-load -- --scenario thousand
cargo run -p ipars-load -- --transport http --scenario ten
cargo run -p ipars-load -- --transport relay-udp --scenario ten --relay-packets-per-session 16 --relay-payload-bytes 1200
cargo build -p ipars-daemon
cargo run -p ipars-load -- --transport daemon --scenario three --iparsd-bin target/debug/iparsd --daemon-agent-processes 3
```

## CLI Surface

```bash
ipars init --public-endpoint 203.0.113.10:51820
ipars join '<signed-token>'
ipars status --agent-url http://127.0.0.1:9780
ipars peers --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars routes --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars token create --role edge --tag edge --ttl-seconds 86400
ipars token revoke --control-plane-url https://203.0.113.10:8443 --cluster-id <cluster-id> --nonce <token-nonce>
ipars relay status --relay-url http://127.0.0.1:9580
ipars path status --agent-url http://127.0.0.1:9780
ipars docker install
ipars k8s install
```

`iparsd agent --runtime-backend linux-command` is the default data-plane applier and uses explicit `ip`/`wg` commands. It preflights interface naming, required host commands, `CAP_NET_ADMIN`, and requested `ip netns exec` placement before mutating host networking. Peer-map application can switch WireGuard interface and peer management to kernel netlink with `--wireguard-backend kernel-netlink`, and peer-map/Docker/Kubernetes route application can switch route/rule management to rtnetlink with `--route-backend kernel-netlink`. `--runtime-backend dry-run` keeps peer-map, Docker route, and Kubernetes underlay application loops active while using in-memory WireGuard state and dry-run route plans.

For Kubernetes underlay routing, `--kubernetes-discover-services` lets the agent query the Kubernetes API with its ServiceAccount token, optionally constrained by `--kubernetes-namespace` and `--kubernetes-service-label-selector`, and convert Service cluster IPs plus the in-cluster API server address into overlay host routes. Explicit `--kubernetes-service-cidr` and `--kubernetes-api-server-cidr` values remain supported for static deployments.

Docker route application can use explicit `--docker-container-cidr` inputs or `--docker-discover-networks` to query Docker Engine bridge networks over the Unix socket. `--docker-api-socket` overrides socket placement, otherwise `DOCKER_HOST=unix://...`, `/var/run/docker.sock`, and rootless `$XDG_RUNTIME_DIR/docker.sock` are checked in order. `--docker-network` filters discovery by network name or ID for multi-network Compose deployments.

`iparsd` accepts root observability flags before the subcommand. `--otel-enabled --otel-endpoint http://collector:4318` exports traces, logs, and metrics through OTLP HTTP/protobuf; relay dataplane counters are also recorded as OTLP metrics. `--otel-service-name` overrides the default `iparsd-<component>` service name, `--otel-metrics-poll-interval-seconds` controls relay snapshot polling, and `--log-filter` maps to tracing filter syntax. The same settings are available through `IPARS_OTEL_ENABLED`, `IPARS_OTEL_ENDPOINT`, `IPARS_OTEL_SERVICE_NAME`, `IPARS_OTEL_METRICS_POLL_INTERVAL_SECONDS`, and `IPARS_LOG_FILTER`.

The next production milestone is to extend network-namespace integration tests from route-backend validation into direct, NAT traversal, and relay fallback path validation.
