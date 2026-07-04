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
- RFC 5389 STUN Binding request/response handling, multi-server NAT mapping classification, and `iparsd stun` daemon for public endpoint detection
- relay session admission/status HTTP API, Prometheus relay metrics, expiring credentialed opaque UDP payload forwarding with per-session rate limits, and `iparsd relay`
- `ipars join <token>` now builds a typed join request, generates node keys, and posts to the token's control-plane bootstrap endpoint
- persistent agent node state, agent status/STUN probe/NAT classification HTTP API, and `iparsd agent`
- `iparsd agent --join-token` startup registration using persisted agent identity/WireGuard keys and token bootstrap control-plane discovery
- `iparsd agent` heartbeat reporting to `/v1/heartbeat` with current health and endpoint candidates, retrying on control-plane errors
- `iparsd agent` signal-service node registration that refreshes the registered NodeRecord and endpoint candidates when a signal endpoint is known
- `iparsd agent` signal path negotiation loop that records pair-scoped path state and reports it in heartbeat payloads
- `iparsd agent` relay admission for signal-selected relay paths, storing expiring relay credentials only in transient agent runtime state
- relay session renewal window handling and stale relay credential removal when paths return to direct/non-relay states
- agent relay dataplane forwarder that proxies local WireGuard UDP packets through credentialed relay frames while keeping payload opaque end to end
- relay-aware peer-map application and daemon-supervised per-peer forwarder endpoints with namespace placement checks, capacity limits, and restart backoff for active relay sessions
- agent JSON and Prometheus metrics plus bounded structured path-change event export
- UDP hole-punch executor and `iparsd agent` integration for signal-provided NAT traversal punch plans
- Kubernetes underlay Service/API route application from Helm-provided CIDRs through the Linux route backend
- Docker container CIDR route application from explicit Compose/agent route intents through the Linux route backend
- control-plane heartbeat handling for health, candidate refresh, and pair-scoped path-state persistence
- Linux WireGuard command backend for explicit interface creation and peer upsert/removal through `ip`/`wg`, with optional validated `ip netns exec` execution
- Linux route-manager command backend for overlay routes and policy rules through `ip route`/`ip rule`, with optional validated `ip netns exec` execution
- agent peer-map applier that converts control-plane peers into WireGuard peer configs and route plans
- `iparsd agent --apply-peer-map` continuous peer-map polling for fetching `/v1/peers/{node_id}` and applying peers/routes through Linux backends, including `--linux-netns` namespace placement, with retry on control-plane errors
- CLI command surface for `init`, `join`, `status`, `peers`, `routes`, `token create`, `token revoke`, `relay status`, `path status`, `docker install`, and `k8s install`
- Docker Compose and Helm chart starting points
- architecture, operations, security, and load-test plan

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete target design and implementation roadmap.

## Build

```bash
cargo test --workspace
```

Linux network namespace integration tests are gated because they create host network namespaces and require `iproute2` plus `CAP_NET_ADMIN`:

```bash
IPARS_RUN_NETNS_TESTS=1 cargo test -p ipars-route-manager --test netns_route_backend
```

## CLI Surface

```bash
ipars init --public-endpoint 203.0.113.10:51820
ipars join '<signed-token>'
ipars status
ipars peers
ipars routes
ipars token create --role edge --tag edge --ttl-seconds 86400
ipars token revoke --control-plane-url https://203.0.113.10:8443 --cluster-id <cluster-id> --nonce <token-nonce>
ipars relay status
ipars path status
ipars docker install
ipars k8s install
```

The next production milestone is to extend network-namespace integration tests from route-backend validation into direct, NAT traversal, and relay fallback path validation.
