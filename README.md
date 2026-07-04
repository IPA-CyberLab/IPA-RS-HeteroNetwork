# IPA-RS-HeteroNetwork

Rust implementation of an operations-oriented P2P VPN / overlay network for Linux hosts, Docker environments, Kubernetes node underlays, edge nodes, and large distributed clusters.

The repository is being built toward a complete system rather than an MVP. The current baseline contains:

- a Rust workspace split by control plane, signal, relay, STUN, agent, route manager, crypto, shared types, and CLI boundaries
- typed node, peer, path, relay, token, policy, ACL, route, and health models
- signed join token creation and verification primitives
- pair-scoped path state and scoring primitives
- control-plane registration/IP-allocation service that skips already assigned VPN IPs when backed by durable node state
- SQLite and PostgreSQL control-plane store implementations with VPN IP uniqueness guards
- token ledger primitives and control-plane revocation API for revocation and max-use enforcement
- control-plane join service that verifies signed tokens, issuer keys, cluster/time validity, token-ledger admission, CIDR-containing route policy, and relay-capability policy before registration
- typed control-plane HTTP routes for health, join registration, policy inspection, ACL-filtered peer-map retrieval, and JSON/Prometheus metrics
- `iparsd control-plane` daemon for serving the control-plane HTTP API with in-memory, SQLite, or PostgreSQL stores
- signal registry, typed signal HTTP routes, JSON/Prometheus metrics, and `iparsd signal` for endpoint candidate exchange, path negotiation, and hole-punch planning
- RFC 5389 STUN Binding request/response handling, RFC 5780 change-request/other-address probes, multi-server NAT mapping/filtering classification, and `iparsd stun` daemon for public endpoint detection
- relay session admission/status HTTP API, Prometheus relay metrics with cumulative dataplane/drop counters, expiring credentialed opaque UDP payload forwarding with per-session rate limits, and `iparsd relay`
- control-plane relay maps and relay-candidate metrics that require relay policy, capacity, E2E-only mode, and a fresh healthy heartbeat within the configured relay health TTL
- `ipars join <token>` now builds a typed join request, generates node keys, and posts to the token's control-plane bootstrap endpoints with ordered failover
- persistent agent node state, agent status/path/path-probe/STUN probe/NAT classification/peer-activity/packet-flow HTTP API, and `iparsd agent`
- `iparsd agent --join-token` or `--join-token-path` startup registration using persisted agent identity/WireGuard keys and token bootstrap control-plane discovery with ordered failover
- `iparsd agent` heartbeat reporting to `/v1/heartbeat` with current health, endpoint candidates, relay capability updates, and path state, retrying across known control-plane endpoints
- `iparsd agent` signal-service node registration that refreshes the registered NodeRecord and endpoint candidates across known signal endpoints
- `iparsd agent` signal path negotiation loop that fetches peer maps across known control-plane endpoints, fails over across known signal endpoints, records pair-scoped path state, and reports it in heartbeat payloads
- `iparsd agent` relay admission for signal-selected relay paths, failing over across ranked relay candidates and storing expiring relay credentials only in transient agent runtime state
- relay session renewal window handling and stale relay credential removal when paths return to direct/non-relay states
- agent relay dataplane forwarder that proxies local WireGuard UDP packets through credentialed relay frames while keeping payload opaque end to end
- agent relay capability advertisement for public nodes with explicit relay endpoint/admission URL settings, still gated by join-token relay policy at control-plane registration
- relay-aware peer-map application and daemon-supervised per-peer forwarder endpoints with namespace placement checks, capacity limits, dead-task reaping, and restart backoff for active relay sessions
- agent JSON and Prometheus metrics for path state, relay admission, relay forwarders, lazy connect, packet-flow activity, and filtered destination reason counters plus bounded structured path-change event export
- `iparsd` root observability options for structured tracing output and optional OTLP HTTP/protobuf trace/log/metrics export to an OpenTelemetry collector across control-plane, signal, relay, and agent components
- UDP hole-punch executor and `iparsd agent` integration for signal-provided NAT traversal punch plans
- Kubernetes underlay Service/API route application from explicit Helm CIDRs or RBAC-backed Kubernetes API Service discovery through command or kernel netlink Linux route backends
- Docker container CIDR route application from explicit Compose/agent route intents or Docker Engine API network discovery through command or kernel netlink Linux route backends
- control-plane heartbeat handling for health, candidate refresh, and pair-scoped path-state persistence
- Linux WireGuard command backend for explicit interface creation and peer upsert/removal through `ip`/`wg`, plus a selectable kernel netlink backend for current or validated `--linux-netns` WireGuard interface and peer management
- Linux route-manager command backend for overlay routes and policy rules through `ip route`/`ip rule`, plus a selectable rtnetlink backend, both with validated namespace placement
- agent peer-map applier that converts active or pinned control-plane peers into WireGuard peer configs and route plans, and prunes idle unpinned peers from WireGuard state after the cluster idle timeout
- `iparsd agent --apply-peer-map` continuous peer-map polling for fetching `/v1/peers/{node_id}` and applying active/pinned peers/routes through selectable runtime backends, including Linux command execution with `--linux-netns` namespace placement and a `dry-run` backend for validation without host mutation
- CLI command surface for `init`, `join`, `status`, `peers`, `routes`, `token create`, `token revoke`, `relay status`, `path status`, `path probe`, `docker install`, and `k8s install`, with reusable issuer-key token signing, bootstrap daemon command output, opt-in local daemon spawning, token policy flags, and HTTP API-backed agent/control-plane status, peer, route, relay, and path queries/probes when URLs are provided
- Docker Compose and Helm chart starting points
- architecture, operations, security, load-test plan, and `ipars-load` scale/load harness

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete target design and implementation roadmap.

## Build

```bash
cargo test --workspace
```

Linux network namespace integration tests are gated because they create host network namespaces and require `iproute2` plus `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`:

```bash
IPARS_RUN_NETNS_TESTS=1 cargo test -p ipars-route-manager --test netns_route_backend
IPARS_RUN_WG_NETNS_TESTS=1 cargo test -p ipars-agent --test netns_wireguard_backend
IPARS_RUN_HOLE_PUNCH_NETNS_TESTS=1 cargo test -p ipars-agent --test netns_hole_punch
IPARS_RUN_RELAY_NETNS_TESTS=1 cargo test -p ipars-agent --test netns_relay_fallback
```

The WireGuard namespace test also requires `wireguard-tools` and kernel WireGuard support. The hole-punch namespace tests include fixed-port one-sided public-peer SNAT plus IP-only and fixed-port endpoint-independent two-sided SNAT topologies, and require `iptables` plus `sysctl` when the gated tests are enabled.

Scale/load harness scenarios run against in-memory control-plane and signal components by default,
against loopback HTTP control-plane/signal endpoints with `--transport http`, through relay
HTTP admission plus UDP forwarding with `--transport relay-udp`, or across spawned `iparsd`
control-plane/signal/STUN/relay/agent processes with `--transport daemon`. Daemon transport waits for service health, agent registration visibility in the control plane, and signal negotiation readiness before measuring:

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
ipars init --public-endpoint 203.0.113.10:51820 --issuer-private-key-path ./issuer.key --issuer-key-id root --allowed-route 10.43.0.0/16 --allow-relay --unlimited-uses --daemon-state-dir ./ipars-state --spawn-daemons
ipars join '<signed-token>'
ipars status --agent-url http://127.0.0.1:9780
ipars status --control-plane-url http://127.0.0.1:8443
ipars peers --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars routes --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars token create --issuer-private-key-path ./issuer.key --issuer-key-id root --role edge --tag edge --allowed-route 10.42.0.0/16 --allow-relay --max-uses 7 --ttl-seconds 86400
ipars token revoke --control-plane-url https://203.0.113.10:8443 --cluster-id <cluster-id> --nonce <token-nonce>
ipars relay status --relay-url http://127.0.0.1:9580
ipars path status --agent-url http://127.0.0.1:9780
ipars path probe --agent-url http://127.0.0.1:9780 --peer <peer-node-id> --state DIRECT_NAT_TRAVERSAL --latency-ms 23.5 --loss-ppm 100 --jitter-ms 3.25 --candidate-addr 198.51.100.10:51820 --candidate-kind stun-reflexive --pin
ipars docker install --project-name ipars --compose-file docker/compose.yaml --docker-discover-networks --docker-network ipars_default
ipars k8s install --release ipars --namespace ipars-system --join-token-secret ipars-join-token --join-token-key token
```

`ipars init` returns the signed bootstrap join token, the issuer metadata, and the `iparsd` commands for control-plane, signal, STUN, and relay. With `--spawn-daemons`, those services are started in the background and write logs under `--daemon-state-dir`; without it, run the returned commands manually. Later `token create` calls should use the same issuer private key path or `IPARS_ISSUER_PRIVATE_KEY`. Join clients and agents try multiple control-plane bootstrap endpoints in token order for initial registration failover. After agent registration, heartbeat reporting, peer-map polling, and signal path peer-map fetches keep an ordered control-plane endpoint list, prioritizing the registered endpoint and falling back to token bootstraps unless `--control-plane-url` is explicitly set. Agents also register node/candidate state with all token signal bootstraps and fail over signal path negotiation and hole-punch plan requests across them unless `--signal-url` is explicitly set.

Join tokens are single-use by default. `ipars init` and `ipars token create` can set route allowlists with repeated `--allowed-route`, relay permission with `--allow-relay`, and admission limits with `--max-uses` or `--unlimited-uses`.

For issuer key rotation, start `iparsd control-plane` with repeated `--trusted-issuer-key issuer_node_id,key_id,public_key` values, or semicolon-separated `IPARS_TRUSTED_ISSUER_KEYS`, so old and next signing keys overlap while new tokens move to the next `--issuer-key-id`.

Control-plane ACLs can be loaded with repeated `iparsd control-plane --acl-rule '<json>'` values, or semicolon-separated JSON objects in `IPARS_ACL_RULES`. Each object uses the typed `AclRule` shape with `id`, `from_roles`, `from_tags`, `to_roles`, `to_tags`, `routes`, `protocol`, and `action`; an empty ACL list keeps default allow-all peer visibility, while configured deny rules take precedence over allow rules.

Relay candidates also require fresh healthy status. `iparsd control-plane --relay-health-ttl-seconds` or `IPARS_RELAY_HEALTH_TTL_SECONDS` controls how long a healthy relay heartbeat remains eligible for relay maps and relay-candidate metrics. `iparsd signal --relay-health-ttl-seconds` or `IPARS_SIGNAL_RELAY_HEALTH_TTL_SECONDS` applies the same freshness window to relay candidates offered during signal path negotiation.

Operators can inspect the active control-plane cluster policy, VPN pool, and loaded ACL rules with `GET /v1/policy` on the control-plane HTTP service.

`iparsd agent --runtime-backend linux-command` is the default data-plane applier and uses explicit `ip`/`wg` commands. It always validates static runtime configuration such as Linux interface names, namespace names, and relay-forwarder capacity, then preflights required host commands, `CAP_NET_ADMIN` for kernel network mutation, `CAP_NET_RAW` when WireGuard peer-map dataplane application is enabled, `CAP_SYS_ADMIN` when `--linux-netns` placement is requested, and the requested `/var/run/netns` entry before mutating host networking. Namespace preflight rejects missing entries, symlinks, directories, and non-`nsfs` regular files, and warns when the requested entry resolves to the current process namespace. `--skip-runtime-preflight` skips the host command/capability/path probes, but not static configuration validation. Peer-map application can switch WireGuard interface and peer management to kernel netlink with `--wireguard-backend kernel-netlink`, and peer-map/Docker/Kubernetes route application can switch route/rule management to rtnetlink with `--route-backend kernel-netlink`. `--runtime-backend dry-run` keeps peer-map, Docker route, and Kubernetes underlay application loops active while using in-memory WireGuard state and dry-run route plans.

Lazy connect is enforced during signal path negotiation and `--apply-peer-map`: route providers, relay-capable peers, control-plane/policy-pinned roles or tags, peers marked through `POST /v1/peer-activity`, and packet-flow destinations resolved through `POST /v1/packet-flow` are negotiated/applied, while idle unpinned peers are removed from WireGuard and relay-forwarder state after the cluster idle timeout. Packet-flow requests can include optional source IP, protocol, source/destination ports, and detector metadata for auditability. `iparsd agent --packet-flow-detector proc-net-conntrack` can poll `/proc/net/nf_conntrack` or `/proc/net/ip_conntrack`, or a custom `--packet-flow-conntrack-path`; `--packet-flow-detector conntrack-netlink` reads the Linux conntrack table through `NETLINK_NETFILTER`; and `--packet-flow-detector conntrack-netlink-events` subscribes to conntrack NEW/UPDATE multicast events. Detector-fed observations ignore unspecified, loopback, multicast, broadcast, and link-local destinations before lazy-connect route matching so broad advertised routes do not activate peers for local control traffic.

For Kubernetes underlay routing, `--kubernetes-discover-services` lets the agent query the Kubernetes API with its ServiceAccount token, optionally constrained by `--kubernetes-namespace` and `--kubernetes-service-label-selector`, and convert Service cluster IPs plus the in-cluster API server address into overlay host routes. Explicit `--kubernetes-service-cidr` and `--kubernetes-api-server-cidr` values remain supported for static deployments. The Helm chart mounts the join token Secret and passes it to the agent through `--join-token-path`, and can optionally create Services for the agent API and colocated relay endpoints. NodePort/LoadBalancer exposure requires `--allow-public-service-exposure`; LoadBalancer exposure also requires `--agent-api-allow-source-cidr` or `--relay-allow-source-cidr` unless `--allow-unrestricted-load-balancer` is set, and the chart refuses external Service types unless the corresponding exposure acknowledgement value is set.

Public nodes that run a colocated relay can start `iparsd agent` with `--relay-public-endpoint` and `--relay-admission-url` to advertise relay capability during join. `--relay-status-url` lets heartbeat refresh capacity and active-session counts from the relay daemon. The control plane enables that capability only when the signed join token includes relay permission.

Docker route application can use explicit `--docker-container-cidr` inputs or `--docker-discover-networks` to query Docker Engine bridge networks over the Unix socket. `--docker-api-socket` overrides socket placement, otherwise `DOCKER_HOST=unix://...`, `/var/run/docker.sock`, and rootless `$XDG_RUNTIME_DIR/docker.sock` are checked in order. `--docker-network` filters discovery by network name or ID for multi-network Compose deployments.

The bundled Docker Compose and Helm examples use plain HTTP between private deployment services because the current `iparsd` daemons serve HTTP directly. Terminate TLS at an external reverse proxy or Kubernetes Ingress when exposing control-plane, signal, relay, or agent APIs outside the private deployment network.

`ipars docker install` and `ipars k8s install` emit JSON install plans with the manifest path, validation/apply commands, environment overrides, privilege requirements, and exposure/security notes. The Docker plan exports the agent route settings for rootless socket discovery, repeated network filters, explicit container namespace/interface/CIDR inputs, and the default `IPARS_AGENT_APPLY_DOCKER_ROUTES=true` wiring. The Kubernetes plan includes the join-token Secret wiring and optional flags for agent API and relay Service exposure, including Service type, source-range, unrestricted LoadBalancer acknowledgement, and annotation overrides; relay exposure requires the public UDP endpoint and relay admission URL that peers should use.

`iparsd` accepts root observability flags before the subcommand. `--otel-enabled --otel-endpoint http://collector:4318` exports traces, logs, and metrics through OTLP HTTP/protobuf; control-plane node/path/health gauges, signal node/relay/NAT/health/request metrics, relay dataplane counters, and agent path, path-probe, relay-admission, relay-forwarder, lazy-connect, packet-flow, and filtered destination reason metrics are also recorded as OTLP metrics. `--otel-service-name` overrides the default `iparsd-<component>` service name, `--otel-metrics-poll-interval-seconds` controls control-plane, signal, relay, and agent snapshot polling, and `--log-filter` maps to tracing filter syntax. The same settings are available through `IPARS_OTEL_ENABLED`, `IPARS_OTEL_ENDPOINT`, `IPARS_OTEL_SERVICE_NAME`, `IPARS_OTEL_METRICS_POLL_INTERVAL_SECONDS`, and `IPARS_LOG_FILTER`.

The next production milestone is to extend network-namespace integration tests from route-backend and relay fallback smoke coverage into reproducible NAT topology and full path validation.
