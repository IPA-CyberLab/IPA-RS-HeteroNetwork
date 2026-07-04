# IPA-RS-HeteroNetwork

Rust implementation of an operations-oriented P2P VPN / overlay network for Linux hosts, Docker environments, Kubernetes node underlays, edge nodes, and large distributed clusters.

The repository is being built toward a complete system rather than an MVP. The current baseline contains:

- a Rust workspace split by control plane, signal, relay, STUN, agent, route manager, crypto, shared types, and CLI boundaries
- typed node, peer, path, relay, token, policy, ACL, route, and health models
- signed join token creation and verification primitives
- pair-scoped path state and scoring primitives
- initial control-plane registration/IP-allocation service with in-memory test backend
- SQLite and PostgreSQL control-plane store implementations
- CLI command surface for `init`, `join`, `status`, `peers`, `routes`, `token create`, `relay status`, `path status`, `docker install`, and `k8s install`
- Docker Compose and Helm chart starting points
- architecture, operations, security, and load-test plan

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete target design and implementation roadmap.

## Build

```bash
cargo test --workspace
```

## CLI Surface

```bash
ipars init --public-endpoint 203.0.113.10:51820
ipars join '<signed-token>'
ipars status
ipars peers
ipars routes
ipars token create --role edge --tag edge --ttl-seconds 86400
ipars relay status
ipars path status
ipars docker install
ipars k8s install
```

The next production milestone is to wire the CLI to long-running daemons, enforce token revocation/max-use in durable storage, and add network-namespace integration tests for direct, NAT traversal, and relay fallback paths.
