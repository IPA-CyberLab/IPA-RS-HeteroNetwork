# HeteroNetwork

HeteroNetwork is a Rust-based P2P VPN and overlay network for Linux, Docker,
Kubernetes, edge nodes, and native desktop clients. It prefers direct
WireGuard paths, falls back to an end-to-end encrypted relay, and keeps the
data plane running when the control plane is temporarily unavailable.

## Quick setup

### macOS or Windows

Run this in macOS Terminal or Windows Git Bash:

```sh
curl -fsSL https://raw.githubusercontent.com/IPA-CyberLab/IPA-RS-HeteroNetwork/master/install-client.sh | sh
```

The installer detects the host architecture, downloads the newest published
client, verifies its SHA-256 checksum, installs it for the current user, and
opens the app. Published macOS and Windows clients check for verified updates at
startup and every six hours. Sign in with Keycloak and select **Connect**.

macOS asks for administrator access when it installs the network helper and
starts a tunnel. Windows includes the required .NET and WireGuard runtime in
the release archive.

### Linux node

Use an existing HeteroNetwork management console:

1. Select **Add device**.
2. Choose the required setup profile.
3. Copy the generated one-line command to a clean Ubuntu systemd host and run
   it with `sudo`.
4. Wait for the node to become healthy and pass the automated onboarding E2E
   checks.

The generated command contains a short-lived enrollment token and the exact
release checksum. Do not assign a VPN address or create a Kubernetes join
command manually.

For the first public node or a deployment without an existing console, follow
the [operations runbook](docs/OPERATIONS.md).

### Build from source

Rust 1.88 or newer is required:

```sh
git clone https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork.git
cd IPA-RS-HeteroNetwork
cargo build --locked --release
cargo test --locked --workspace
```

The binaries are written to `target/release/ipars` and
`target/release/iparsd`.

## What it provides

- Signed, policy-bound node and desktop-client enrollment
- WireGuard peer and route reconciliation with lazy connections
- Direct IPv4, IPv6, and NAT-traversed paths with encrypted relay fallback
- HA Control Plane, Signal, STUN, Relay, Web UI, Keycloak, and PostgreSQL
- Docker route discovery and Kubernetes underlay integration
- Native macOS and Windows clients
- Prometheus, OpenTelemetry, health, path, and service-directory telemetry
- Terraform, Ansible, Argo CD, Helm, systemd, and release automation

The current implementation and known gaps are tracked in
[Implementation Status](docs/IMPLEMENTATION_STATUS.md).

## Repository map

| Path | Purpose |
| --- | --- |
| [`crates/`](crates/) | Rust CLI, daemons, protocol, storage, networking, and controllers |
| [`clients/macos/`](clients/macos/README.md) | SwiftUI client and privileged userspace WireGuard helper |
| [`clients/windows/`](clients/windows/README.md) | WPF client and WireGuardNT service integration |
| [`charts/`](charts/) | Helm deployment |
| [`deploy/`](deploy/) | Terraform, Ansible, Argo CD, systemd, and Kubernetes configuration |
| [`scripts/`](scripts/) | Deployment, recovery, packaging, and E2E verification |
| [`webui/`](webui/) | Embedded management UI |
| [`docs/`](docs/) | Design, operations, security, and incident records |

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Operations](docs/OPERATIONS.md)
- [Security](docs/SECURITY.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Kubernetes HA over HeteroNetwork](docs/KUBERNETES_HA_UNDERLAY.md)
- [PostgreSQL HA](docs/POSTGRES_HA.md)
- [Master-only and standard-node IaC](deploy/terraform/master-only/README.md)
- [Release channels](docs/RELEASE_CHANNELS.md)
- [GitHub Actions VPN and console E2E](docs/github-actions-vpn-console-e2e.md)

## Development checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Privileged network, Docker, Kubernetes, desktop-client, and release tests run
in GitHub Actions for published releases.

## License

[MIT](LICENSE)
