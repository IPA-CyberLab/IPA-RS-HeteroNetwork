# Operations Runbook

This runbook covers the current operational path for a Linux-first IPA-RS deployment.

## Bootstrap A Public Node

Generate an issuer key, bootstrap services, and a first join token:

```bash
ipars init \
  --public-endpoint 203.0.113.10:51820 \
  --issuer-private-key-path ./issuer.key \
  --issuer-key-id root \
  --allowed-route 100.64.0.0/10 \
  --allow-relay \
  --unlimited-uses \
  --spawn-daemons \
  --daemon-state-dir ./ipars-state
```

With `--spawn-daemons`, spawned services receive only a fixed system `PATH` and `C` locale rather than the operator's full environment. The bootstrap state directory and `logs/` directory are made owner-only, and service log files must be regular, non-symlink, non-hardlinked owner-only files. Without `--spawn-daemons`, run the emitted `iparsd control-plane`, `iparsd signal`, `iparsd stun`, and `iparsd relay` commands manually or under systemd.

## Join Nodes

Use file-backed tokens for agents:

```bash
iparsd agent \
  --join-token-path /etc/ipars/join.token \
  --state-path /var/lib/ipars/agent.json \
  --runtime-backend linux-command \
  --apply-peer-map
```

For validation without host route mutation:

```bash
iparsd agent \
  --join-token-path /etc/ipars/join.token \
  --state-path /var/lib/ipars/agent.json \
  --runtime-backend dry-run
```

## Docker

The base Compose stack starts PostgreSQL, control plane, signal, STUN, relay, and agent services. Docker Engine API access is not mounted into the agent unless the discovery override is used; the override mounts the selected Docker socket read-only and does not create a missing host socket path.

```bash
docker compose -f docker/compose.yaml up -d --build --wait
```

For route discovery through Docker Engine bridge networks, use the install plan:

```bash
ipars docker install \
  --project-name ipars \
  --compose-file docker/compose.yaml \
  --relay-public-endpoint 203.0.113.10:51820 \
  --relay-admission-url https://relay.example.com:9580 \
  --relay-max-sessions 10000 \
  --relay-max-sessions-per-node 100 \
  --relay-max-mbps 1000 \
  --relay-session-ttl-seconds 300 \
  --relay-admission-rate-limit 4096 \
  --relay-admission-rate-limit-window-seconds 60 \
  --docker-discover-networks \
  --docker-network ipars_default
```

Set `--agent-runtime-backend dry-run` for rootful Compose validation that must not
create host networking resources. Rootless deployments require the default
`linux-command` backend because their Compose override starts a userspace
WireGuard process.

Run the repeatable Compose smoke with:

```bash
scripts/docker-smoke.sh
```

## Kubernetes

The Helm chart deploys a node-underlay VPN agent, not a CNI. It can advertise Kubernetes Service/API routes through a route-provider agent and optional RBAC-backed Service discovery.

```bash
ipars k8s install \
  --release ipars \
  --namespace ipars-system \
  --join-token-secret ipars-join-token \
  --join-token-key token \
  --expose-relay \
  --relay-public-endpoint 203.0.113.10:51820 \
  --relay-admission-url https://relay.example.com:9580 \
  --relay-max-sessions 10000 \
  --relay-max-mbps 1000 \
  --allow-public-service-exposure \
  --relay-allow-source-cidr 203.0.113.0/24
```

Render and validate common chart modes with:

```bash
scripts/helm-smoke.sh
```

For a live Kubernetes cluster integration gate, provide an image that the cluster can
pull and run the disposable-namespace smoke. It verifies Helm's DaemonSet against a
real control-plane/signal pair, signed token registration, namespace-scoped Service
discovery RBAC, agent peer-map synchronization, and control-plane health metrics:

```bash
IPARS_K8S_SMOKE_IMAGE_REPOSITORY=registry.example.com/ipars \
IPARS_K8S_SMOKE_IMAGE_TAG=ci \
scripts/k8s-live-smoke.sh
```

The runner requires `kubectl`, `helm`, `jq`, and either `IPARS_K8S_SMOKE_IPARS_BIN`
or Cargo. It refuses an existing namespace, removes its generated namespace by default,
and never writes the signed token to command-line arguments. Set
`IPARS_K8S_SMOKE_KEEP_RESOURCES=1` only when retaining diagnostics is required.
Set `IPARS_K8S_SMOKE_AGENT_RUNTIME_BACKEND=dry-run` only for clusters where the
real WireGuard backend is intentionally unavailable; the default is `linux-command`.

For kind-based CI or a local disposable cluster, the wrapper creates a control-plane
and worker node, builds and loads a local image, invokes the same live smoke with the
`dry-run` backend, then removes the cluster and generated image:

```bash
scripts/kind-k8s-smoke.sh
```

It requires `docker`, `kind`, `kubectl`, `helm`, `jq`, and Cargo or
`IPARS_K8S_SMOKE_IPARS_BIN`. Set `IPARS_KIND_K8S_SMOKE_KEEP_CLUSTER=1` to retain
the cluster and live-smoke namespace for diagnostics.

## Health Checks

Common probes:

```bash
ipars status --agent-url http://127.0.0.1:9780
ipars status --control-plane-url http://127.0.0.1:8443
ipars peers --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars routes --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars path status --agent-url http://127.0.0.1:9780
ipars path events --agent-url http://127.0.0.1:9780
ipars relay status --relay-url http://127.0.0.1:9580
ipars relay probe --relay-url http://127.0.0.1:9580 --relay-udp 127.0.0.1:51820 --relay-admission-bearer-token <relay-secret> --send-invalid-credential
ipars stun probe --stun-server 127.0.0.1:3478
```

Prometheus-style metrics are exposed by control-plane, signal, relay, and agent HTTP services. Control-plane metrics include accepted/rejected WireGuard key-rotation and node-removal counters. OTLP HTTP/protobuf export is available with `--otel-enabled --otel-endpoint http://collector:4318`.

## Failure Behavior

- Existing WireGuard data-plane state and relay sessions continue when the control plane is unavailable.
- New joins, peer-map refreshes, policy changes, route changes, key rotations, and node removals require a reachable control plane.
- Agents keep ordered control-plane and signal endpoint lists and retry failover endpoints without stopping the local data-plane loop.
- Signal failure prevents new path negotiation and hole-punch planning; existing selected paths remain in local runtime state until they expire or are replaced.
- Relay failure causes affected relay paths to renew or renegotiate. If direct candidates are available, path scoring can promote back to direct.
- Redundant control-plane instances can share durable SQL state. The load harness verifies peer-map, path-state, relay-candidate, and existing relay dataplane survival after one control-plane process is stopped.

## Smoke Gates

Use these before publishing an operational change:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
scripts/helm-smoke.sh
scripts/docker-smoke.sh
IPARS_LOAD_SMOKE_BUILD_DAEMON=1 scripts/load-smoke.sh
```

Privileged Linux hosts can also run:

```bash
scripts/netns-smoke.sh
```

That suite requires network namespace creation privileges and may require `wireguard-tools`, kernel WireGuard support, `iptables`, and forwarding sysctls.
