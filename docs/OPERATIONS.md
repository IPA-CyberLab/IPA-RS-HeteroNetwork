# Operations Runbook

This runbook covers the current operational path for a Linux-first IPA-RS deployment.

## Bootstrap A Public Node

Generate an issuer key, bootstrap services, and a first join token:

```bash
umask 077
head -c 32 /dev/urandom | base64 > ./control-plane-operator-api.token
ipars init \
  --public-endpoint 203.0.113.10:51820 \
  --issuer-private-key-path ./issuer.key \
  --issuer-key-id root \
  --control-plane-operator-api-bearer-token-path ./control-plane-operator-api.token \
  --allowed-route 100.64.0.0/10 \
  --allow-relay \
  --unlimited-uses \
  --spawn-daemons \
  --daemon-state-dir ./ipars-state
```

With `--spawn-daemons`, spawned services receive only a fixed system `PATH` and `C` locale rather than the operator's full environment. The Control Plane receives the operator credential by file path, not token value in argv. Its policy and metric routes are absent when no operator credential is configured. The bootstrap state directory and `logs/` directory are made owner-only, and service log files must be regular, non-symlink, non-hardlinked owner-only files. Without `--spawn-daemons`, run the emitted `iparsd control-plane`, `iparsd signal`, `iparsd stun`, and `iparsd relay` commands manually or under systemd.

Signal metrics also require a distinct operator token. For a manually supervised Signal service, generate one with `umask 077`, pass `--operator-api-bearer-token-path /etc/ipars/signal-operator-api.token`, and configure the same credential in the metrics scraper. If omitted, Signal metric routes remain absent while health and signed protocol routes continue operating.

STUN HTTP metrics require another distinct token through `iparsd stun --operator-api-bearer-token-path /etc/ipars/stun-operator-api.token`. Omitting it removes only `/metrics` and `/v1/metrics`; UDP Binding, RFC5780 probes, and `/healthz` remain available.

Signal must be able to reach at least one control-plane API to authenticate node registrations. Configure repeated `iparsd signal --control-plane-url http://control-plane-a:8443 --control-plane-url http://control-plane-b:8443` values, or the comma-delimited `IPARS_SIGNAL_CONTROL_PLANE_URLS` environment variable. The default authenticated-membership TTL is 90 seconds; agents refresh every 30 seconds. Tune it with `--node-auth-ttl-seconds` or `IPARS_SIGNAL_NODE_AUTH_TTL_SECONDS` between 1 and 3600 seconds, keeping it above the refresh interval and consistent across redundant Signal instances.

Revoke a join token with the same trusted issuer key family used to mint it:

```bash
ipars token revoke \
  --control-plane-url https://203.0.113.10:8443 \
  --cluster-id <cluster-id> \
  --nonce <token-nonce> \
  --issuer-private-key-path ./issuer.key \
  --issuer-key-id root
```

The control plane accepts only fresh Ed25519-signed revocations from its configured issuer key ring. Keep overlapping old/new issuer public keys configured until tokens from the old key no longer need revocation.

## Join Nodes

Use file-backed tokens for agents:

```bash
iparsd agent \
  --join-token-path /etc/ipars/join.token \
  --state-path /var/lib/ipars/agent.json \
  --runtime-backend linux-command \
  --apply-peer-map
```

The Agent API listens on `127.0.0.1:9780` by default. To bind it to a non-loopback address, create a separate owner-only management token and pass `--api-bearer-token-path /etc/ipars/agent-api.token`; startup rejects non-loopback listeners without a valid 32-512 byte printable ASCII token. All `/v1/*` routes and `/metrics` then require `Authorization: Bearer <token>`, while `/healthz` remains available for orchestration probes.

For a real `--apply-peer-map` runtime, keep `--stun-bind` and
`--wireguard-listen-port` on the same nonzero UDP port. The agent performs its
initial STUN probe before configuring the WireGuard interface, then configures
the interface to listen on that same port. For example, use
`--stun-bind 0.0.0.0:51820 --wireguard-listen-port 51820`. This preserves the
local-port relationship needed by port-preserving NATs; relay fallback remains
required where direct traversal is not possible.

For validation without host route mutation:

```bash
iparsd agent \
  --join-token-path /etc/ipars/join.token \
  --state-path /var/lib/ipars/agent.json \
  --runtime-backend dry-run
```

## Docker

The base Compose stack starts PostgreSQL, control plane, signal, STUN, relay, and agent services. The agent continuously applies its peer map after joining so the selected WireGuard and route backends configure the data plane. Docker Engine API access is not mounted into the agent unless the discovery override is used; the override mounts the selected Docker socket read-only and does not create a missing host socket path.

The bundled agent uses `IPARS_AGENT_STUN_BIND=0.0.0.0:51821` and
`IPARS_AGENT_WIREGUARD_LISTEN_PORT=51821`, deliberately separate from the
bundled relay UDP listener on `51820`. Override the two variables together with
the same nonzero port for a real data-plane deployment. The Compose smoke uses
an ephemeral STUN bind only because its two host-network agents run with the
non-mutating `dry-run` backend.

Before starting the bundled stack, place the signed join token at
`docker/join.token` and create distinct Control Plane, Signal, STUN, Relay, and Agent management tokens:

```bash
umask 077
head -c 32 /dev/urandom | base64 > docker/control-plane-operator-api.token
head -c 32 /dev/urandom | base64 > docker/signal-operator-api.token
head -c 32 /dev/urandom | base64 > docker/stun-operator-api.token
head -c 32 /dev/urandom | base64 > docker/relay-operator-api.token
head -c 32 /dev/urandom | base64 > docker/agent-api.token
```

Set `IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE`, or
`IPARS_AGENT_API_BEARER_TOKEN_FILE` when a token lives at a different host path.
Keep all five credentials distinct, and keep the Relay operator token separate from `IPARS_RELAY_ADMISSION_BEARER_TOKEN`.

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
create host networking resources. Rootless deployments are always forced to the
same `dry-run` backend because their Compose override intentionally removes the
TUN device and kernel capabilities required by a WireGuard data plane. Use a
rootful agent for production WireGuard connectivity.

Run the repeatable Compose smoke with:

```bash
scripts/docker-smoke.sh
```

## Kubernetes

The Helm chart deploys a node-underlay VPN agent, not a CNI. It can advertise Kubernetes Service/API routes through a route-provider agent and optional RBAC-backed Service discovery.

Its production defaults set `agent.wireguardListenPort: 51820` and
`agent.stunBind: "0.0.0.0:51820"`. Helm rejects zero ports and mismatched values
before rendering the DaemonSet.

`ipars k8s install` can override either side with
`--agent-wireguard-listen-port` or `--agent-stun-bind`; the omitted value is
derived from the supplied port, while conflicting explicit values are rejected
before Helm is invoked.

Prepare separate join and Agent API token files. The install plan creates one
Kubernetes Secret with distinct keys and rejects key reuse:

```bash
kubectl -n ipars-system create secret generic ipars-join-token \
  --from-file=token=./join.token \
  --from-file=agent-api-token=./agent-api.token
```

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
export IPARS_AGENT_API_BEARER_TOKEN_PATH=/etc/ipars/agent-api.token
ipars status --agent-url http://127.0.0.1:9780
ipars --control-plane-operator-api-bearer-token-path /etc/ipars/control-plane-operator-api.token status --control-plane-url http://127.0.0.1:8443
ipars --agent-state-path /var/lib/ipars/agent.json peers --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars --agent-state-path /var/lib/ipars/agent.json routes --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars path status --agent-url http://127.0.0.1:9780
ipars --agent-state-path /var/lib/ipars/agent.json path status --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars path events --agent-url http://127.0.0.1:9780
ipars relay status --relay-url http://127.0.0.1:9580
ipars relay probe --relay-url http://127.0.0.1:9580 --relay-udp 127.0.0.1:51820 --relay-admission-bearer-token <relay-secret> --send-invalid-credential
ipars stun probe --stun-server 127.0.0.1:3478
```

Prometheus-style metrics are exposed by control-plane, signal, STUN, relay, and agent HTTP services. Agent metrics use the same Bearer authentication as its `/v1/*` routes when configured. Control Plane, Signal, STUN, and Relay metrics require distinct operator Bearer credentials and are absent when those credentials are not configured. Relay `/v1/status` remains public for capability refresh, while relay admission uses its separate optional credential. Control-plane metrics include accepted/rejected WireGuard key-rotation and node-removal counters. OTLP HTTP/protobuf export is available with `--otel-enabled --otel-endpoint http://collector:4318`.

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
