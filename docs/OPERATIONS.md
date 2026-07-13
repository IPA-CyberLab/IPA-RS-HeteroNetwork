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

All file-backed daemon Bearer credentials must be direct regular files with one hard link, an owner-read bit, and no group or world permissions. Use mode `0400` or `0600`; the `umask 077` examples in this runbook create compliant files. The daemon rejects a final symlink component and verifies file identity across open/read, so mount the credential file itself rather than a symlink managed outside the deployment's trust boundary.

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

Join-token bootstrap lists are capped at 32 endpoints total and 8 per service kind. Each URL is capped at 2048 bytes and must be an absolute typed endpoint without userinfo, query, fragment, control characters, unusable numeric addresses, or normalized duplicates. Agents also cap the merged explicit and token-derived STUN set at 8 unique usable resolved socket addresses; publish multiple independent endpoints within these bounds for failover.

## Join Nodes

Before placing credentials or starting the service, validate the intended host runtime with the same data-plane flags:

```bash
iparsd agent \
  --preflight-only \
  --runtime-backend linux-command \
  --apply-peer-map \
  --wireguard-backend kernel-netlink \
  --route-backend kernel-netlink \
  --linux-netns edge-a
```

Preflight-only validates static settings plus required commands, capabilities, forwarding sysctls, netlink protocols, sockets, files, and namespace entries. It exits before reading join/API credentials, creating the Agent state file, contacting STUN/control/Signal, mutating the data plane, or binding a listener. Credential validity and service reachability are therefore still checked by normal startup.

Use file-backed tokens for agents:

```bash
iparsd agent \
  --join-token-path /etc/ipars/join.token \
  --state-path /var/lib/ipars/agent.json \
  --runtime-backend linux-command \
  --apply-peer-map
```

The Agent API listens on `127.0.0.1:9780` by default. To bind it to a non-loopback address, create a separate owner-only management token and pass `--api-bearer-token-path /etc/ipars/agent-api.token`; startup rejects non-loopback listeners without a valid 32-512 byte printable ASCII token. All `/v1/*` routes and `/metrics` then require `Authorization: Bearer <token>`, while `/healthz` remains available for orchestration probes.

Agent outbound HTTP uses a 5-second connect timeout and a 30-second whole-request timeout by default. Tune them with `--http-connect-timeout-seconds` / `IPARS_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS` and `--http-request-timeout-seconds` / `IPARS_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS`; both must be 1-3600 seconds and connect must not exceed request. The bounds apply per attempted endpoint to join, heartbeat, peer-map, Signal, Relay, lifecycle, Docker API, and Kubernetes API calls. `ipars docker install --agent-http-*-timeout-seconds` and `ipars k8s install --agent-http-*-timeout-seconds` propagate the same settings into Compose and Helm.

For a real `--apply-peer-map` runtime, keep `--stun-bind` and
`--wireguard-listen-port` on the same nonzero UDP port. The agent performs its
initial STUN probe before configuring the WireGuard interface, then configures
the interface to listen on that same port. For example, use
`--stun-bind 0.0.0.0:51820 --wireguard-listen-port 51820`. This preserves the
local-port relationship needed by port-preserving NATs; relay fallback remains
required where direct traversal is not possible.

With a real `--apply-peer-map` backend, Signal candidates and successful UDP
hole-punch sends are provisional. The agent reads each WireGuard peer's current
endpoint, latest handshake, and RX/TX counters through generic netlink for the
kernel backend or bounded `wg show` field queries for command/userspace
backends. It promotes a path to `DIRECT_*` only after the candidate endpoint is
active and a post-switch handshake or transfer increase is observed. During a
relay-to-direct probe, the existing relay session and forwarder remain available;
an unverified path returns to `RELAY`, or `UNREACHABLE` when no relay is
admissible. `--direct-path-probe-timeout-seconds` defaults to 120 seconds and
must cover at least one peer-map poll plus two Signal intervals;
`--direct-handshake-max-age-seconds` defaults to 180 seconds and must be at least
the Signal interval. The corresponding environment variables are
`IPARS_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS` and
`IPARS_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS`. Docker and Kubernetes install
plans expose the same settings as `--agent-direct-path-probe-timeout-seconds`
and `--agent-direct-handshake-max-age-seconds`. Monitor
`ipars_agent_direct_path_probes_started_total`,
`ipars_agent_direct_path_probes_confirmed_total`, and
`ipars_agent_direct_path_probes_timeout_total`; a rising timeout ratio indicates
candidate reachability, NAT classification, firewall, or keepalive problems.

After a path is active, the agent measures its actual WireGuard data-plane
quality without operator input. A fixed 32-byte UDP challenge is sent to the
peer VPN IP on `--peer-probe-port` (default `51821`); the responder binds only
the local VPN IP, answers only source VPN IPs in the current peer map, returns
exactly one same-size response, validates nonce and sequence, and applies a
per-peer request rate limit. Only lazy-connect-active or pinned paths are
measured, with bounded concurrency, so this does not create a full-mesh probe
loop. Defaults are five samples every 30 seconds, a 500 ms response timeout, a
20 ms inter-sample delay, concurrency 32, and 100 responder requests per second
per peer. Configure these through `IPARS_AGENT_PEER_PROBE_*` or the matching
`--peer-probe-*` flags; `--disable-peer-probe` disables both measurement and the
responder. `ipars docker install` and `ipars k8s install` expose the same values
as `--agent-peer-probe-*` and `--disable-agent-peer-probe`. Install plans disable
the probe automatically for rootless/dry-run agents or disabled peer-map sync,
where no real WireGuard data plane exists.

Each completed round calculates mean RTT, loss in parts per million, mean
absolute RTT jitter, and a bounded stability value smoothed only across the
same path fingerprint. A path change during measurement discards the round.
The latest observation is included in the node-identity-signed Signal request;
Signal validates sample/loss consistency and applies it only when state,
candidate address or relay node, and freshness all match the selected path.
`--peer-probe-observation-max-age-seconds` and
`IPARS_SIGNAL_PATH_QUALITY_OBSERVATION_TTL_SECONDS` default to 120 seconds.
Docker install plans set the Agent observation age and bundled Signal TTL from
the same `--agent-peer-probe-observation-max-age-seconds` value. Kubernetes
installs must keep the external Signal service TTL at least as fresh as the
rendered Agent observation age.
Compose uses probe port `51822` because its bundled WireGuard listener uses
`51821`; Helm uses WireGuard `51820` and probe `51821`. Monitor
`ipars_agent_peer_probe_*`, `ipars_agent_path_quality_observations`, and
`ipars_signal_path_quality_observations_total{status=...}` in Prometheus, or the
equivalent OTLP instruments.

For rolling upgrades, deploy the new Signal service before enabling upgraded
agents: older Signal versions do not include the optional observation in their
signature payload and therefore reject requests that carry it. New Signal
versions continue to accept older agents because the absent field serializes
identically to the previous signed payload.

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
`docker/join.token` and create distinct Control Plane, Signal, STUN, Relay, and Agent management tokens plus a separate Relay admission token:

```bash
umask 077
head -c 32 /dev/urandom | base64 > docker/control-plane-operator-api.token
head -c 32 /dev/urandom | base64 > docker/signal-operator-api.token
head -c 32 /dev/urandom | base64 > docker/stun-operator-api.token
head -c 32 /dev/urandom | base64 > docker/relay-operator-api.token
head -c 32 /dev/urandom | base64 > docker/agent-api.token
head -c 32 /dev/urandom | base64 > docker/relay-admission.token
```

Set `IPARS_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_STUN_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_RELAY_OPERATOR_API_BEARER_TOKEN_FILE`,
`IPARS_RELAY_ADMISSION_BEARER_TOKEN_FILE`, or
`IPARS_AGENT_API_BEARER_TOKEN_FILE` when a token lives at a different host path.
Keep all six credentials distinct. Compose mounts the one Relay admission file into both Relay and Agent without copying its value into service environment variables.

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
kernel capabilities required by route and kernel-WireGuard mutation and does
not provide an unprivileged userspace data plane. Use a rootful agent for
production WireGuard connectivity.

Run the repeatable Compose smoke with:

```bash
scripts/docker-smoke.sh
```

The suite first validates the full management stack with non-mutating Agents, then starts a second stack with two concurrently initialized Control Planes sharing PostgreSQL, paired Signal/STUN services in the two Control Plane network namespaces, and two production `linux-command` Agents. The production phase discovers isolated IPv4 and dual-stack IPv6 workload bridge CIDRs before signing a multi-bootstrap route-authorized token, requires kernel WireGuard support, and verifies addresses, `AllowedIPs`/routes, handshakes, counters, and bidirectional workload HTTP. It stops the primary namespace, checks all three secondary service endpoints, repeats both address-family traffic checks, then changes a live Docker subnet through surviving heartbeat and peer-map reconciliation. Finally, it starts a third dry-run Agent only after failure and requires secondary STUN discovery, registration with a new VPN IP, Signal registration, heartbeat, peer-map sync, and an identity-signed peer-map query against the secondary Control Plane. The kernel Agents do not mount `/dev/net/tun`; that device is only needed when an operator deliberately selects a userspace WireGuard implementation that consumes TUN.

## Kubernetes

The Helm chart deploys a node-underlay VPN agent, not a CNI. It can advertise Kubernetes Service/API routes through a route-provider agent and optional RBAC-backed Service discovery.

Its production defaults set `agent.wireguardListenPort: 51820` and
`agent.stunBind: "0.0.0.0:51820"`. Helm rejects zero ports and mismatched values
before rendering the DaemonSet.

`ipars k8s install` can override either side with
`--agent-wireguard-listen-port` or `--agent-stun-bind`; the omitted value is
derived from the supplied port, while conflicting explicit values are rejected
before Helm is invoked.

Every DaemonSet agent advertises its own discovered Service/API routes by default.
For a dedicated remote routing peer, set `agent.routeProvider=false` and
`serviceExposure.routeProviderNodeId=<node-id>` together; the chart rejects both
local-plus-remote ownership and a disabled local provider without a remote provider.
The CLI emits this pair automatically when `--route-provider-node-id` is used.
Kernel WireGuard needs kernel support plus `NET_ADMIN`/`NET_RAW`, but no
`/dev/net/tun` device mount.

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
pull and run the disposable-namespace smoke. It verifies Helm's DaemonSet against real
control-plane, signal, and STUN services, signed token registration, namespace-scoped
Service discovery RBAC, agent peer-map synchronization, control-plane health metrics,
and, by default, a cross-agent WireGuard handshake plus encrypted HTTP traffic:

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
production `linux-command` backend, then removes the cluster and generated image:

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
- New joins, peer-map refreshes, policy changes, route changes, key rotations, and node removals require at least one reachable control plane.
- Agents keep ordered control-plane and signal endpoint lists and retry failover endpoints without stopping the local data-plane loop. Connect and whole-request deadlines bound each endpoint attempt, including peers that accept TCP but never return HTTP.
- Signal failure prevents new path negotiation and hole-punch planning; existing selected paths remain in local runtime state until they expire or are replaced.
- Relay failure causes affected relay paths to renew or renegotiate. If direct candidates are available, path scoring can promote back to direct.
- Redundant control-plane instances can share durable SQL state. PostgreSQL schema initialization is transaction-locked so instances can start concurrently. Signal and STUN replicas must not share the primary's sole failure domain. The load harness verifies peer-map, path-state, relay-candidate, and existing relay dataplane survival after one process is stopped; the Docker gate additionally proves existing kernel-WireGuard IPv4/IPv6 traffic, post-failover route reconciliation, and a completely new Agent join through surviving Control Plane/Signal/STUN endpoints.

## Smoke Gates

Use these before publishing an operational change:

```bash
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
scripts/helm-smoke.sh
scripts/docker-smoke.sh
IPARS_LOAD_SMOKE_BUILD_DAEMON=1 scripts/load-smoke.sh
```

Privileged Linux hosts can also run:

```bash
scripts/netns-smoke.sh
```

That suite requires network namespace creation privileges, runs the actual `iparsd agent --preflight-only` path for kernel-netlink and (when `wg` is installed) command backends, and runs the routed peer-quality UDP probe alongside route, WireGuard, hole-punch, and relay-fallback checks. Set `IPARS_NETNS_SMOKE_EBPF_OBJECT_PATH` to a built object to make real tracepoint attach and ring-buffer event delivery a required part of the suite; CI always sets it. The suite may require `wireguard-tools`, kernel WireGuard support, `iptables`, tracefs, BPF privileges, and forwarding sysctls.

`.github/workflows/ci.yml` runs the Rust/MSRV, 3/10/1000-node plus daemon-failover load, Helm, Docker Compose, privileged namespace, and two-node kind suites as independent CI jobs for every pull request and `master` push. The privileged namespace job installs pinned eBPF Rust and linker tools, builds the repository object, requires real syscall tracepoint attach plus `sendto(2)` delivery and cgroup-only IPv4/IPv6 TCP `connect(2)`, TCP established/closing sockops state, and UDP send-message delivery with kernel-derived endpoint metadata, and installs the matching Ubuntu kernel module package only when WireGuard is not already available. The Kubernetes job downloads fixed kind, kubectl, and Helm versions and verifies each binary archive against its pinned SHA-256 before creating the disposable cluster.
