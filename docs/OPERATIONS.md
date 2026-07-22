# Operations Runbook

This runbook covers the current operational path for a Linux-first HeteroNetwork deployment.

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
  --allowed-route 10.250.0.0/16 \
  --allow-relay \
  --unlimited-uses \
  --spawn-daemons \
  --daemon-state-dir ./heteronetwork-state
```

With `--spawn-daemons`, spawned services receive only a fixed system `PATH` and `C` locale rather than the operator's full environment. `init` passes the selected Control Plane listener to Signal and waits for each service's `/healthz` endpoint before returning; `--daemon-ready-timeout-seconds` bounds that wait. If a service exits or never becomes ready, already-started services are terminated and the per-service log path is included in the error. When `--allow-relay` is set, `init` also creates an owner-only relay-agent state/token and starts a dry-run relay-agent after the four core services are ready; it registers the same relay Node ID used by the UDP Relay and keeps the capability fresh through signed heartbeats. The Control Plane receives the operator credential by file path, not token value in argv. Its policy and metric routes are absent when no operator credential is configured. The bootstrap state directory and `logs/` directory are made owner-only, and service log files must be regular, non-symlink, non-hardlinked owner-only files. Without `--spawn-daemons`, run the emitted `iparsd control-plane`, `iparsd signal`, `iparsd stun`, and `iparsd relay` commands manually or under systemd. When `--allow-relay` is set, `init` also emits an `iparsd agent` relay-agent command with a one-use state/token, so the manually supervised Relay publishes its capability to Control Plane.

All file-backed daemon Bearer credentials must be direct regular files with one hard link, an owner-read bit, and no group or world permissions. Use mode `0400` or `0600`; the `umask 077` examples in this runbook create compliant files. The daemon rejects a final symlink component and verifies file identity across open/read, so mount the credential file itself rather than a symlink managed outside the deployment's trust boundary.

When `--allow-relay` is used with `--spawn-daemons`, `init` creates or validates the owner-only relay admission credential at `--relay-admission-bearer-token-path` or `<daemon-state-dir>/relay-admission.token`. Without `--spawn-daemons`, `--relay-admission-bearer-token-path` is required so an emitted manual Relay command cannot accidentally run without admission authentication; the parent directory must already exist and the file is created or validated there. The value is passed to Relay and relay-agent by file path only and is never included in daemon argv or JSON output.

Signal metrics also require a distinct operator token. For a manually supervised Signal service, generate one with `umask 077`, pass `--operator-api-bearer-token-path /etc/heteronetwork/signal-operator-api.token`, and configure the same credential in the metrics scraper. If omitted, Signal metric routes remain absent while health and signed protocol routes continue operating.

STUN HTTP metrics require another distinct token through `iparsd stun --operator-api-bearer-token-path /etc/heteronetwork/stun-operator-api.token`. Omitting it removes only `/metrics` and `/v1/metrics`; UDP Binding, RFC5780 probes, and `/healthz` remain available.

Signal must be able to reach at least one control-plane API to authenticate node registrations. Configure repeated `iparsd signal --control-plane-url http://control-plane-a:8443 --control-plane-url http://control-plane-b:8443` values, or the comma-delimited `HETERONETWORK_SIGNAL_CONTROL_PLANE_URLS` environment variable. The default authenticated-membership TTL is 90 seconds; agents refresh every 30 seconds. Tune it with `--node-auth-ttl-seconds` or `HETERONETWORK_SIGNAL_NODE_AUTH_TTL_SECONDS` between 1 and 3600 seconds, keeping it above the refresh interval and consistent across redundant Signal instances.

## Deploy Active-Active Public Nodes

Use the units and environment contract in [`deploy/systemd`](../deploy/systemd/README.md) on at least two independently reachable hosts. Both Control Planes must use the same cluster ID, issuer public key, policy, and PostgreSQL database. Each host uses a unique service instance and Relay node ID and advertises its own externally reachable Control Plane, Signal, STUN, and Relay URLs. Keep the issuer private key offline; public nodes need only the public key.

To expose **Add device** in the Web UI, create a separate enrollment signer and
install the same root-owned key as
`/etc/credstore/node-enrollment-issuer.key` on every Control Plane replica. The
packaged unit imports that file with systemd `LoadCredential=` so only the
Control Plane receives a readable copy. Configure
`HETERONETWORK_NODE_ENROLLMENT_ENABLED=true`, a distinct
`HETERONETWORK_NODE_ENROLLMENT_ISSUER_KEY_ID`, the bounded
`HETERONETWORK_NODE_ENROLLMENT_MAX_TTL_SECONDS`, and the release artifact path in
`HETERONETWORK_NODE_ENROLLMENT_BINARY_PATH`. Do not copy the root issuer private
key to these nodes. A direct non-systemd invocation must instead set
`HETERONETWORK_NODE_ENROLLMENT_ISSUER_PRIVATE_KEY_PATH`. Enrollment issuance
requires authenticated management access
and two distinct active URLs for Control Plane, Signal, and STUN, plus two Relay
URLs when relay permission is requested.

The four local services form one advertised failure domain. The packaged Control Plane unit is bound to Signal, STUN, and Relay, so stopping or losing any of them stops the local lease renewal. A failed instance disappears from `/v1/admin/services` after `HETERONETWORK_SERVICE_LEASE_TTL_SECONDS`. Use a managed HA PostgreSQL service or a quorum deployment outside the two application failure domains; a single database on either public host makes whole-host failover asymmetric.

Mint join tokens from the active directory instead of manually copying endpoint lists:

```bash
ipars token create \
  --service-directory-url https://public-a.example:8443 \
  --control-plane-operator-api-bearer-token-path ./control-plane-operator-api.token \
  --issuer-private-key-path ./issuer.key \
  --issuer-key-id root \
  --allowed-route 10.250.0.0/16 \
  --allow-relay \
  --unlimited-uses
```

The command requires two active endpoints for Control Plane, Signal, and STUN, and two Relay endpoints when `--allow-relay` is present. `--allow-degraded-service-directory` exists for deliberate disaster recovery, not routine provisioning. Agents persist the directory learned from registration, heartbeat, and peer-map responses, prefer those active entries on every later loop, and retain signed token entries as fallback seeds.

The Web UI workflow performs the same HA directory check, signs and records the
token in the shared ledger, and returns a Linux x86_64 install command. The
generated installer checks root/systemd prerequisites, downloads the pinned
daemon through the still-active token, verifies SHA-256, enrolls once into an
owner-only state file, deletes the token, and enables the Agent service with an
event-driven conntrack detector that activates lazy peers on first traffic. A
single-use token cannot download the artifact again after its successful join;
expired, revoked, exhausted, or unknown tokens are rejected.

An idle ACL-visible peer remains installed in WireGuard as a passive quarantine
entry with its overlay `/32` AllowedIP and host route, a loopback discard hold
endpoint, no keepalive, and a public key distinct from the advertised real peer
key. The host route selects the overlay source address for the first socket,
and the local hold endpoint keeps that socket retryable without sending a
handshake outside the host. The quarantine key also prevents an incoming real
peer packet from reactivating the entry through WireGuard endpoint roaming. On
activation the Agent replaces the quarantine entry with the real peer at the
selected endpoint, resetting any hold-endpoint handshake timer. The initiating
Agent publishes the actual local packet-activity timestamp as a bounded marker in its signed
path snapshot; any healthy Control Plane instance returns a fresh marker as an
intent to the target Agent, which immediately wakes its Signal and peer-map
loops. This reciprocal activation allows the first one-sided flow to establish
a path without keeping an all-to-all set of active sessions. The intent expires
with the cluster lazy-connect idle timeout, a repeated or remote intent is never
republished as new local activity, and the Agent excludes its configured UDP
peer-probe port from packet-flow activation.
Conntrack-backed detectors use only the initiating/original tuple, so inbound
reply tuples do not wake an otherwise idle peer.
Tailscale routing-bypass traffic marked `0x80000/0xff0000` is likewise counted
as `internal_control_traffic` and cannot trigger a path. The event detector also
uses `NETLINK_SOCK_DIAG` to recognize marked UDP source sockets when their
locally NATed conntrack entry itself remains unmarked.
Once an initiator establishes the authenticated WireGuard receive path, its
first valid wake-intent peer-probe request wakes a passive target without
waiting for the next heartbeat. The Agent emits wake intent only for recent
local application activity, sends it after a short endpoint-application bound,
and does not wait for pre-existing handshake evidence. Quality-only probes and
probes from a remotely activated peer do not extend either peer's idle timeout.

The generated Agent service uses conntrack NEW/UPDATE events plus a one-second
bounded counter reconciliation. Event delivery handles new flows immediately;
the counter pass catches traffic on a conntrack entry that existed before an
Agent restart. Its first snapshot is baseline-only, so an unchanged stale entry
does not wake a peer.

Before declaring failover ready, verify both public APIs report two active instances and `ipars_control_plane_ha_ready 1`. Stop `ipars-public-node.target` on one host, wait one lease TTL, and verify the survivor reports one instance, existing WireGuard traffic continues, and a fresh Agent can register using the previously minted HA token. Restart the target and require HA readiness to return to `1`.

Revoke a join token with the same trusted issuer key family used to mint it:

```bash
ipars token revoke \
  --control-plane-url https://203.0.113.10:8443 \
  --cluster-id <cluster-id> \
  --nonce <token-nonce> \
  --issuer-private-key-path ./issuer.key \
  --issuer-key-id root
```

The control plane accepts only fresh Ed25519-signed revocations from its configured issuer key ring. Keep overlapping old/new issuer public keys configured until tokens from the old key no longer need revocation. The nonce does not need to have joined before this command: the store persists a tombstone and rejects a later first admission. Redundant Control Planes serialize issue, admission, and revocation for each cluster/nonce with an SQLite writer transaction or PostgreSQL transaction advisory lock. A concurrent join is either recorded before revocation or rejected after it, and `RevokeTokenResponse.record` is absent until full token claims are observed.

Join-token signatures must be canonical standard Base64 encoding of exactly one 64-byte Ed25519 signature, which is 88 encoded bytes including padding. CLI, Agent, verifier, and Control Plane inputs reject malformed, non-canonical, wrong-length, and oversized signature envelopes before issuer lookup or verification. Cluster, issuer, key, role, nonce, claim-tag, and policy-tag identifiers are capped at 255 bytes and must use path-safe ASCII. Claim and policy tag sets are each capped at 64 entries. Policy route allowlists are capped at 256 safe canonical, unique, non-overlapping CIDRs. The validity window must be positive and cannot exceed the 30-day TTL plus the CLI's 5-second `not_before` skew allowance. Bootstrap lists are capped at 32 endpoints total and 8 per service kind; each URL is capped at 2048 bytes and must be an absolute typed endpoint without userinfo, query, fragment, control characters, unusable numeric addresses, or normalized duplicates. Agents cap each selected STUN set at 8 unique usable resolved socket addresses; publish multiple independent globally routable endpoints within these bounds for self-hosted discovery and failover.

The same 88-byte canonical signature envelope applies to heartbeat, WireGuard key rotation, node removal, token revocation, direct Control Plane node queries, and Signal upsert/path/hole-punch requests. A malformed or oversized envelope is rejected as an input-shape error rather than retried as an authentication failure; inspect the service response and correct the producer or transport encoding before retrying.

All Ed25519 identity/issuer and WireGuard private/public keys must be canonical standard Base64 encoding of exactly 32 bytes, or 44 encoded bytes including padding. Control Plane startup rejects malformed, oversized, non-canonical, wrong-length, or weak primary/trusted issuer public keys. Registration and rotation reject weak Ed25519 or low-order WireGuard public keys. Agent state load/save verifies both private-to-public derivations, the identity-derived node ID, and timestamp order; an inconsistent state file is not repaired automatically because choosing one conflicting key as authoritative could silently change node identity or data-plane credentials. Restore the complete state from backup or remove it and perform an intentional fresh join.

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
  --join-token-path /etc/heteronetwork/join.token \
  --state-path /var/lib/heteronetwork/agent.json \
  --runtime-backend linux-command \
  --apply-peer-map
```

The Agent prefers globally routable STUN endpoints from its persisted service
directory and signed token. A directory containing only private or
`100.64.0.0/10` endpoints cannot reveal the Internet-facing address, so the
default binary falls back to these configurable public probes:

```bash
iparsd agent \
  --public-stun-url udp://stun.cloudflare.com:3478 \
  --public-stun-url udp://stun.cloudflare.com:53 \
  --join-token-path /etc/heteronetwork/join.token \
  --apply-peer-map
```

Set `HETERONETWORK_AGENT_PUBLIC_STUN_URL` to a comma-separated replacement.
Use `--disable-public-stun-fallback` only for an offline/private lab; such a
node can still report local candidates but cannot be classified as public.
Explicit `--stun-server IP:PORT` values override automatic source selection.
The Web UI shows `Private` rather than `Public` when a no-NAT observation uses
RFC1918, CGNAT/Tailscale, loopback, link-local, documentation, benchmarking, or
another special-purpose address.

Self-hosted public STUN services should set
`HETERONETWORK_STUN_ALTERNATE_LISTEN` and expose both UDP listeners. Agents use
the RFC 5780 `OTHER-ADDRESS` response to probe the alternate listener with the
same socket, so one reachable public service is sufficient to classify NAT
mapping and filtering behavior. Multiple public services remain necessary for
control-plane and STUN failover.

For one-shot CLI provisioning, persist the generated node credentials before
starting the Agent daemon:

```bash
ipars join "$(cat ./join.token)" \
  --state-path /var/lib/heteronetwork/agent.json
iparsd agent \
  --state-path /var/lib/heteronetwork/agent.json \
  --control-plane-url https://203.0.113.10:8443 \
  --apply-peer-map
```

`ipars join` never prints private keys. It persists the accepted NodeRecord and
bootstrap endpoints with the credentials, so a later `iparsd agent` startup
can resume the registration without reusing the single-use join token. It
rejects an existing state path instead of silently replacing another node
identity; use a new state path for a new node. `--dry-run` validates the token
and bootstrap selection but does not write state.

### Join macOS clients

Before issuing a client link, register at least one Linux node with role
`gateway` and a fresh reachable IPv6, public UDP, or STUN-reflexive WireGuard
candidate. The gateway must forward overlay traffic. Persist IPv4 forwarding on
the gateway, then apply the equivalent IPv6 setting if the overlay uses IPv6:

```bash
sudo install -m 0644 /dev/stdin /etc/sysctl.d/99-heteronetwork-client-gateway.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sudo sysctl --system
```

Allow forwarding from the managed WireGuard interface back to that interface
and to each advertised destination according to the host firewall policy. The
selected gateway terminates the client's only WireGuard peer and forwards to
the mesh; other nodes route the client host prefix back through that gateway.
Do not advertise a default route solely for client access.

Enable the dedicated enrollment signer as described under Web Management UI,
keep at least two Control Plane endpoints active, then select **Add device** ->
**macOS client** in the Web UI. Open the returned `heteronetwork://` link on a
Mac with the native app installed. The token is single-use. The app installs a
signed Network Extension profile, refreshes the gateway map immediately before
connecting, and stores private key material in the shared device-only Keychain.
Control-only clients are intentionally absent from the normal node table; use
`ipars_control_plane_clients` or `client_count` to observe their allocation.

The Agent API listens on `127.0.0.1:9780` by default. To bind it to a non-loopback address, create a separate owner-only management token and pass `--api-bearer-token-path /etc/heteronetwork/agent-api.token`; startup rejects non-loopback listeners without a valid 32-512 byte printable ASCII token. All `/v1/*` routes and `/metrics` then require `Authorization: Bearer <token>`, while `/healthz` remains available for orchestration probes.

On the default loopback listener, open `http://127.0.0.1:9780/ui/` for the
failover-capable console. An enrolled Agent learns leased Web UI origins from
registration and heartbeat responses. On a fresh state file, enter one initial
IP address or URL in the connection form; the Agent validates `/ui/config`
before caching it. Enable **OAuth 2.0 Device Authorization Grant** on the
Keycloak public client; Agent-hosted consoles use that flow so neither localhost
nor changing public IPs need redirect-URI or Web-Origin wildcards. Direct
Control Plane consoles retain authorization-code PKCE. The local UI is
intentionally disabled when the Agent listener is bound to a non-loopback
address.

The generated node installer starts `heteronetwork-gateway.service` with a
checksum-pinned Caddy 2.11.4 binary. Keep inbound TCP 80 and 443 available on nodes
that may become public and allow outbound ACME traffic. The service starts with
no public listener. Fresh public STUN classification causes the Agent to load
an `https://IP/` configuration through the protected Unix admin socket;
private/stale classification removes it. Inspect the current phase in the Web
UI endpoint control or with
`ipars_agent_public_web_gateway_phase{phase="ready"}`. Control Plane
`ipars_control_plane_active_services{kind="web_ui"}` and the Public nodes view
show only gateways that passed an external TLS/config probe. Generated node
install commands include those active gateways and can fetch the
join-token-protected script and binary through a surviving gateway. Public
nodes use the shorter of `HETERONETWORK_AGENT_NAT_DISCOVERY_INTERVAL_SECONDS` and
`HETERONETWORK_AGENT_PUBLIC_NAT_DISCOVERY_INTERVAL_SECONDS`; non-public nodes
retain the general interval so repeated filtering probes do not destabilize
active paths. Tune the remaining convergence stages with
`HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_RECONCILE_INTERVAL_SECONDS`, and the
Control Plane `HETERONETWORK_DYNAMIC_WEB_GATEWAY_*` lease/probe settings.

When a Control Plane cannot reach the public Keycloak address through NAT
hairpinning, keep `HETERONETWORK_WEB_OIDC_ISSUER_URL` public and set
`HETERONETWORK_WEB_OIDC_BACKCHANNEL_BASE_URL` to the trusted private Keycloak
realm URL. Only server-side token exchange and userinfo validation use this
backchannel; browsers continue to use the public OIDC endpoints.

Agent outbound HTTP uses a 5-second connect timeout and a 30-second whole-request timeout by default. Tune them with `--http-connect-timeout-seconds` / `HETERONETWORK_AGENT_HTTP_CONNECT_TIMEOUT_SECONDS` and `--http-request-timeout-seconds` / `HETERONETWORK_AGENT_HTTP_REQUEST_TIMEOUT_SECONDS`; both must be 1-3600 seconds and connect must not exceed request. The bounds apply per attempted endpoint to join, heartbeat, peer-map, Signal, Relay, lifecycle, Docker API, and Kubernetes API calls. `ipars docker install --agent-http-*-timeout-seconds` and `ipars k8s install --agent-http-*-timeout-seconds` propagate the same settings into Compose and Helm.

For a real `--apply-peer-map` runtime, keep `--stun-bind` and
`--wireguard-listen-port` on the same nonzero UDP port. The agent performs its
initial STUN probe before configuring the WireGuard interface, then configures
the interface to listen on that same port. For example, use
`--stun-bind 0.0.0.0:51820 --wireguard-listen-port 51820`. This preserves the
local-port relationship needed by port-preserving NATs; relay fallback remains
required where direct traversal is not possible. On restart, the Agent restores
the accepted candidates persisted in its registered-node state before
heartbeat and Signal registration, even when the surviving kernel WireGuard
interface already owns the shared port and the startup STUN bind cannot run.

With the default token or explicit STUN bootstrap, the Agent runs NAT discovery
before registration and refreshes non-public classifications every
`HETERONETWORK_AGENT_NAT_DISCOVERY_INTERVAL_SECONDS` seconds. A public
classification is refreshed at the shorter
`HETERONETWORK_AGENT_PUBLIC_NAT_DISCOVERY_INTERVAL_SECONDS` interval. The signed
join and heartbeat payloads carry mapping/filtering observations, confidence,
traversal strategy, and the derived connectivity state (`public`, `nat`,
`double_nat`, or `relay_only`). Control Plane retains the latest result and the
WebConsole reads the same state for its node table, drawer, and topology. Run
`scripts/nat-discovery-smoke.sh` to verify the three-node overview and heartbeat
update contract without manually assigning NAT labels.

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
`HETERONETWORK_AGENT_DIRECT_PATH_PROBE_TIMEOUT_SECONDS` and
`HETERONETWORK_AGENT_DIRECT_HANDSHAKE_MAX_AGE_SECONDS`. Docker and Kubernetes install
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
per peer. Configure these through `HETERONETWORK_AGENT_PEER_PROBE_*` or the matching
`--peer-probe-*` flags; `--disable-peer-probe` disables both measurement and the
responder. `ipars docker install` and `ipars k8s install` expose the same values
as `--agent-peer-probe-*` and `--disable-agent-peer-probe`. Install plans disable
the probe automatically for explicit dry-run agents or disabled peer-map sync,
where no real WireGuard data plane exists. The default rootless plan uses the
in-process BoringTun data plane and keeps the probe enabled unless explicitly
disabled.

Each completed round calculates mean RTT, loss in parts per million, mean
absolute RTT jitter, and a bounded stability value smoothed only across the
same path fingerprint. A path change during measurement discards the round.
The latest observation is included in the node-identity-signed Signal request;
Signal validates sample/loss consistency and applies it only when state,
candidate address or relay node, and freshness all match the selected path.
`--peer-probe-observation-max-age-seconds` and
`HETERONETWORK_SIGNAL_PATH_QUALITY_OBSERVATION_TTL_SECONDS` default to 120 seconds.
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
  --join-token-path /etc/heteronetwork/join.token \
  --state-path /var/lib/heteronetwork/agent.json \
  --runtime-backend dry-run
```

## Docker

The base Compose stack starts PostgreSQL, control plane, signal, STUN, relay, and agent services. The agent continuously applies its peer map after joining so the selected WireGuard and route backends configure the data plane. Docker Engine API access is not mounted into the agent unless the discovery override is used; the override mounts the selected Docker socket read-only and does not create a missing host socket path.

The bundled agent uses `HETERONETWORK_AGENT_STUN_BIND=0.0.0.0:51821` and
`HETERONETWORK_AGENT_WIREGUARD_LISTEN_PORT=51821`, deliberately separate from the
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

Set `HETERONETWORK_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_FILE`,
`HETERONETWORK_SIGNAL_OPERATOR_API_BEARER_TOKEN_FILE`,
`HETERONETWORK_STUN_OPERATOR_API_BEARER_TOKEN_FILE`,
`HETERONETWORK_RELAY_OPERATOR_API_BEARER_TOKEN_FILE`,
`HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_FILE`, or
`HETERONETWORK_AGENT_API_BEARER_TOKEN_FILE` when a token lives at a different host path.
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
  --docker-network heteronetwork_default
```

Set `--agent-runtime-backend dry-run` for Compose validation that must not create
networking resources. Rootless installs default to the in-process BoringTun
backend and add `docker/compose.rootless-dataplane.yaml`; the rootless engine
must be able to pass `/dev/net/tun` and grant `CAP_NET_ADMIN` inside the agent's
user namespace. The agent fails preflight if that substrate is unavailable.
The default rootless plan keeps Docker route discovery and container-CIDR route
application disabled. Use the explicit shared-namespace route-provider contract
when workload reachability is required:

```bash
docker network create --driver bridge ipars_workload
ipars docker install \
  --rootless \
  --agent-runtime-backend linux-command \
  --rootless-workload-network ipars_workload \
  --docker-container-namespace compose-edge \
  --docker-container-cidr 172.30.251.0/24
```

This adds `docker/compose.rootless-route-provider.yaml`. It puts the agent on
the Compose default network and the existing external workload network, starts
the bundled STUN sidecar in the agent namespace, and applies routes there with
no iptables mutation. For Docker API discovery, add
`--docker-discover-networks` and one or more `--docker-network` filters; the
generated plan adds `docker/compose.rootless-docker-discovery.yaml`, mounts the host
Docker socket read-only at `/run/heteronetwork/docker.sock`, and reconciles discovered
CIDR changes without creating, disconnecting, or deleting Docker networks. For a
remote Engine, use `--docker-api-url https://docker.example:2376` instead; the
plan omits the socket bind and accepts an optional bounded PEM trust bundle via
`--docker-api-ca-cert-path`, mounted read-only inside the Agent. For example,
when the external workload network is the route provider:

The remote rootless workload-network preflight requires host `curl`, checks the
external network on the Docker Engine that will run Compose, and then queries
the configured remote Engine API before startup. When a CA path is supplied,
the remote check passes it as `curl --cacert`; it does not depend on Docker CLI
certificate directory conventions.

```bash
ipars docker install \
  --rootless \
  --agent-runtime-backend linux-command \
  --rootless-workload-network ipars_workload \
  --docker-discover-networks \
  --docker-network ipars_workload
```

The API filter is matched by Docker network name or ID. To attach arbitrary
services from an existing Compose application, first render the complete
rootless configuration and generate an override for each service that should
share an Agent namespace:

```bash
docker compose -p edge \
  -f docker/compose.yaml \
  -f docker/compose.rootless.yaml \
  -f docker/compose.rootless-dataplane.yaml \
  -f docker/compose.rootless-route-provider.yaml \
  config --format json >"$XDG_RUNTIME_DIR/edge.compose.json"

scripts/rootless-compose-attach.sh \
  --config-json "$XDG_RUNTIME_DIR/edge.compose.json" \
  --agent-service agent \
  --workload-service api \
  --workload-service worker \
  --output "$XDG_RUNTIME_DIR/edge.workloads.yaml"

docker compose -p edge \
  -f docker/compose.yaml \
  -f docker/compose.rootless.yaml \
  -f docker/compose.rootless-dataplane.yaml \
  -f docker/compose.rootless-route-provider.yaml \
  -f "$XDG_RUNTIME_DIR/edge.workloads.yaml" \
  up -d
```

The generator sets `network_mode: service:agent`, clears the workload
`networks` declaration, preserves the existing Agent health dependency, and
moves explicit TCP/UDP published ports to the Agent. This keeps rootlesskit's
host port forwarder at the namespace boundary, so host-to-workload service
requests continue to work after the workload joins the Agent namespace. It
rejects missing published ports, duplicate target ports, and duplicate
published ports. Use a separate generated override for a workload attached to
each different Agent. The generated override must be passed after all rootless
route-provider overlays.

This is service-level host-to-container return-path support through published
ports; it is not an arbitrary unprivileged L3 route from the outer host into a
slirp4netns network. Workloads that require raw host-to-container IP routing
still need a privileged route-provider boundary. Use the explicit `dry-run`
runtime when only management/control-plane validation is needed.

Run the repeatable Compose smoke with:

```bash
scripts/docker-smoke.sh
```

On a host configured for rootless Docker, run the rootless dataplane preflight
with:

```bash
scripts/rootless-docker-smoke.sh
```

This starts an isolated rootless daemon, renders the rootless Compose overrides,
and runs the real Agent container with in-process BoringTun, `/dev/net/tun`, and
user-namespace `CAP_NET_ADMIN`. It does not replace the multi-node traffic smoke;
Docker route discovery remains a separate route-provider concern for rootless
deployments.

The suite first validates the full management stack with non-mutating Agents, then starts a second stack with two concurrently initialized Control Planes sharing PostgreSQL, paired Signal/STUN services in the two Control Plane network namespaces, and two production `linux-command` Agents. The production phase discovers isolated IPv4 and dual-stack IPv6 workload bridge CIDRs before signing a multi-bootstrap route-authorized token, requires kernel WireGuard support, and verifies addresses, `AllowedIPs`/routes, handshakes, counters, and bidirectional workload HTTP. It stops the primary namespace, checks all three secondary service endpoints, repeats both address-family traffic checks, then changes a live Docker subnet through surviving heartbeat and peer-map reconciliation. Finally, it starts a third dry-run Agent only after failure and requires secondary STUN discovery, registration with a new VPN IP, Signal registration, heartbeat, peer-map sync, and an identity-signed peer-map query against the secondary Control Plane. The kernel Agents do not mount `/dev/net/tun`; that device is only needed when an operator deliberately selects a userspace WireGuard implementation that consumes TUN.

## Kubernetes

The Helm chart deploys a node-underlay VPN agent, not a CNI. It can advertise Kubernetes Service/API routes through a route-provider agent and optional RBAC-backed Service discovery.

Its production defaults set `agent.wireguardListenPort: 51820` and
`agent.stunBind: "0.0.0.0:51820"`. Helm rejects zero ports and mismatched values
before rendering the DaemonSet.

When relay advertisement and relay Service exposure are enabled, the DaemonSet
starts an `iparsd relay` sidecar in the same Pod. Its UDP target defaults to
`51830` so it does not collide with the Agent's `51820` WireGuard/STUN listener;
the relay Service exposes the advertised UDP port `51820` and HTTP port `9580`.
The sidecar reads the Agent Node ID from the shared `agent.json` state file and
waits for that file before serving, so relay admission responses use the same
identity that the Agent advertises. It exposes `/healthz` for startup, readiness,
and liveness checks. Use a different relay target if the Agent listener is
customized, and keep the Service's external endpoint aligned with the value
passed to `--relay-public-endpoint`.

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
kubectl -n heteronetwork-system create secret generic heteronetwork-join-token \
  --from-file=token=./join.token \
  --from-file=agent-api-token=./agent-api.token
```

```bash
ipars k8s install \
  --release heteronetwork \
  --namespace heteronetwork-system \
  --join-token-secret heteronetwork-join-token \
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
relay sidecar health and relay UDP/HTTP Service reachability through ClusterIP and
NodePort, relay-candidate publication, and, by default, a cross-agent WireGuard
handshake plus encrypted HTTP traffic:

```bash
HETERONETWORK_K8S_SMOKE_IMAGE_REPOSITORY=registry.example.com/heteronetwork \
HETERONETWORK_K8S_SMOKE_IMAGE_TAG=ci \
scripts/k8s-live-smoke.sh
```

The runner requires `kubectl`, `helm`, `jq`, and either `HETERONETWORK_K8S_SMOKE_HETERONETWORK_BIN`
or Cargo. It refuses an existing namespace, removes its generated namespace by default,
and never writes the signed token to command-line arguments. Set
`HETERONETWORK_K8S_SMOKE_KEEP_RESOURCES=1` only when retaining diagnostics is required.
Set `HETERONETWORK_K8S_SMOKE_AGENT_RUNTIME_BACKEND=dry-run` only for clusters where the
real WireGuard backend is intentionally unavailable; the default is `linux-command`.

For kind-based CI or a local disposable cluster, the wrapper creates a control-plane
and worker node, builds and loads a local image, invokes the same live smoke with the
production `linux-command` backend, then removes the cluster and generated image:

```bash
scripts/kind-k8s-smoke.sh
```

It requires `docker`, `kind`, `kubectl`, `helm`, `jq`, and Cargo or
`HETERONETWORK_K8S_SMOKE_HETERONETWORK_BIN`. Set `HETERONETWORK_KIND_K8S_SMOKE_KEEP_CLUSTER=1` to retain
the cluster and live-smoke namespace for diagnostics.

## Health Checks

Common probes:

```bash
export HETERONETWORK_AGENT_API_BEARER_TOKEN_PATH=/etc/heteronetwork/agent-api.token
ipars status --agent-url http://127.0.0.1:9780
ipars --control-plane-operator-api-bearer-token-path /etc/heteronetwork/control-plane-operator-api.token status --control-plane-url http://127.0.0.1:8443
ipars --agent-state-path /var/lib/heteronetwork/agent.json peers --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars --agent-state-path /var/lib/heteronetwork/agent.json routes --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars path status --agent-url http://127.0.0.1:9780
ipars --agent-state-path /var/lib/heteronetwork/agent.json path status --control-plane-url http://127.0.0.1:8443 --node-id <node-id>
ipars path events --agent-url http://127.0.0.1:9780
ipars relay status --relay-url http://127.0.0.1:9580
ipars relay probe --relay-url http://127.0.0.1:9580 --relay-udp 127.0.0.1:51820 --relay-admission-bearer-token <relay-secret> --send-invalid-credential
ipars stun probe --stun-server 127.0.0.1:3478
```

Prometheus-style metrics are exposed by control-plane, signal, STUN, relay, and agent HTTP services. Agent metrics use the same Bearer authentication as its `/v1/*` routes when configured. Control Plane, Signal, STUN, and Relay metrics require distinct operator Bearer credentials and are absent when those credentials are not configured. Relay `/v1/status` remains public for capability refresh, while relay admission uses its separate optional credential. Control-plane metrics include accepted/rejected WireGuard key-rotation and node-removal counters. OTLP HTTP/protobuf export is available with `--otel-enabled --otel-endpoint http://collector:4318`.

## Failure Behavior

- Existing WireGuard data-plane state and relay sessions continue when the control plane is unavailable.
- New joins, peer-map refreshes, policy changes, route changes, key rotations, and node removals require at least one reachable control plane.
- A successful peer-map refresh serializes application and inventories the live WireGuard interface plus its IPv4/IPv6 main-table routes before changing peers. It removes restart-surviving or rotated keys outside the active/pinned map directly by public key and removes stale HeteroNetwork protocol-240 routes by their live CIDR/metric/protocol identity. Shape-compatible direct `boot`/`static` routes on that dedicated interface are migrated from older releases. An unreachable control plane does not trigger cleanup; an inventory or stale-route deletion error leaves WireGuard peer state unchanged for that attempt and is retried on the next poll.
- Agents keep ordered control-plane and signal endpoint lists and retry failover endpoints without stopping the local data-plane loop. Connect and whole-request deadlines bound each endpoint attempt, including peers that accept TCP but never return HTTP.
- Signal failure prevents new path negotiation and hole-punch planning; existing selected paths remain in local runtime state until they expire or are replaced.
- Relay failure causes affected relay paths to renew or renegotiate. If direct candidates are available, path scoring can promote back to direct.
- Redundant control-plane instances can share durable SQL state. PostgreSQL schema initialization is transaction-locked so instances can start concurrently. Heartbeats commit candidates, relay capability, optional routes, health freshness, and local path state atomically after a per-node monotonic timestamp check; SQLite serializes the writer transaction and PostgreSQL locks the node row. Signal and STUN replicas must not share the primary's sole failure domain. The load harness verifies peer-map, path-state, relay-candidate, and existing relay dataplane survival after one process is stopped; the Docker gate additionally proves existing kernel-WireGuard IPv4/IPv6 traffic, post-failover route reconciliation, and a completely new Agent join through surviving Control Plane/Signal/STUN endpoints.

## Smoke Gates

Use these before publishing an operational change:

```bash
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
scripts/helm-smoke.sh
scripts/docker-smoke.sh
HETERONETWORK_LOAD_SMOKE_BUILD_DAEMON=1 scripts/load-smoke.sh
```

Privileged Linux hosts can also run:

```bash
scripts/netns-smoke.sh
```

That suite requires network namespace creation privileges, runs the actual `iparsd agent --preflight-only` path for kernel-netlink and (when `wg` is installed) command backends, proves that a restarted kernel-netlink backend can remove a pre-existing peer by public key without its lost Node ID cache, and proves that fresh command and netlink route managers can inventory and remove protocol-marked routes created by an earlier instance. It also runs the routed peer-quality UDP probe alongside route, WireGuard, hole-punch, and relay-fallback checks. Set `HETERONETWORK_NETNS_SMOKE_EBPF_OBJECT_PATH` to a built object to make real tracepoint attach and ring-buffer event delivery a required part of the suite; CI always sets it. The suite may require `wireguard-tools`, kernel WireGuard support, `iptables`, tracefs, BPF privileges, and forwarding sysctls.

`.github/workflows/ci.yml` runs the Rust/MSRV, 3/10/1000-node plus daemon-failover load, Helm, Docker Compose, privileged namespace, and two-node kind suites as independent CI jobs for every pull request and `master` push. The privileged namespace job installs pinned eBPF Rust and linker tools, builds the repository object, requires real syscall tracepoint attach plus `sendto(2)` delivery and cgroup-only IPv4/IPv6 TCP `connect(2)`, TCP established/closing sockops state, and UDP send-message delivery with kernel-derived endpoint metadata, and installs the matching Ubuntu kernel module package only when WireGuard is not already available. The Kubernetes job downloads fixed kind, kubectl, and Helm versions and verifies each binary archive against its pinned SHA-256 before creating the disposable cluster.
