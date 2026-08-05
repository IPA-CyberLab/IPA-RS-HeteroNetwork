# Public node systemd deployment

The units in this directory support both manually configured full public nodes
and automatically promoted partial nodes. Each Control Plane renews its instance
lease in the shared PostgreSQL store. Signed token endpoints are used only for
initial discovery; Agents persist each core-complete active directory as
authoritative and replace retired endpoints instead of retaining them as
permanent seeds.

`ipars-control-plane.service` uses `BindsTo=` for the other three services. If
Signal, STUN, or Relay leaves the active state, the Control Plane also stops and
its whole-node lease expires instead of advertising a partially dead public
node. The automatic `heteronetwork-control-plane.service` instead binds its base
lease to Agent, STUN, and Relay. Its reconciler independently adds Signal while
the HTTPS gateway is reachable and removes only Signal when that probe fails.
All units use automatic restart and systemd hardening without root or network
capabilities.

## Prerequisites

- Two or more independently reachable public hosts.
- Three mutually reachable private PostgreSQL members, deployed with
  [`scripts/postgres-ha-node.sh`](../../scripts/postgres-ha-node.sh), or an
  equivalent managed synchronous HA service.
- An external load balancer or multiple DNS records when a stable UI hostname
  must survive a public-node outage.
- Keycloak with each public `/ui/` URL registered as a valid redirect URI and
  Web Origin.

The application tier is active-active with two public nodes. PostgreSQL uses
three private failure domains and does not require a public IP. The packaged HA
deployment is documented in
[`docs/POSTGRES_HA.md`](../../docs/POSTGRES_HA.md).

## Install one node

```sh
sudo useradd --system --home /var/lib/ipars --create-home --shell /usr/sbin/nologin ipars
sudo install -d -o root -g ipars -m 0750 /etc/ipars
sudo install -d -o root -g root -m 0700 /etc/credstore
sudo install -d -o root -g root -m 0755 /opt/ipars/bin
sudo install -o root -g root -m 0755 target/release/iparsd /opt/ipars/bin/iparsd
sudo install -o root -g ipars -m 0640 deploy/systemd/public-node.env.example /etc/ipars/public-node.env
sudo install -o root -g root -m 0644 deploy/systemd/*.service deploy/systemd/ipars-public-node.target /etc/systemd/system/
```

Replace every example value in `/etc/ipars/public-node.env`. Store independent,
random 32-byte-or-longer printable tokens in the five referenced token files,
owned by `ipars:ipars` with mode `0400`. The daemon intentionally rejects
group/world-readable credential files. The issuer private key is not installed
on public nodes; only its public key belongs in this environment file.
Every service replica must run on an enrolled Agent machine. Set both
`HETERONETWORK_SERVICE_OWNER_HOST_ID` and
`HETERONETWORK_SERVICE_OWNER_NODE_ID` to that machine's registered Node ID.
The daemon rejects missing or mismatched owner IDs, and excludes leases from
unhealthy or non-public owners from the service directory and HA counts. When the
Web UI **Add device** workflow is enabled, generate a separate Ed25519 enrollment
signing key and install the same key as
`/etc/credstore/node-enrollment-issuer.key` on every Control Plane replica with
ownership `root:root` and mode `0400`. The Control Plane unit imports it with
systemd `LoadCredential=` into that service's read-only credential namespace;
Signal, STUN, and Relay do not receive it even though the packaged services use
the same Unix account. Do not set the direct private-key path variable in the
shared environment file, and never reuse the offline root issuer key. Startup
rejects key reuse and issuer/key ID collisions. Tokens from this online key are
verifier-constrained to `edge`, `worker`, or
`gateway` joins, matching claim/policy tags, no route authority, finite use
counts, the configured TTL ceiling, and at least two active Control Plane,
Signal, STUN, and Relay endpoints because relay permission is enabled by
default. Every Relay replica must read the same
`HETERONETWORK_RELAY_ADMISSION_BEARER_TOKEN_PATH` credential. The Control Plane
reads that credential through the same owner-only path and places it, together
with the Agent systemd configuration, in each Add device install script. Run an
installer with `--disable-relay` only when that node must not receive Relay
admission configuration. Do not configure Relay admission manually on joining
nodes.
The installer also enables `heteronetwork-public-services-autopilot.timer` by
default. On every enrolled machine with a fresh directly reachable public
classification, it starts STUN from the independent `udp-services.env` file and
has the Agent publish signed STUN and live Relay endpoints to the existing
Control Planes. This base promotion requires neither a local Control Plane nor
PostgreSQL or HTTPS. A local VPN Control Plane and Web UI are added only when the
PostgreSQL HA proxy and credentials are available, and Signal is added only
while the public HTTPS gateway probe succeeds. Failure of one role does not stop
the other roles. Pass
`--disable-public-services` only for an explicit per-node opt-out. Automatically
promoted Control Planes receive the root and enrollment public verification
keys. They remain verification-only unless an operator explicitly provisions
both `/etc/credstore/node-enrollment-issuer.key` and the root-only
`/etc/heteronetwork/agent-relay-admission.token`. When both files pass the
owner-only credential checks, the autopilot imports them into only the Control
Plane's systemd credential namespace and enables enrollment. This lets selected
automatic replicas provide HA enrollment without distributing the signing key
to every public node.
Install the local database proxy and place its complete TLS-verifying
PostgreSQL URL in `/etc/credstore/database-url`, owned by `root:root` with mode
`0400`. The unit imports that URL as a separate systemd credential, keeping the
database password out of the shared environment file and process arguments.
Set `HETERONETWORK_WEB_PUBLIC_URL` to that node's externally used origin. The daemon
then keeps PKCE verifier/state server-side for the callback, including on lab
HTTP IP addresses where browser WebCrypto is not available.
Internet-facing issuer and public URLs must use HTTPS; plain HTTP is accepted
only for loopback, private, link-local, and CGNAT lab addresses.
Allow both `HETERONETWORK_STUN_LISTEN` and
`HETERONETWORK_STUN_ALTERNATE_LISTEN` through the host and upstream UDP
firewalls. The alternate RFC 5780 listener lets an Agent obtain two mapping
observations from one public STUN service; separate public nodes are still
required for service HA.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ipars-public-node.target
```

## Verify and fail over

Read `/v1/admin/services` or the Web UI's **Public nodes** view. A two-node
deployment is ready only when the HA metric is `1` and all four service counts
are at least `2`.

```sh
curl -fsS -H "Authorization: Bearer $OPERATOR_TOKEN" \
  https://public-a.example:8443/v1/admin/services
curl -fsS -H "Authorization: Bearer $OPERATOR_TOKEN" \
  https://public-b.example:8443/metrics | grep ipars_control_plane_ha_ready
sudo systemctl stop ipars-public-node.target
```

After one lease TTL, the surviving node reports one instance and
`ipars_control_plane_ha_ready 0`. Existing direct WireGuard sessions remain in
the data plane; control, Signal, STUN, and new joins fail over to the surviving
directory entries. Restart the stopped target and wait for HA readiness to
return to `1`.

The authenticated **Add device** view issues a token into the shared PostgreSQL
ledger before returning a Linux install command. The command downloads the
pinned `iparsd` artifact through token-authenticated, non-cacheable endpoints,
verifies its SHA-256 digest, performs a one-time enrollment, removes the token,
and starts the persistent systemd Agent from owner-only state. Issuance is
disabled unless the service directory contains the required distinct active HA
endpoints.
