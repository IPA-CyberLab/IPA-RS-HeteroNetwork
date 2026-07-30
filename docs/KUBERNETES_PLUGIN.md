# HeteroNetwork Kubernetes Public Load Balancer Plugin

The HeteroNetwork Kubernetes plugin publishes selected Kubernetes workloads
through public IP addresses owned by HeteroNetwork nodes. It supports a
forwarded path for placement flexibility and a direct path for latency-sensitive
traffic. It is an L4 integration for TCP and UDP; it does not replace the
cluster CNI or add HTTP routing by itself.

The examples in [`examples/kubernetes-plugin`](../examples/kubernetes-plugin)
assume that the HeteroNetwork controller, admission webhook, and node gateway
are installed, and that every Kubernetes node has joined the same
HeteroNetwork cluster.

The Helm chart enables the core plugin with `kubernetesPlugin.enabled=true`.
Agones users must additionally set `kubernetesPlugin.agones.enabled=true`; this
adds the Agones RBAC and GameServer reconciler. The controller runs with two
replicas by default, while the per-node reporter runs beside the HeteroNetwork
Agent and publishes the Kubernetes Node metadata consumed by the controller.

## Service contract

Managed Services use this class:

```yaml
spec:
  type: LoadBalancer
  loadBalancerClass: heteronetwork.io/public
```

Each managed Service must choose exactly one traffic mode:

```yaml
metadata:
  annotations:
    networking.heteronetwork.io/traffic-mode: forwarded
```

The accepted combinations are:

| Traffic mode | `externalTrafficPolicy` | Eligible workload nodes | Public data path |
| --- | --- | --- | --- |
| `forwarded` | `Cluster` | Any schedulable node | Public node, then an L4 hop over HeteroNetwork to the selected endpoint |
| `direct` | `Local` | Public nodes only | Public IP owner directly to a Ready local endpoint |

The Service reconciler refuses to assign `forwarded` with `Local`, `direct`
with `Cluster`, or an unknown traffic mode, and records the reason in
`networking.heteronetwork.io/reconcile-error`. Always set the annotation
explicitly even though the controller can derive a compatibility mode from
`externalTrafficPolicy` for an older manifest.

A direct workload must also carry this label on its **Pod template**:

```yaml
metadata:
  labels:
    networking.heteronetwork.io/traffic-mode: direct
```

The Pod admission webhook uses that label to inject
`nodeSelector.networking.heteronetwork.io/public-ingress: "true"` and marks the
Pod with `networking.heteronetwork.io/placement-injected: "true"`. A label on a
Deployment, Fleet, or Service does not label the resulting Pod. For a
Deployment the required location is `.spec.template.metadata.labels`. For an
Agones Fleet it is
`.spec.template.spec.template.metadata.labels`, because the outer template
creates a GameServer and the inner template creates its Pod.

The Service annotation controls the ingress path. The Pod label controls
placement. Both are required for direct mode so that
`externalTrafficPolicy: Local` cannot select a public IP owner with no eligible
local endpoint.

## Public address eligibility

The per-node reporter correlates the Kubernetes node with its HeteroNetwork
node identity, VPN address, health, and endpoint candidates. Eligible Nodes
carry `networking.heteronetwork.io/public-ingress: "true"` plus the
`networking.heteronetwork.io/node-id`,
`networking.heteronetwork.io/vpn-ip`, and
`networking.heteronetwork.io/public-ip` annotations. A public address is
eligible only while its node is Ready and the address is locally owned by that
node.

In particular, a `PublicUdp` candidate used for this plugin must represent a
globally routable IP configured on a local interface. A STUN-reflexive address
behind NAT, a shared router address, CGNAT, or an address merely reachable from
the node is not sufficient: the gateway must be able to bind the address and
receive unsolicited TCP and UDP traffic for the published ports. Firewall and
upstream routing rules must also permit those ports.

The controller owns `.status.loadBalancer.ingress` and records the selected
gateways in `networking.heteronetwork.io/assigned-nodes`. A Service requests
two ingress nodes by default; set
`networking.heteronetwork.io/ingress-replicas` to a value from 1 through 64
when a different count is required. Do not set
`spec.externalIPs` to a HeteroNetwork VPN address and do not manually copy a
public IP between nodes. In direct mode the controller publishes only public
nodes with a Ready local endpoint. In forwarded mode it may use any healthy
public gateway and send traffic to endpoints on private nodes over their VPN
paths.

## Forwarded mode

Forwarded mode is intended for HTTP signaling, APIs, TURN, and game traffic
where an additional overlay hop is acceptable:

```text
client -> public node L4 gateway -> HeteroNetwork VPN -> Service endpoint
```

The gateway is stateful and protocol-aware only at L4. UDP must use the
gateway's UDP forwarding path; an HTTP reverse proxy cannot carry arbitrary
game or WebRTC media traffic. Backend Pods remain eligible on public and
private nodes, so adding private workers increases compute capacity.

Source-address preservation is not guaranteed across the forwarded path.
Applications that require the original client identity must use an
application-supported mechanism or a proxy protocol supported end to end.

Apply the generic example with:

```bash
kubectl apply -f examples/kubernetes-plugin/generic-forwarded.yaml
```

## Direct mode

Direct mode is intended for latency-sensitive UDP/TCP workloads:

```text
client -> public IP owner -> Ready Pod on the same Kubernetes node
```

The plugin does not forward service traffic to a different HeteroNetwork node.
The Pod still uses the cluster CNI for ordinary Pod networking. Replicas that
cannot fit on eligible public nodes remain Pending; the controller must not
silently fall back to forwarding.

Apply the generic example with:

```bash
kubectl apply -f examples/kubernetes-plugin/generic-direct.yaml
```

## Agones Fleets

The plugin watches annotated Agones GameServers. The Fleet annotation must be
inside `.spec.template.metadata.annotations` so Agones propagates it to each
GameServer. The examples use `portPolicy: None` because HeteroNetwork, rather
than the Agones host-port allocator, owns the public address and port.

For every annotated GameServer, the controller allocates public ports from the
configured `kubernetesPlugin.agones.portRangeStart` through
`portRangeEnd` range and creates one owner-referenced Service with:

- `type: LoadBalancer`
- `loadBalancerClass: heteronetwork.io/public`
- the GameServer's traffic-mode annotation
- `externalTrafficPolicy: Cluster` for forwarded mode or `Local` for direct
- `networking.heteronetwork.io/agones-managed: "true"` and
  `networking.heteronetwork.io/agones-game-server: GAME_SERVER` labels
- a selector scoped to that GameServer Pod
- ports derived from the named entries in `GameServer.spec.ports`

The generated Service is deleted with its GameServer. Once the Service has a
published endpoint, the controller writes the
`networking.heteronetwork.io/public-addresses` annotation to the GameServer.
Its value is a JSON array containing the generated Service's named public
address, port, and protocol tuples:

For example:

```json
[{"name":"game","address":"PUBLIC_IP","port":32001,"protocol":"UDP"}]
```

The plugin does not overwrite Agones-owned `GameServer.status.address` or
`GameServer.status.ports`. Allocation code must read the published endpoint
annotation, or use an allocation adapter that returns it to the game client.
Treat the annotation as controller-owned and wait for `public-addresses` before
advertising an allocated GameServer.

Inspect an allocated endpoint with:

```bash
kubectl get gameserver GAME_SERVER -o \
  jsonpath='{.metadata.annotations.networking\.heteronetwork\.io/public-addresses}'
```

Forwarded GameServers can run on every worker:

```bash
kubectl apply -f examples/kubernetes-plugin/agones-forwarded-fleet.yaml
```

Direct GameServers carry the direct label on the nested Pod template and run
only on eligible public nodes:

```bash
kubectl apply -f examples/kubernetes-plugin/agones-direct-fleet.yaml
```

See the upstream [Agones Fleet specification](https://agones.dev/site/docs/reference/fleet/)
for Fleet and nested GameServer template fields.

## LiveKit split profile

[`livekit-split.yaml`](../examples/kubernetes-plugin/livekit-split.yaml) keeps
the latency-sensitive RTC path direct while allowing the signaling Service to
use the forwarded policy:

| LiveKit path | Mode | Ports |
| --- | --- | --- |
| Signal/API/WebSocket | `forwarded` | TCP 7880 |
| RTC media | `direct` | TCP 7881 and UDP 7882 |

The LiveKit Pod template is labeled `direct`, uses host networking, and has
required hostname anti-affinity. It therefore runs at most one replica per
eligible public node. `rtc.use_external_ip: true` is valid only because every
eligible node owns its advertised public IP locally.

Before applying the example:

1. Replace the example API secret with a generated secret.
2. Provide a production Redis service at the configured address.
3. Confirm TCP 7881 and UDP 7882 are open on every eligible public node.
4. Put TLS termination for signaling in front of TCP 7880 or configure LiveKit
   with the required certificate path.

```bash
kubectl apply -f examples/kubernetes-plugin/livekit-split.yaml
```

LiveKit requires Redis for a distributed deployment and recommends direct host
networking for its normal RTC path. See the upstream
[Kubernetes deployment guide](https://docs.livekit.io/home/self-hosting/kubernetes)
and [port reference](https://docs.livekit.io/transport/self-hosting/ports-firewall/).

## LiveKit fully forwarded TURN profile

[`livekit-forwarded-turn.yaml`](../examples/kubernetes-plugin/livekit-forwarded-turn.yaml)
allows LiveKit Pods to run on public or private workers. Signal and embedded
TURN Services both use forwarded mode:

```text
client -> public HeteroNetwork gateway -> TURN Pod -> LiveKit RTC node
```

The profile intentionally has no direct Pod label and no host networking.
External clients use TURN/UDP 3478 or TURN/TLS 5349 instead of relying on
private RTC candidates. To require this path rather than merely allow fallback,
set the client WebRTC ICE transport policy to relay.

Before applying the example:

1. Replace `turn.example.com` and point it at the `livekit-turn` Service
   ingress address.
2. Create `livekit-turn-tls` as a TLS Secret for that domain.
3. Replace the example API secret and provide production Redis.
4. Replace the example Flannel Pod CIDR and HeteroNetwork CIDR in
   `allow_restricted_peer_cidrs` with the actual routed ranges.
5. Permit UDP 3478 and TCP 5349 at every selected public gateway.

LiveKit v1.12 and newer deny TURN relay access to private destinations unless
they are explicitly allowed. Keep the restricted-peer list limited to the
actual Pod and HeteroNetwork ranges.

```bash
kubectl apply -f examples/kubernetes-plugin/livekit-forwarded-turn.yaml
```

TURN makes private-node placement possible, but every media packet consumes
gateway and TURN capacity and takes an additional path. Use the split/direct
profile when lower latency is more important than placement flexibility.

## Capacity and failure limits

One public node remains a single point of failure even when Kubernetes,
HeteroNetwork, Redis, and the workload all have multiple replicas. Forwarded
mode can distribute CPU and memory work to many private nodes, but it cannot
exceed that one node's public uplink, packet-processing rate, conntrack state,
or UDP forwarding capacity.

At least two independently reachable public nodes are required for ingress
failover. Existing TCP connections, UDP mappings, WebRTC sessions, and game
sessions are not migrated when a public gateway dies; clients must reconnect
to a surviving published endpoint. Direct mode additionally needs a Ready local
Pod on each advertised public node.

Scaling private workers therefore has different effects:

- `forwarded`: increases backend compute capacity but not aggregate public
  ingress capacity unless public gateways are also added.
- `direct`: does not use private workers for the managed Service.

Monitor bandwidth, packets per second, active flows, drops, and per-gateway
endpoint health before increasing Fleet or LiveKit replica counts.

## Verification

Check that the class, mode, policy, and assigned ingress agree:

```bash
kubectl get service -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,CLASS:.spec.loadBalancerClass,MODE:.metadata.annotations.networking\.heteronetwork\.io/traffic-mode,POLICY:.spec.externalTrafficPolicy,INGRESS:.status.loadBalancer.ingress[*].ip'
```

For direct workloads, verify that every selected endpoint is on the node that
owns its published public IP:

```bash
kubectl get pods -A -o wide \
  -l networking.heteronetwork.io/traffic-mode=direct
kubectl get endpointslice -A \
  -l kubernetes.io/service-name=SERVICE_NAME -o wide
```

Treat a Service that remains Pending, a direct Pod scheduled without the
injected public-node constraint, or an ingress IP not locally owned by its
gateway as a failed publication rather than falling back to an untracked
forwarding path.
