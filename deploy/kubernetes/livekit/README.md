# LiveKit on HeteroNetwork

This deployment runs LiveKit in distributed mode on public HeteroNetwork
Kubernetes nodes:

- LiveKit Server 1.13.4, two replicas, one replica per public node
- Redis 8.8.1, three replicas with Redis Sentinel quorum 2
- forwarded signaling on TCP 7880 through all three public nodes
- direct RTC on TCP 7881 and UDP 7882 through the two nodes that host LiveKit
- automatic host UDP-buffer tuning before each LiveKit Pod starts

Run the deployment from the repository root:

```bash
scripts/deploy-livekit-heteronetwork.sh
```

The script creates random Redis and LiveKit credentials on the first run and
reuses them on upgrades. Credential values are stored only in Kubernetes
Secrets in the `livekit` namespace.

Inspect the assigned public addresses and workload placement:

```bash
kubectl -n livekit get service livekit-signal livekit-rtc -o wide
kubectl -n livekit get pod -o wide
```

Retrieve the generated API credentials when configuring a trusted backend:

```bash
kubectl -n livekit get secret livekit-keys \
  -o jsonpath='{.data.api-key}' | base64 -d
kubectl -n livekit get secret livekit-keys \
  -o jsonpath='{.data.api-secret}' | base64 -d
```

TCP 7880 and 7881 and UDP 7882 must be permitted by every selected public
node's host firewall and upstream network. Terminate TLS in front of TCP 7880
before exposing browser clients in production.

The UDP-buffer init container is privileged because `net.core.rmem_max` and
`net.core.wmem_max` belong to the host network namespace. It exits before the
unprivileged LiveKit container starts and applies only on nodes selected for
LiveKit.

Redis persistence is intentionally disabled because this cluster currently has
no StorageClass. Sentinel tolerates one Redis-node failure, but simultaneous
loss of all three Redis Pods loses transient room and routing state.
