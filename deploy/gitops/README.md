# Hetero platform GitOps bootstrap

This directory is the reproducible desired state for Argo CD. The bootstrap
keeps secrets outside Git, adopts the existing HeteroCloud releases, and can be
run repeatedly without rotating Grafana credentials.

From a Kubernetes control-plane node with this repository checked out:

```bash
sudo ./scripts/bootstrap-gitops.sh
```

The script performs these idempotent reconciliations:

1. upgrades the HeteroNetwork chart and publishes the internal DNS zone;
2. creates or repairs Grafana's PostgreSQL role, database, and Kubernetes
   Secret while preserving existing credentials;
3. installs the pinned Argo CD Helm chart in HA mode; and
4. installs the pinned Envoy Gateway chart and its three-replica global rate
   limit service;
5. applies self-healing Argo CD Applications for cluster DNS, the Envoy
   Gateway edge, HeteroCloud, Flow, and the gVisor-backed Flash provider.

The Argo CD chart is pinned by `ARGOCD_CHART_VERSION` (default `10.2.2`). Its
three Web replicas run on the Kubernetes pod network. The separately managed
`argocd-server-overlay` Service exposes them only through the three
control-plane VPN addresses. Initial administrator credentials remain in the
standard `argocd-initial-admin-secret`. The console URL is
`http://argocd.heteronetwork.internal:8088`.

The three repo-server replicas use the control-plane host network so Git
fetches use the same outbound path that is available from the Kubernetes
nodes. Their host listeners use ports `28081` and `28084` to avoid the
HeteroCloud Flow matchmaker's host port; the Argo Services keep their
cluster-internal `8081` and `8084` ports. `ClusterFirstWithHostNet` keeps
cluster DNS resolution for Argo's internal services while preserving GitHub
access for manifest reconciliation.

The public HTTP and WebSocket edge is declared in
`deploy/gitops/envoy-gateway/`. Envoy Gateway is pinned to v1.8.3, its
generated proxy Service uses the HeteroNetwork `heteronetwork.io/public`
LoadBalancer class on listener port 18081, and only the three managed Caddy
gateways may reach that Service. The generated public Envoy proxy runs with
three replicas on public-ingress nodes and keeps two available during
voluntary disruption. Flow's HTTP API, signaling, and LiveKit
signaling Services are private ClusterIP backends. A Redis-backed Envoy global
rate limit applies a shared 200 requests/second bucket per client IP to the
HeteroCloud and HeteroCloud Flow HTTPRoutes; IPv4 and IPv6 limits are declared
separately. Route-level policies keep Envoy Gateway's rate-limit domain aligned
with each route. The
rate-limit deployment has three replicas and a two-pod disruption budget. The
rate-limit service uses a three-replica HAProxy Redis-primary proxy. Each
proxy health-checks the Flow Redis nodes and accepts traffic only from the
current `role:master` node, so Redis failover does not send writes to
read-only replicas. If the shared limiter cannot be reached, Envoy fails open
while retaining the per-proxy 200 requests/second limit for each client IP.

The GitOps overlay also creates the annotated `envoy-ratelimit-metrics`
Service. It exposes the rate-limit service's Prometheus endpoint without
modifying the Envoy Gateway-owned Service, so the existing Prometheus
Kubernetes service discovery collects rate-limit counters after a fresh
install as well as after reconciliation.

Cluster DNS is managed by the `cluster-dns` Application. It keeps three CoreDNS
replicas on separate nodes with a two-pod disruption budget and runs the
upstream Kubernetes NodeLocal DNSCache DaemonSet on every Linux node. The
NodeLocal cache keeps normal Pod DNS traffic on the local node and forwards
cache misses to the CoreDNS Service over TCP. The same Application runs a
privileged, capability-limited `kubernetes-service-route` DaemonSet. It pins
host-originated Service traffic to each node's `cni0` source address so return
traffic remains routable when Kubernetes nodes are spread across unrelated
physical LANs. Run
`sudo scripts/reconcile-kubelet-dns.sh` once on each existing node after a
cluster upgrade; kubeadm-created nodes configure the same resolver path during
`prepare`. The helper limits the resolver file consumed by kubelet to three
non-loopback nameservers, avoiding the systemd-resolved/Tailscale nameserver
overflow that produces `DNSConfigForming` events. Because NodeLocal DNSCache
binds TCP and UDP 53 on the node's local and Service IPs, any host DNS service
must bind only to its LAN address instead of `0.0.0.0:53`.

This is an L7 abuse and overload control, not volumetric Internet DDoS
scrubbing. It protects the Kubernetes services after traffic reaches the
public nodes. Prometheus also scrapes the Envoy Gateway namespace so the
control-plane, proxy, and rate-limit metrics remain in the existing Grafana
stack.

Internal DNS records are declared in
`deploy/environments/heteronet/values.yaml`. Every HeteroNetwork agent reloads
the generated JSON zone without restarting the VPN dataplane.
