# Flash Autoscaling And Domain Load Balancing

Flash supports optional autoscaling and an independent domain publishing mode.
Fixed replicas and IP endpoints remain the defaults; existing services are not
automatically converted.

## Configuration

```json
{
  "replicas": 1,
  "autoscaling": {
    "min_replicas": 1,
    "max_replicas": 2,
    "target_cpu_utilization_percent": 70,
    "target_memory_utilization_percent": 80
  },
  "exposure": {
    "type": "public",
    "traffic_mode": "forwarded",
    "endpoint_mode": "load_balancer"
  }
}
```

This is a fragment of a Flash spec, not a complete creation request. CPU and
memory targets are independently optional, but at least one is required. HPA
uses utilization relative to resource requests, not total host capacity. When
both targets are enabled, Kubernetes selects the larger replica recommendation.
Scale-in has a 300-second stabilization window. This scales Pods, not physical
nodes, and insufficient schedulable resources can still leave replicas pending.
See the [Kubernetes HPA documentation](https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/).

Account quota calculations reserve the maximum configured replica count and its
CPU, memory and disk requirements. This quota reservation does not reserve actual
cluster capacity. Applications must support multiple instances; local sessions
and in-memory state are not synchronized by the load balancer.

## Domain Endpoints

The provider's trusted `publicDomain` setting assigns
`f-<service-uuid>.flash.heterocloud.mizuame.app` in this deployment. ExternalDNS
watches labeled Services and publishes their load-balancer addresses. Provider
credentials remain in the existing DNS controller Secret, not in Flash specs.

Domain mode requires public, forwarded traffic. The existing HeteroNetwork
LoadBalancer class forwards traffic to Service backends across eligible Pods.
DNS publishes ingress addresses; DNS itself does not balance individual Pods.
TCP/UDP clients still specify the assigned service port. This is L4 publishing,
not an HTTP virtual-host gateway, automatic TLS termination, or a guarantee
that existing connections survive Pod/node loss. DNS caches also affect node
address removal. Cloudflare proxying is disabled for these generic TCP/UDP names.

## Prerequisites And Verification

`deploy/gitops/applications/metrics-server.yaml` pins the Metrics Server chart
and deploys two replicas on different nodes. The existing kubeadm kubelet
serving certificates are self-signed and lack IP SANs, so the manifest currently
uses `--kubelet-insecure-tls` on the VPN. This does not verify kubelet server
identity; replace it with verified serving certificates before relying on TLS
identity for this path. The metrics API and DNS controller remain internal.

```sh
KUBERNETES_API_SERVER=https://10.250.0.10:6443 \
  python3 scripts/flash-scaling-preflight.py
```

Add `--service-id <uuid>` to check an existing service's HPA targets and active
condition, then compare its locally resolved A records to its advertised ingress
addresses. This read-only check does not prove end-to-end traffic delivery.

`scripts/flash-autoscaling-e2e.py --service-port <unused-port>` creates one
disposable provider CR with a bounded CPU workload, requires scale-out 1 to 2
and stabilized scale-in 2 to 1, and requests cleanup in `finally`. It can take
12 minutes. It does not modify existing services, exercise HeteroCloud login or
quota enforcement, or prove cross-Internet load-balancer reachability. Confirm
owned resource and DNS cleanup after an interrupted run. Run it only after the
new provider version is deployed.

The pre-existing two-node outage is independent of these features; this change
does not restore unavailable control-plane nodes or claim complete cluster HA.
