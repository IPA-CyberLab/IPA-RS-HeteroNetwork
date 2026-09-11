# Production Readiness Observation

Observed on 2026-09-10/11 UTC. This is a timestamped observation, not a
continuous health check or evidence of successful production deployment.

## API And Consensus

- On ichikawap1, the production admin kubeconfig targets
  `https://k8s-api.heteronetwork.internal:7443`. The name resolved to
  `127.0.0.1`, with a local listener on port 7443. Reading the kube-system
  namespace timed out. Direct local API access on port 6443 was refused at
  the sampled instant.
- The running local etcd container answered a certificate-authenticated
  endpoint status request with `etcdserver: no leader`. Its subsequent
  bounded member-list request timed out. API logs also showed etcd Range
  request deadlines against `10.250.0.8:2379`.
- SSH to uc-k8sv1 (`10.250.0.8`) through ichikawap1 succeeded. Kubelet and
  containerd were active and control-plane manifests existed. This does
  not establish API or consensus health.
- On uc-k8sv1, the namespace read timed out and a certificate-validated
  local etcd `/health` request returned
  `{"health":"false","reason":"RAFT NO LEADER"}`.
- Direct public SSH attempts timed out; a direct workspace Tailscale
  attempt returned a local network-unreachable error. Neither is proof
  that those destination machines are powered off.

The production kube-system UID remains unverified. Etcd numerical cluster
IDs are not Kubernetes namespace UIDs. Do not substitute one for the other,
invent a UID, or weaken the independent DEV/production identity guard.

## Changes Not Performed

These checks did not restart services, alter etcd membership, initialize
databases, deploy production artifacts, or change sudo enforcement. Existing
DEV identity services and inactive sudo companion installation are separate
from production readiness.

Recovery requires examining the remaining actual voting members and peer
connectivity. Two observed no-leader responses alone do not identify the
failed members or distinguish network partition from unavailable voters.
Do not shrink membership or recreate the database to bypass this condition.

## Follow-Up: 2026-09-11 00:06-00:09 UTC

On uc-k8sv1, current etcd logs reported a connection timeout to
`10.250.0.4:2380` and TLS handshake timeouts for other peer IDs. Some TCP
connections were established, which is insufficient evidence of usable Raft
transport. The manifest's initial-cluster list is bootstrap configuration,
not an authoritative current voting-member list.

Certificate-validated requests from uc-k8sv1 to the etcd client health endpoint:

| Destination | Observation |
| --- | --- |
| 10.250.0.5:2379 | Connection timed out after 8 seconds; no TLS completion |
| 10.250.0.6:2379 | Connection timed out after 8 seconds; no TLS completion |
| 10.250.0.10:2379 | TLS completed in about 12 ms; HTTP 503, RAFT NO LEADER |

Short resource samples on uc-k8sv1 showed approximately 84-85% CPU idle,
16 GiB available memory, and 9.1 GiB free on the etcd filesystem. This does
not measure disk latency or resource pressure on the other nodes.

The agent repeatedly failed path negotiation against ichikawap1: VPN port
19443 refused connections and the public HTTPS fallback returned 404.
Systemd reported the signal and control-plane units inactive with failed
conditions. Their declarations require staged signal/services environment
files and, for the control plane, a database URL file. Configuration contents
were not printed and no replacement credentials were generated.

SSH banner exchanges through ichikawap1 timed out for VPN peers .4, .5 and
.6, and for uc-k8sp2's separate Tailscale address. Proxmox management at
100.97.114.85 answered SSH but rejected the available key for mizuame.
No password attempts, VM power operations, network changes or service restarts
were performed. Out-of-band guest state and the other voters remain unverified.
