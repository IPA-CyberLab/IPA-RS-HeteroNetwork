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
