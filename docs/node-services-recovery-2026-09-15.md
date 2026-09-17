# Node Service Recovery, 2026-09-15

The user requested recovery of the six unassigned HeteroNetwork services on
uc-k8sp5 and uc-k8sp2. uc-k8sp5 is recovered. uc-k8sp2 remains unrecovered;
its authenticated SSH connections do not execute commands or open forwarded
channels, and its Kubernetes node is NotReady.

## uc-k8sp5

The previous join left `20-private-control-plane.conf` explicitly disabling
both the public web gateway and automatic public-service installation.
The Kubernetes control-plane role was already Ready, but the HeteroNetwork
Control Plane, Signal, STUN, Relay, and Keycloak units were absent.

Automatic promotion and the public web gateway are now enabled. The existing
Agent obtained the authenticated promotion script and the standard bootstrap
executor installed the services without reenrolling the node. Its node ID,
VPN address, Kubernetes membership, and registered worker role were preserved.
The registered role is also worker on the existing Kubernetes masters; the
`kubernetes-control-plane` tag identifies their Kubernetes role.

The initially staged executor could not start because its systemd mount
namespace referenced absent directories. `/etc/sysusers.d`, `/etc/credstore`,
and the Control Plane drop-in directory were created before retrying.

The downloaded installer inherited the actual public OIDC issuer, but also
used its `/id` frontend prefix in two private Keycloak settings. Before
execution, those generated entries were corrected to:

- Backchannel: `http://127.0.0.1:18079/realms/heterocloud`.
- Replica probe: `/realms/heterocloud/.well-known/openid-configuration`.

The standard installer restaged the PostgreSQL autopilot configuration.
Its existing configuration, including healthy endpoint ordering, was restored
from the backup after promotion. The existing database bundle was retained.
The console owner email policy still matches the preexisting policy hash.

Promotion restarts the Agent several times. The console proxy's dependency
stopped it without restarting it. An Agent drop-in now explicitly wants
`heteronetwork-console-proxy.service`. A subsequent Agent restart verified
that the proxy returns automatically and both console ports return HTTP 200.

All six services have current assignments. Both service-instance leases and
the ready Keycloak candidate lease continued updating, including after the
restart. The gateway, Agent, console proxy, promotion timers, and Keycloak
autopilot timer are enabled.

The previous Kubernetes ingress override remains false on uc-k8sp5. Its
HeteroNetwork gateway serves .45, while the existing HeteroCloud LoadBalancer
origins remain .51/.53/.61.

## uc-k8sp2

Its Agent heartbeat continues, but its service leases expired on September 14.
Kubernetes has not received a kubelet status update since 16:28:09 UTC that day
and reports `NodeStatusUnknown`, NotReady, and an unknown container runtime.
Tailscale reports its separate management address offline.

SSH was tried over the HeteroNetwork address, Tailscale, and public address.
The public endpoint accepts the supplied key for mizuame, but neither a
hostname command nor a privileged interactive session executes. An SSH
connection dedicated to forwarding also authenticated; forwarded localhost
Agent, kubelet, and Docker socket requests received no response. That
connection eventually disconnected. No privileged command ran on this host.
Kubernetes node-proxy and direct API probes also timed out.

The underlying host failure is not established; these results do not prove an
OOM or a disk failure. No node, etcd member, tenant Pod, or volume was deleted
to conceal this failure. A separate management endpoint or physical console
is required to continue host diagnosis. This information has been requested.

## Validation

- uc-k8sp5: Kubernetes control-plane Ready before and after promotion/restart.
- All six HeteroNetwork assignments have updating leases; Keycloak ready=true.
- Control Plane, Signal, Relay status, Keycloak readiness, and private realm
  discovery return HTTP 200.
- STUN binding responses verified on both VPN and public addresses.
- Console 80 and 9781 return HTTP 200 after an Agent restart.
- Committed console E2E passed against all four reachable console gateways.
- Chromium rendered both canonical console URLs and opened the public
  Keycloak credential form without JavaScript errors. No login was submitted.
- Public HTTP HA checks passed on .51/.53/.61 and 20 normal public requests.
  This suite checks authentication discovery/forms, not a completed login.
- Focused Rust tests passed 2/2; rustfmt and diff whitespace checks passed.
- uc-k8sp2 is still NotReady. A complete fleet recovery is not claimed.

The source installer now normalizes both `/realms/` and `/id/realms/` issuers
to private `/realms/` paths for backchannels and replica probes. The source
change has focused regression coverage. Running Control Plane binaries were
not replaced during this repair; uc-k8sp5's generated configuration received
the corresponding correction before installation.

Root-protected uc-k8sp5 backups are in
`/var/backups/heteronetwork/20260915T0645Z-node-services/`.
Private verification artifacts are under
`artifacts/node-services-recovery-2026-09-15/`.
