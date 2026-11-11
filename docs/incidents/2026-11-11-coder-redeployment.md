# Coder redeployment and public gateway return routing

Coder and its database had been removed during the approved resource cleanup.
They were recreated as fresh Flash services; old workspaces and user data were
not restored. The non-secret service and VPC specifications are recorded in
`deploy/coder/flash-services.json`. This is a configuration snapshot, not an
automatic recreation mechanism; secret values remain in HeteroCloud.

The first attempt to issue and activate the custom-domain certificate stalled.
External HTTP-01 requests reached the solver, but cert-manager and the custom
domain controller could not reach the public gateway from Pods. On
`ichikawap1`, replies sourced from `163.220.236.61` to the Pod CIDR followed
source-policy routing table 2033's default route instead of the Flannel route.
The existing Pod routing oneshot service reported active while its priority 50
rule was missing. The reason the rule disappeared was not established.

The existing Pod CIDR rule was restored. A Terraform-managed Ansible policy
installs a small systemd timer on the ingress node to reinstate that existing
rule if it disappears. The guard checks first and does not rewrite a healthy
rule. A controlled removal with a temporary source-specific fallback verified
that the guard restored the priority 50 rule without interrupting the route.

The Coder owner is linked to the stable GitHub account ID for `mizuamedesu`.
Password login and GitHub self-signup are disabled; the fresh installation has
no other non-system users. The temporary operator credentials used for the
redeployment were revoked. Coder and PostgreSQL each have one running replica;
their Longhorn volumes each have two healthy replicas on separate nodes. This
protects the volumes but does not make the applications interruption-free.

Verification on 2026-11-11 included public HTTPS, private PostgreSQL and task
IAM connectivity, a newly created Flash-backed workspace reaching a connected
agent, and Chromium opening an editor file with bidirectional WebSocket traffic
before and after reload. The temporary workspace and its disk were deleted.
