# Overlay rollout and control-plane availability, 2026-11-15

This record distinguishes observed failures from possible contributors. The
strict hierarchical overlay is an opt-in policy; deploying compatible binaries
does not itself enable it.

## Findings and repairs

- The Signal service on `ichikawap1` repeatedly restarted because its generated
  control-plane URL list contained the local URL twice. The public-services
  reconciler now normalizes and deduplicates the URLs, and its managed copies
  were repaired on both control-plane hosts. Both Signal services subsequently
  remained active.
- During a later automatic promotion, the generated configuration replaced the
  public OIDC issuer with an internal HTTP URL. The live issuer was restored via
  Terraform and the control-plane source was fixed to preserve the configured
  public issuer. The tested fix was rolled out to both serving control planes.
- Agent logs showed repeated Signal registration HTTP 409 responses. The same
  signed nonce was sent to both internal and public URLs, which can address the
  same Signal instance. A test against a real Signal server reproduced the
  failure. The Agent fix signs each endpoint request separately. The same
  replay affected path negotiation if the first response was lost; a second
  real-server regression test reproduced and fixed that case. A true replay is
  still rejected, and logs describe endpoint counts rather than server counts.
  The Agent fix has passed its local regression tests; rollout is pending the
  tested release candidate.
- Kubelets on all five hosts read the system resolver file instead of the
  managed resolver file. On several hosts that file had more than three
  nameservers. Repeated `DNSConfigForming`
  events affected 24 system Pods. Terraform and a serial Ansible playbook now
  reconcile the resolver and kubelet configuration, backing up previous files.
  All nodes returned Ready; cluster, public and overlay DNS queries succeeded.
  No existing warning count increased during the two-minute observation after
  repair.
- On `uc-k8sp1`, the four-core HDD host had load above five and elevated disk
  I/O pressure. `etcd` accounted for much of the sampled write activity. This
  establishes contention, not that it caused the browser timeouts below.

## Acceptance and remaining uncertainty

Before repair, one live GitHub runner timed out on a monitoring DNS request;
a later run timed out on a different gateway while a rollout was in progress.
Another post-rollout run resolved the monitoring names but exceeded the
three-second browser budget on a gateway. The exact cause of these intermittent
failures was not established. Direct node-to-node probes and subsequent real
VPN/browser runs succeeded; they do not prove the earlier failure is fixed.
Failure diagnostics now record the endpoint and subsequent probe results while
preserving the original failure and the three-second gate.

The hierarchy CI uses real WireGuard agents in network namespaces on one
GitHub-hosted VM, including latency, first-hop loss, a new node and a failed
conntrack snapshot. The 1,000-node native topology test is an in-memory test;
the 1,000 authenticated HTTP-mesh members are logical clients on a test VM.
Neither demonstrates 1,000 physical machines or independent geographic sites.

Only two existing control-plane/database voters are available. Without another
independent voter, loss or partition of one side cannot be claimed to preserve
write quorum. Region and zone are currently unspecified; measured path quality
is available, but geographic separation has not been inferred from addresses.
The policy change requires an authenticated HeteroNetwork owner and is not
complete until that change and the post-activation connectivity test succeed.
