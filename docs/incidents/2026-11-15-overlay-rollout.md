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
  The tested Agent fix was deployed to all five declared nodes, each of which
  reported the new build and a synchronized peer map.
- Kubelets on all five hosts read the system resolver file instead of the
  managed resolver file. On several hosts that file had more than three
  nameservers. Repeated `DNSConfigForming`
  events affected 24 system Pods. Terraform and a serial Ansible playbook now
  reconcile the resolver and kubelet configuration, backing up previous files.
  All nodes returned Ready; cluster, public and overlay DNS queries succeeded.
  No existing warning count increased during the two-minute observation after
  repair.
- The GitOps CoreDNS configuration still listed the retired `10.250.0.8`
  node as an overlay DNS forwarder. The internal Git mirror and Argo CD were
  updated to remove it and include the active bootstrap node. CoreDNS now
  imports a controller-generated list of Ready, non-stopped Kubernetes nodes
  on the declared overlay CIDR, bounded to the forward plugin's 15-upstream
  limit. A missing healthy list retains the last known list. The controller is
  running on two hosts and the three CoreDNS replicas consume its ConfigMap.
  An isolated GitHub runner tested the production CoreDNS image, including
  Kubernetes-style ConfigMap symlink swaps, addition and removal of an upstream.
  This explains probes toward the retired address, but does not establish that
  it caused the separate client-to-gateway DNS timeout.
- The Agent's UDP DNS loop previously terminated both DNS listeners for five
  seconds after any individual response-send error. The source fix drops that
  response and continues serving other clients; a regression test injects such
  an error and verifies the next real UDP query succeeds. The hierarchy and
  transport CI passed before the fix was rolled out serially to all five
  Agents, each of which reported a synchronized peer map. No corresponding
  listener restart was observed during the intermittent timeout below, so this
  defect is not asserted to be its cause.
- Packet traces on `uc-k8sp5` showed repeated WireGuard handshakes during
  peer-map application. The Agent's stored X25519 private-key bytes were not
  clamped, whereas Linux stored the equivalent clamped scalar. The Agent sent
  the unmodified stored bytes on every peer-map application. Linux compared
  the bytes before clamping and expired the peer session keys on each apparent
  change. The kernel key was confirmed to equal the clamped stored key; no key
  material was logged. The fix clamps the supplied value at both Linux backend
  boundaries without changing the stored key or its public identity. In two
  isolated network namespaces on the production kernel, a regression test
  reproduced a new handshake using the old raw setting and verified that both
  fixed backends preserve the established session. The same test passed on a
  GitHub-hosted Linux VM before the fix was rolled out serially to all five
  Agents; all reported the new build and a synchronized peer map. See the
  Linux 6.8 [key comparison and peer
  keypair expiration](https://github.com/torvalds/linux/blob/v6.8/drivers/net/wireguard/netlink.c)
  and [private-key clamping](https://github.com/torvalds/linux/blob/v6.8/drivers/net/wireguard/noise.c).
- On `uc-k8sp1`, the four-core HDD host had load above five and elevated disk
  I/O pressure. `etcd` accounted for much of the sampled write activity. This
  establishes contention, not that it caused the browser timeouts below.
- During the Agent rollout, a Kubernetes API server was restarted by its
  etcd-backend reconciler. A local administrative SSH tunnel pointed directly
  to that one API server and a Terraform read received HTTP 403. All five API
  servers subsequently authorized direct checks. The remaining rollout used
  the existing HA proxy; the node-retirement CLI now targets that proxy when
  it creates its own tunnel. The timing is established, while the precise
  reason for the transient 403 was not conclusively determined.

## Acceptance and remaining uncertainty

Before repair, one live GitHub runner timed out on a monitoring DNS request;
a later run timed out on a different gateway while a rollout was in progress.
Another post-rollout run resolved the monitoring names but exceeded the
three-second browser budget on a gateway. The exact cause of these intermittent
failures was not established. Direct node-to-node probes and subsequent real
VPN/browser runs succeeded; they do not prove the earlier failure is fixed.
Failure diagnostics now record the endpoint and subsequent probe results while
preserving the original failure and the three-second gate.
A further live run timed out on the first Prometheus DNS query to `10.250.0.5`;
three immediate follow-up queries succeeded in 565, 125 and 123 ms. That run
remained failed. These observations do not identify where the datagram or
response was delayed or lost.
Another post-rollout run timed out twice on Grafana DNS through `10.250.0.4`
before succeeding twice. A later run after the CoreDNS change succeeded with
authenticated Chromium, a 793 ms canonical console load and 2,642 ms maximum
gateway load; the transient DNS failure remains under investigation.
Separate probes from `uc-k8sp5` to `uc-k8sp1` then failed 3 of 150 times,
while 150 concurrent DNS queries local to `uc-k8sp1` all completed within
3 ms. Captures filtered to dedicated test ports showed two failed requests on
the sender's WireGuard interface but not on the receiver's WireGuard interface;
a third arrived about 480 ms late. This localizes the observed loss before
delivery to the receiver's overlay DNS listener, but does not distinguish
WireGuard encryption, the public underlay, and receiver-side decryption. The
sender was also repeatedly reapplying peer maps and re-verifying direct paths.
After the DNS send-error fix was deployed, a fresh comparison still had one
timeout and an 861 ms response in 200 queries from `uc-k8sp5` to `uc-k8sp1`;
200 concurrent local queries on `uc-k8sp1` all succeeded within 2 ms. The
transport loss persisted before the key-normalization fix. The live browser run
passed: the canonical page loaded in 932 ms after the route-readiness phase,
which itself took 18.5 seconds for all five gateways.

After the key-normalization fix was installed on all five nodes, 600 successive
queries from `uc-k8sp5` to `uc-k8sp1` succeeded, with a maximum response time
of 12.41 ms; another 600 concurrent queries local to `uc-k8sp1` succeeded, with
a maximum of 4.64 ms. A subsequent 200 inter-node queries also succeeded.
Packet capture counted 49 initiations from `uc-k8sp5` to `uc-k8sp1` during a
57.92-second observation before the fix, and zero during a 21.84-second
observation after the fix, while 7,888 outbound WireGuard packets were seen.
This supports the diagnosis and improvement on that path; it does not prove
that loss is impossible on other paths or under different conditions.
The subsequent [live GitHub Actions run](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/43692329617)
joined the production overlay from its hosted VM, exercised the canonical
console and every gateway in Chromium with the three-second page-open budget,
and completed the authenticated-console and isolated control-plane-unavailable
VPN recovery checks. These checks ran before strict hierarchy was enabled.

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
The full, non-targeted Terraform plan also contains other pending resource
changes. The overlay, issuer and kubelet repairs were applied with individually
reviewed targets; this does not establish that the entire plan is drift-free.
