# Flash Scaling Verification: 2026-09-08

## Deployment

- HeteroCloud 0.1.66 (`aec3ec3`): API, console, owner console, worker and CLI.
- Flash 0.1.28 (`107f577`): provider API, controller and CRD.
- Terraform provider 0.1.1 (`d438fd3`): release binaries and signed checksums.
- Metrics Server: chart 3.14.0, two replicas on separate nodes.
- Argo CD reports HeteroCloud and Flash as Synced and Healthy.

See [configuration and reproducible checks](flash-autoscaling-and-load-balancing.md).

## Observed Results

- CPU fixture: real utilization caused 1 -> 2 ready Pods, then stabilized
  scale-in to 1, without changing HPA configuration.
- Memory-only fixture: 60% target, 128 MiB request, 64 MiB temporary private
  allocation. Real utilization reached 79% and caused 1 -> 2 ready Pods,
  then returned to 1 after the stabilization window, with unchanged settings.
- External DNS resolved the fixture domain to both public ingress addresses.
- External TCP: 20/20 requests succeeded. Each ingress reached both Pods
  (4/6 and 7/3 response distributions).
- External UDP: 20/20 flows succeeded. Each ingress reached both Pods
  (5/5 and 6/4 response distributions).
- All three provider API replicas returned signed, read-only status requests
  with HTTP 200 and desired/ready replica counts of 2/2.
- After Flash 0.1.28, NetworkPolicy generation and resourceVersion remained
  unchanged over 30 seconds. The earlier empty-array normalization mismatch
  had caused unnecessary reconciliation writes; nonempty access restrictions
  are preserved by the fix.
- Cleanup confirmed for all four fixture IDs: no labeled FlashServices,
  Deployments, Services, HPAs, PVCs, NetworkPolicies or Pods remained.
  Authoritative DNS queries returned NXDOMAIN for all four fixture names.

Two earlier memory fixtures were interrupted and replaced while tuning the
test: shared mappings did not provide the intended working-set signal, and a
40% target with about 20% idle utilization could legitimately retain two Pods
because replica recommendations round upward. They are not counted as complete
scale-out/scale-in passes.

## Scope And Limitations

These are disposable provider-resource tests and external TCP/UDP checks, not
a production browser-login test, capacity benchmark, or cluster HA test.
Console browser checks use mocked APIs; quota and provider contracts have
separate automated coverage. CPU/memory percentages are relative to requests.

Existing tenant Pod UIDs did not change. The escape Pod still had one recorded
OOMKilled restart from 06:25 UTC, before this release was deployed; the nginx
Pod had zero restarts. No existing tenant container was deliberately restarted
or updated for these tests.

The two pre-existing unavailable nodes remain a separate incident. Metrics
Server currently uses the documented insecure kubelet TLS option because the
existing serving certificates lack suitable IP SANs. This deployment does not
claim verified kubelet TLS identity or restored full cluster HA.
