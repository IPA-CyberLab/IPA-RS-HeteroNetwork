# Flash Web Shell Recovery

## Incident

The escape Web Shell reported container discovery failure. HeteroCloud logged
provider HTTP 403, translated to public HTTP 503. The workload remained Running,
with its workload container running and ready, restart count zero, but Pod Ready
was False. Flash reported provisioning with zero ready replicas and refused the
diagnostic request because the service was not Ready.

Kubelet logs showed API timeouts and `etcdserver: too many requests`. At inspection,
uc-k8sp2 was unreachable and uc-k8sp1 later became unreachable. The root cause of
those node/control-plane failures has not been established by this shell fix.

## Changes

- HeteroCloud 0.1.64 (`7d72c62`): console and management API permit authorized shell
  discovery for non-deleting services, including provisioning/updating/error.
- Flash 0.1.25 (`4c8ff5d`): readiness is no longer an authorization prerequisite.
  Exact service, organization, project, desired/observed generation, signature,
  action, pod ownership, running workload and non-termination checks remain.
- Container-list `ready` denotes shell eligibility, using actual workload running
  state instead of application readiness.
- `scripts/flash-web-shell-preflight.py` checks each ready provider endpoint using
  the configured operator-accessible signing key, without printing/storing tokens.
  Optional `KUBERNETES_API_SERVER` selects a responsive API endpoint.

## Deployment

Both release workflows succeeded. GitOps records both versions. Argo manifest
retrieval initially timed out; the same committed HeteroCloud Helm configuration
was rendered and applied to management resources through a responsive API.
Five pending management/provider pods assigned to an unreachable node were
normally deleted to permit rescheduling; no force deletion was used.
Tenant workload deployments were not changed or restarted.

Final state: HeteroCloud API 4/4, owner console 3/3, worker 4/4; Flash API 3/3,
controller 2/2. Both Argo applications reported Synced/Healthy at the release
commits above.

## Verification

- Focused console tests: 5 passed; Flash API tests: 7 passed.
- Provider preflight reproduced HTTP 403 before the update.
- After update, all three ready provider endpoints returned container-list HTTP
  200 and WebSocket upgrade HTTP 101 for escape.
- Kubernetes exec printed `escape-exec-ok` during the incident.
- Public HeteroCloud readiness returned HTTP 200.
- Escape Pod UID `08942b6b-7a5d-408d-9a88-16acfbe24b40` remained unchanged,
  restart count remained zero, and Pod Ready recovered to True.

The provider preflight closes each diagnostic connection immediately without
sending terminal input. It does not test browser session cookies, user IAM login,
terminal rendering, or sustained WebSocket traffic; browser E2E is not claimed.
