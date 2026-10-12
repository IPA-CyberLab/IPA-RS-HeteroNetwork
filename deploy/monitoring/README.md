# Resource monitoring identity projection

`resource-services.sql` exposes the minimum HeteroCloud metadata needed to attribute measured Flash usage to a creator. It never includes specs, environment variables, secrets, tokens or email addresses. The generation-one outbox event identifies the creator; later edits do not transfer ownership.

`terraform_data.resource_monitoring` installs and runs the reconciler once on the bootstrap node. It creates a read-only SQL role, the projection and the existing-password-preserving `heterocloud-resource-monitoring` Secret in `heterocloud-flow`. It changes no workload, node or database service configuration. The bootstrap GitOps script invokes the same reconciler.

The Flow Helm chart owns the collector, private Service, namespace-scoped Pod/PVC read access, node stats read access, Prometheus discovery and Grafana dashboards. Users can open Grafana's cluster resource home and click a user donut slice for service details. The exporter reads the view every 30 seconds, so new/deleted users and services need no manual registration. See the Flow repository's `docs/monitoring/resource-usage.md` for accounting semantics and tests.
