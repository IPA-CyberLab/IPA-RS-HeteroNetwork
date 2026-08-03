# Hetero platform GitOps bootstrap

This directory is the reproducible desired state for Argo CD. The bootstrap
keeps secrets outside Git, adopts the existing HeteroCloud releases, and can be
run repeatedly without rotating Grafana credentials.

From a Kubernetes control-plane node with this repository checked out:

```bash
sudo ./scripts/bootstrap-gitops.sh
```

The script performs these idempotent reconciliations:

1. upgrades the HeteroNetwork chart and publishes the internal DNS zone;
2. creates or repairs Grafana's PostgreSQL role, database, and Kubernetes
   Secret while preserving existing credentials;
3. installs the pinned Argo CD Helm chart in HA mode; and
4. applies self-healing Argo CD Applications for HeteroCloud and Flow.

The Argo CD chart is pinned by `ARGOCD_CHART_VERSION` (default `10.2.2`). Its
three Web replicas listen only on the control-plane VPN addresses. Initial
administrator credentials remain in the standard `argocd-initial-admin-secret`.

Internal DNS records are declared in
`deploy/environments/heteronet/values.yaml`. Every HeteroNetwork agent reloads
the generated JSON zone without restarting the VPN dataplane.
