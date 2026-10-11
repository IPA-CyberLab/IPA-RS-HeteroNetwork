# Flash configuration and storage update deployment — 2026-10-11

Terraform selects HeteroCloud 0.1.105 and Flash 0.1.48 through immutable release digests in the external Argo CD Application manifests. Both applications are Synced/Healthy. The workload helper remains at its existing 0.1.41 digest, so deploying the controller does not replace tenant containers.

The saved Flash plan updated only `kubernetes_manifest.external_application["heterocloud-flash"]` and its CRD/secret acceptance hook. The saved HeteroCloud plan updated only its Application and Helm-values cleanup hook. Unrelated database/host configuration changes were not applied.

The CRD guard now verifies optional persistent disk sizing and disk resize status alongside writable filesystem, stop/start, GPU access and secret environment schemas. The real secret injection/removal acceptance passed. GitHub Actions [38117179186](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/38117179186), attempt 2, passed its real runner VPN and authenticated Chromium test. The first attempt failed during deployment and is retained as failed evidence.

[HeteroCloud live acceptance](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/blob/master/docs/verification/flash-config-updates-2026-10-11.md) verified configuration edits, real persistent disk/filesystem expansion, data retention, public/private transitions, project migration and rejected destructive/foreign-tenant requests. Console readiness was 1.29 seconds on desktop and 1.17 seconds on mobile, under the existing 3-second limit. All nine previously Ready Pods and container IDs were unchanged after deployment and verification, including the protected recovery service. All owned test resources and credentials were cleaned up.
