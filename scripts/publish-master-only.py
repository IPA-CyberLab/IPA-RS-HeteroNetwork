#!/usr/bin/env python3
"""Build a scoped infrastructure commit and bundle without staging unrelated edits."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def files():
    paths=['.gitignore','README.md','heteronet-admin','scripts/heteronet_admin.py','scripts/test_heteronet_admin.py',
           'scripts/prune_overlay_dns_node.py','scripts/test_prune_overlay_dns_node.py',
           'scripts/prune_node_declarations.py','scripts/test_prune_node_declarations.py',
           'scripts/kubeadm-ha-node.sh','scripts/postgres-ha-node.sh','scripts/postgres-ha-autopilot.sh','scripts/keycloak-autopilot.sh','scripts/master-only-iac.py',
           'scripts/verify-master-only.py','scripts/verify-standard-node.py','scripts/test_verify_standard_node.py',
           'scripts/publish-master-only.py','scripts/reconcile-dns-boot-recovery.py','scripts/ensure-flash-ssh-host-key.py','scripts/test_ensure_flash_ssh_host_key.py',
           'scripts/verify-storage-redundancy.py','scripts/test_verify_storage_redundancy.py',
           'scripts/install-public-gateway-base.py','scripts/test_install_public_gateway_base.py',
           'scripts/public_dns_witness_e2e.py',
           'scripts/reconcile-overlay-boot.py','scripts/test_reconcile_overlay_boot.py','scripts/overlay_power_recovery_e2e.py',
           'scripts/node_lifecycle.py','scripts/node_test_fixtures.py','scripts/test_node_lifecycle.py','scripts/reconcile-node-lifecycle.py',
           'scripts/retire_hn_registration.py','scripts/test_retire_hn_registration.py',
           'scripts/retire_node_inventory.py','scripts/test_retire_node_inventory.py',
           'scripts/retire_node_kubernetes.py','scripts/test_retire_node_kubernetes.py',
           'scripts/retire_lost_garage_volume.py','scripts/test_retire_lost_garage_volume.py',
           'scripts/retire_database_member.py','scripts/test_retire_database_member.py',
           'scripts/prune_retired_garage_volumes.py',
           'scripts/prune-terminal-pods.py','scripts/test_prune_terminal_pods.py',
           'scripts/prune-control-plane-releases.py','scripts/test_prune_control_plane_releases.py',
           'scripts/prune-unused-images.py','scripts/test_prune_unused_images.py',
           'scripts/test_flow_capacity.py',
           'scripts/security_runtime_restart.py','scripts/security_runtime_restart_e2e.py',
           'scripts/security_initializer_memory_e2e.py','scripts/security_inventory.py',
           'scripts/security_cargo_patch.py','scripts/test_security_inventory.py',
           'scripts/reconcile-stopped-wireguard.py','scripts/test_reconcile_stopped_wireguard.py',
           'scripts/reconcile-stopped-overlay-firewall.py','scripts/test_reconcile_stopped_overlay_firewall.py',
           'scripts/stopped_firewall_namespace_e2e.py',
           'scripts/verify-heterocloud-iam-rollout.py','scripts/test_verify_heterocloud_iam_rollout.py',
           'scripts/promote-database-sync-replica.py','scripts/test_promote_database_sync_replica.py',
           'scripts/start-declared-sync-replica.py','scripts/prepare-database-ha.py',
           'scripts/test_prepare_database_ha.py','scripts/prepare-console-release.py','scripts/test_prepare_console_release.py',
           'scripts/recover-database-authority.py','scripts/test_recover_database_authority.py',
           'scripts/recover-database-proxy-client.py','scripts/test_recover_database_proxy_client.py',
           'scripts/normalize_application_helm_values.py','scripts/reconcile_platform_release.py',
           'scripts/test_reconcile_platform_release.py',
           'scripts/reconcile-node-health.py','scripts/test_reconcile_node_health.py',
           'scripts/reconcile-receive-steering.py','scripts/test_reconcile_receive_steering.py',
           'scripts/postgres-dcs-metrics.py','scripts/test_postgres_dcs_metrics.py',
           'scripts/public-services-autopilot.sh','scripts/public-services-autopilot-smoke.sh',
           'scripts/patch-legacy-public-services-db.py','scripts/test_patch_legacy_public_services_db.py',
           'scripts/verify-etcd-policy.py','scripts/test_verify_etcd_policy.py',
           'scripts/verify-apiserver-etcd.py','scripts/test_verify_apiserver_etcd.py',
           'scripts/reconcile-etcd-retirements.py','scripts/test_reconcile_etcd_retirements.py',
           'scripts/encrypted-etcd-snapshot.py','scripts/test_encrypted_etcd_snapshot.py',
           'scripts/reconcile-github-dr-environment.py','scripts/test_reconcile_github_dr_environment.py',
           '.github/workflows/storage-heartbeat-e2e.yml',
           '.github/workflows/stopped-firewall-e2e.yml',
           '.github/workflows/oss-security.yml','.github/workflows/oss-security-reusable.yml',
           '.github/workflows/verify-etcd-backup-key.yml',
           '.github/workflows/github-dr-environment.yml',
           '.github/workflows/receive-steering.yml',
           '.github/workflows/postgres-dcs-metrics.yml',
           '.github/workflows/public-services-db-retention.yml',
           'scripts/accept-registered-nodes.py','scripts/verify-console-gateways.mjs','scripts/test_onboarding_acceptance.py',
           'scripts/heteronetwork-console-e2e.sh','scripts/heteronetwork-console-browser-e2e.mjs',
           'scripts/verify-overlay-client-console.py','scripts/test_verify_overlay_client_console.py',
           'scripts/reconcile-console-e2e-user.py','scripts/reconcile-console-issuer.py',
           'scripts/test_reconcile_console_issuer.py',
           'scripts/verify-gpu-runtime.py',
           'scripts/gpu_inventory.py','scripts/test_gpu_inventory.py',
           'scripts/verify_gpu_inventory.py','scripts/test_verify_gpu_inventory.py',
           'scripts/verify_flash_crds.py','scripts/test_verify_flash_crds.py','scripts/verify_flash_secret_env.py',
           'docs/master-only-iac-2026-09-15.md',
           'docs/standard-node-setup-2026-09-15.md',
           'docs/onboarding-e2e-gate-2026-09-15.md',
           'docs/flash-gpu-iac-2026-09-16.md',
           'docs/github-actions-vpn-console-e2e.md',
           'docs/heterogeneous-resilience-2026-11-14.md',
           'docs/encrypted-etcd-offsite.md',
           '.github/workflows/infrastructure-validation.yml',
           'deploy/systemd/heteronetwork-agent-overlay-proxy.conf',
           'deploy/kubernetes/control-plane-only-policy.yaml',
           'deploy/environments/heteronet/values.yaml','deploy/gitops/project.yaml']
    paths += ['deploy/gitops/applications/'+n+'.yaml' for n in
              ['cluster-dns','network-policy-engine','longhorn','longhorn-prerequisites','flash-web','heterocloud-edge','openbao',
               'heterocloud','heterocloud-flash','heterocloud-flow','heterocloud-syouyu','heterocloud-vpc',
               'heterocloud-vpc-egress','public-dns-quorum']]
    paths += ['deploy/gitops/cluster-dns/nodelocaldns.yaml','deploy/gitops/cluster-dns/keycloak-ha-connector.yaml',
              'deploy/gitops/cluster-dns/postgres-ha-connector.yaml','deploy/gitops/cluster-dns/service-route.yaml',
              'deploy/gitops/network-policy-engine/kube-router.yaml','deploy/gitops/longhorn-prerequisites/node-prerequisites.yaml',
              'deploy/gitops/longhorn-prerequisites/kustomization.yaml',
              'deploy/gitops/longhorn-prerequisites/snapshot-replica-reconcile.yaml',
              'deploy/gitops/longhorn-prerequisites/snapshot-replica-reconcile.py',
              'deploy/gitops/longhorn-prerequisites/test_snapshot_replica_reconcile.py',
              'deploy/gitops/flash-web/tls-sync-daemonset.yaml','deploy/gitops/envoy-gateway/redis-primary-proxy.yaml',
              'deploy/gitops/envoy-gateway/kustomization.yaml','deploy/gitops/envoy-gateway/public-web-dns.yaml',
              'deploy/gitops/envoy-gateway/envoyproxy.yaml','deploy/gitops/envoy-gateway/heterocloud-edge-local-proxy-service.yaml',
              'deploy/gitops/envoy-gateway/public-gateway-health.yaml',
              'deploy/gitops/envoy-gateway/README.md','deploy/gitops/envoy-gateway/heterocloud-flash-ssh-route.yaml',
              'deploy/gitops/envoy-gateway/flash-ssh-backend-traffic-policy.yaml']
    paths += ['deploy/public-dns-witness/'+n for n in ['.gitignore','bootstrap.py','worker.mjs','worker.test.mjs','wrangler.toml']]
    for directory in ['deploy/terraform/master-only','deploy/terraform/github-dr-environment','deploy/gitops/control-plane-only','deploy/gitops/standard-nodes','deploy/gitops/gpu-runtime','deploy/gitops/cluster-dns','deploy/gitops/public-dns-quorum','deploy/gitops/custom-domains','scripts/storage-heartbeat-e2e']:
        for p in (ROOT/directory).rglob('*'):
            if not p.is_file() or '.terraform' in p.parts or '__pycache__' in p.parts: continue
            if p.suffix in ['.tf','.py','.yaml','.j2','.json','.md','.cfg','.sh'] or p.name=='.terraform.lock.hcl':
                paths.append(str(p.relative_to(ROOT)))
    return sorted(set(paths))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--work-dir',required=True)
    parser.add_argument('--branch',default='master')
    parser.add_argument('--committed-only', action='store_true',
                        help='bundle the checked-out committed branch without rewriting it')
    args=parser.parse_args()
    work=Path(args.work_dir).expanduser().resolve()
    work.mkdir(parents=True,exist_ok=True)
    work.chmod(0o700)
    if args.committed_only:
        branch = subprocess.check_output(['git', 'symbolic-ref', '--quiet', '--short', 'HEAD'], cwd=ROOT, text=True).strip()
        if branch != args.branch:
            raise ValueError('the checked-out branch does not match the bundle branch')
        dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
        if dirty:
            raise ValueError('committed-only publication requires a clean checkout')
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory(prefix='hnn-iac-bundle-', dir=work) as tmp:
            bundle = Path(tmp) / 'infrastructure.bundle'
            subprocess.run(['git', 'bundle', 'create', '--quiet', str(bundle), 'refs/heads/' + branch], cwd=ROOT, check=True)
            bundle.chmod(0o600)
            os.replace(bundle, work / 'infrastructure.bundle')
        print(json.dumps({'commit': commit, 'branch': branch, 'bundle': str(work / 'infrastructure.bundle')}))
        return
    paths=files()
    for path in paths:
        text=(ROOT/path).read_text()
        assert not re.search(r'(?m)^-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----$',text)
    subprocess.run(['python3',str(ROOT/'deploy/terraform/master-only/render.py')],cwd=ROOT,check=True)
    env=os.environ.copy()
    env.update({'GIT_AUTHOR_NAME':'Codex','GIT_AUTHOR_EMAIL':'codex@localhost',
                'GIT_COMMITTER_NAME':'Codex','GIT_COMMITTER_EMAIL':'codex@localhost'})
    def git(*cmd): return subprocess.check_output(['git',*cmd],cwd=ROOT,env=env,text=True).strip()
    ref='refs/heads/'+args.branch
    previous=subprocess.run(['git','rev-parse','--verify',ref],cwd=ROOT,text=True,capture_output=True)
    parent=previous.stdout.strip() if previous.returncode==0 else git('rev-parse','HEAD')
    with tempfile.TemporaryDirectory(prefix='hnn-iac-index-',dir=work) as tmp:
        env['GIT_INDEX_FILE']=str(Path(tmp)/'index')
        git('read-tree',parent)
        git('add','--',*paths)
        tree=git('write-tree')
        if tree==git('rev-parse',parent+'^{tree}'): commit=parent
        else: commit=git('commit-tree',tree,'-p',parent,'-m','Manage HeteroNetwork hosts with Terraform and Argo CD')
        git('update-ref',ref,commit,previous.stdout.strip() if previous.returncode==0 else '0'*40)
        git('bundle','create',str(work/'infrastructure.bundle'),ref)
    (work/'infrastructure.bundle').chmod(0o600)
    print(json.dumps({'commit':commit,'branch':args.branch,'files':len(paths),'bundle':str(work/'infrastructure.bundle')}))


if __name__=='__main__': main()
