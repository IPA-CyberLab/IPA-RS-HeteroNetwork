resource "terraform_data" "heterocloud_organization_registry" {
  triggers_replace = [
    local.heterocloud_quota_rollout_digest,
    filesha256("${local.repo_root}/scripts/activate_heterocloud_org_registry.py"),
    filesha256("${local.repo_root}/scripts/verify-heterocloud-iam-rollout.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/activate_heterocloud_org_registry.py --digest \"$HNN_CLOUD_DIGEST\" --replicas 2 --desired-replicas 3"
    environment = {
      KUBECONFIG       = pathexpand(var.kubeconfig_path)
      HNN_CLOUD_DIGEST = local.heterocloud_quota_rollout_digest
    }
  }
  depends_on = [terraform_data.heterocloud_organization_quotas, terraform_data.heterocloud_iam_conditions]
}
