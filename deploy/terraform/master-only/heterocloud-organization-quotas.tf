locals {
  heterocloud_quota_rollout_digest = regex("@(sha256:[a-f0-9]{64})", yamldecode(file("${local.repo_root}/deploy/gitops/applications/heterocloud.yaml")).spec.source.helm.values)[0]
}

resource "terraform_data" "heterocloud_organization_quotas" {
  triggers_replace = [
    local.heterocloud_quota_rollout_digest,
    filesha256("${local.repo_root}/scripts/activate_heterocloud_org_quotas.py"),
    filesha256("${local.repo_root}/scripts/verify-heterocloud-iam-rollout.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/activate_heterocloud_org_quotas.py --digest \"$HNN_CLOUD_DIGEST\" --replicas 2 --desired-replicas 3 --ssh-key \"$HNN_SSH_KEY\" --known-hosts \"$HNN_KNOWN_HOSTS\" --jump-host \"$HNN_JUMP_HOST\""
    environment = {
      KUBECONFIG       = pathexpand(var.kubeconfig_path)
      HNN_CLOUD_DIGEST = local.heterocloud_quota_rollout_digest
      HNN_SSH_KEY      = pathexpand(var.ssh_private_key_path)
      HNN_KNOWN_HOSTS  = local_file.known_hosts.filename
      HNN_JUMP_HOST    = "mizuame@${local.bootstrap.ssh_host}"
    }
  }
  depends_on = [local_file.known_hosts]
}
