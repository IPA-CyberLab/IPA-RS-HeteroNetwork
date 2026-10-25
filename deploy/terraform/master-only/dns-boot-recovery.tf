resource "terraform_data" "dns_boot_recovery" {
  triggers_replace = [
    filesha256("${local.repo_root}/scripts/reconcile-dns-boot-recovery.py"),
    filesha256("${local.repo_root}/deploy/gitops/cluster-dns/coredns.yaml")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/reconcile-dns-boot-recovery.py"
    environment = { KUBECONFIG = pathexpand(var.kubeconfig_path) }
  }
  depends_on = [terraform_data.git_source]
}
