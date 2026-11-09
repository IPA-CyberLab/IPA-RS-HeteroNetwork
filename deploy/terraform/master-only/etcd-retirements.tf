resource "terraform_data" "etcd_retirements" {
  input = jsondecode(file("${path.module}/etcd-retirements.json"))
  triggers_replace = [
    filesha256("${path.module}/etcd-retirements.json"),
    filesha256("${path.module}/overlay-boot-peers.json"),
    filesha256("${local.repo_root}/scripts/reconcile-etcd-retirements.py"),
  ]

  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "python3 \"$HNN_REPO/scripts/reconcile-etcd-retirements.py\" --kubeconfig \"$HNN_KUBECONFIG\" --intent etcd-retirements.json --roster overlay-boot-peers.json --backup-dir \"$HNN_BACKUP_DIR\""
    environment = {
      HNN_REPO       = local.repo_root
      HNN_KUBECONFIG = abspath(var.kubeconfig_path)
      HNN_BACKUP_DIR = "${abspath(var.work_dir)}/etcd-backups"
    }
  }
}
