resource "terraform_data" "public_dns_witness" {
  triggers_replace = [
    filesha256("${local.repo_root}/deploy/public-dns-witness/bootstrap.py"),
    filesha256("${local.repo_root}/deploy/public-dns-witness/worker.mjs"),
    filesha256("${local.repo_root}/deploy/public-dns-witness/wrangler.toml"),
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 deploy/public-dns-witness/bootstrap.py --work-dir \"$HNN_IAC_WORK_DIR\" --kubeconfig \"$HNN_IAC_KUBECONFIG\""
    environment = {
      HNN_IAC_WORK_DIR   = abspath(var.work_dir)
      HNN_IAC_KUBECONFIG = pathexpand(var.kubeconfig_path)
    }
  }
}
