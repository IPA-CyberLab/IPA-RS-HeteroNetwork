resource "terraform_data" "postgres_dcs_metrics" {
  triggers_replace = [
    filesha256("${path.module}/ansible/postgres-dcs-metrics.yaml"),
    filesha256("${local.repo_root}/scripts/postgres-dcs-metrics.py"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/postgres-dcs-metrics.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
