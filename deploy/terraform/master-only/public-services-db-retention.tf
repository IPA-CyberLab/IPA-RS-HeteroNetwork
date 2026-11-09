resource "terraform_data" "public_services_db_retention" {
  triggers_replace = [
    filesha256("${path.module}/ansible/public-services-db-retention.yaml"),
    filesha256("${local.repo_root}/scripts/public-services-autopilot.sh"),
    filesha256("${local.repo_root}/scripts/patch-legacy-public-services-db.py"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/public-services-db-retention.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
