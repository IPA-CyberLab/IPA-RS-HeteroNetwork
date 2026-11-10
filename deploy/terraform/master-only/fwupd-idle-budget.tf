resource "terraform_data" "fwupd_idle_budget" {
  triggers_replace = [
    filesha256("${path.module}/ansible/fwupd-idle-budget.yaml"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/fwupd-idle-budget.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
