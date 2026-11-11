resource "terraform_data" "cache_cleanup" {
  triggers_replace = [
    filesha256("${path.module}/ansible/cache-cleanup.yaml"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/cache-cleanup.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
