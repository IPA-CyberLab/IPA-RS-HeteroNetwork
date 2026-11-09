resource "terraform_data" "receive_steering_ichikawa" {
  triggers_replace = [
    filesha256("${path.module}/receive-steering-ichikawa.json"),
    filesha256("${path.module}/ansible/receive-steering-ichikawa.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-receive-steering.py"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/receive-steering-ichikawa.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
