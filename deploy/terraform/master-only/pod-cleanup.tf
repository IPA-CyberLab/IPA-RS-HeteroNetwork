resource "terraform_data" "pod_cleanup" {
  triggers_replace = [
    filesha256("${path.module}/ansible/pod-cleanup.yaml"),
    filesha256("${local.repo_root}/scripts/prune-terminal-pods.py"),
    filesha256("${local.repo_root}/scripts/node_lifecycle.py"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/pod-cleanup.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
