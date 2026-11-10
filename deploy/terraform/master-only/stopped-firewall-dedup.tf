resource "terraform_data" "stopped_firewall_dedup" {
  triggers_replace = [
    filesha256("${path.module}/ansible/stopped-firewall-dedup.yaml"),
    filesha256("${path.module}/overlay-boot-peers.json"),
    filesha256("${local.repo_root}/scripts/reconcile-stopped-overlay-firewall.py"),
    filesha256("${local.repo_root}/scripts/node_lifecycle.py"),
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/stopped-firewall-dedup.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
