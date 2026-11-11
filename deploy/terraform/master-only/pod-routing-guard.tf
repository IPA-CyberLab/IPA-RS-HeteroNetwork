resource "terraform_data" "pod_routing_guard" {
  triggers_replace = [
    sha256(jsonencode(local.inventory)),
    filesha256("${path.module}/pod-routing-policy.json"),
    filesha256("${path.module}/ansible/pod-routing-guard.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-pod-routing.sh"),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/pod-routing-guard.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }

  depends_on = [local_file.inventory, local_file.known_hosts]
}
