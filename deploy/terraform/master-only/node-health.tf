resource "terraform_data" "node_health_policy" {
  input = jsondecode(file("${path.module}/node-health-policy.json"))
  triggers_replace = [
    filesha256("${path.module}/node-health-policy.json"),
    filesha256("${path.module}/ansible/node-health.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-node-health.py")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/node-health.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
