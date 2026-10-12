resource "terraform_data" "resource_monitoring" {
  triggers_replace = [
    filesha256("${local.repo_root}/scripts/reconcile-resource-monitoring.sh"),
    filesha256("${local.repo_root}/deploy/monitoring/resource-services.sql"),
    filesha256("${path.module}/ansible/resource-monitoring.yaml")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/resource-monitoring.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
