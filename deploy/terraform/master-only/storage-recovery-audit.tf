resource "terraform_data" "storage_recovery_audit" {
  triggers_replace = [
    filesha256("${local.repo_root}/scripts/verify-storage-redundancy.py"),
    filesha256("${path.module}/ansible/storage-recovery-audit.yaml")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/storage-recovery-audit.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
