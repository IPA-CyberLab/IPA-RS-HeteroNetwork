resource "terraform_data" "flash_operations" {
  triggers_replace = [
    filesha256("${local.repo_root}/scripts/provision-flash-operations.py"),
    filesha256("${path.module}/ansible/flash-operations.yaml")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "ansible-playbook -i ${abspath(var.work_dir)}/inventory.json deploy/terraform/master-only/ansible/flash-operations.yaml"
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
