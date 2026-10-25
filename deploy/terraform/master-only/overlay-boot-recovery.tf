resource "terraform_data" "overlay_boot_recovery" {
  for_each = toset(concat(keys(local.nodes), keys(local.gvisor_workers)))
  triggers_replace = [
    filesha256("${path.module}/ansible/overlay-boot-recovery.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-overlay-boot.py"),
    filesha256("${path.module}/overlay-boot-peers.json")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/overlay-boot-recovery.yaml --limit \"$HNN_IAC_HOST\""
    environment = {
      HNN_IAC_HOST             = each.key
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
