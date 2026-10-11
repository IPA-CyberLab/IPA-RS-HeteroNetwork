resource "terraform_data" "etcd_policy" {
  triggers_replace = [
    filesha256("${path.module}/ansible/etcd-policy.yaml"),
    filesha256("${local.repo_root}/scripts/verify-etcd-policy.py"),
    filesha256("${local.repo_root}/scripts/kubeadm-ha-node.sh")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/etcd-policy.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
