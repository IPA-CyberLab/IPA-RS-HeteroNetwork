resource "terraform_data" "kubelet_dns" {
  triggers_replace = [
    filesha256("${path.module}/ansible/kubelet-dns.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-kubelet-dns.sh"),
    filesha256("${path.module}/nodes.json"),
    filesha256("${path.module}/standard-nodes.json")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/kubelet-dns.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
