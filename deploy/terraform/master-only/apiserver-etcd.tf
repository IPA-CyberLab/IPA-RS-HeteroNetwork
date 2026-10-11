resource "terraform_data" "apiserver_etcd_client_policy" {
  input = jsondecode(file("${path.module}/apiserver-etcd-policy.json"))
  triggers_replace = [
    filesha256("${path.module}/apiserver-etcd-policy.json"),
    filesha256("${path.module}/ansible/apiserver-etcd.yaml"),
    filesha256("${local.repo_root}/scripts/verify-apiserver-etcd.py")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/apiserver-etcd.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
