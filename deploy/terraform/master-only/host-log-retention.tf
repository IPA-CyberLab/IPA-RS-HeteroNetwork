resource "terraform_data" "host_log_retention" {
  triggers_replace = [
    sha256(jsonencode(local.inventory)),
    filesha256("${path.module}/ansible/host-log-retention.yaml"),
    filesha256("${path.module}/ansible/files/rsyslog-retention.conf"),
    filesha256("${path.module}/ansible/files/journald-retention.conf.j2"),
    filesha256("${path.module}/ansible/files/logrotate-hourly.conf")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/host-log-retention.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
