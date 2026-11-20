variable "heteronetwork_private_console_origins" {
  type        = list(string)
  description = "VPN-only console origins allowed to finish private owner sign-in."
  default = [
    "http://console.heteronetwork.internal",
    "http://console.heteronetwork.internal:9781",
  ]
}

resource "terraform_data" "private_identity_client" {
  triggers_replace = [
    filesha256("${path.module}/ansible/private-identity-client.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-private-oidc-client.py"),
    sha256(jsonencode(var.heteronetwork_private_console_origins)),
  ]

  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/private-identity-client.yaml"
    environment = {
      HNN_IAC_INVENTORY           = local_file.inventory.filename
      HNN_PRIVATE_CONSOLE_ORIGINS = jsonencode(var.heteronetwork_private_console_origins)
      ANSIBLE_CALLBACK_PLUGINS    = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK     = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
