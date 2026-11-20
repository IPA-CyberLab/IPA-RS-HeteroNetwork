variable "heteronetwork_retire_public_owner_client" {
  type        = bool
  description = "Disable the public legacy owner client only after both private control planes authorize the owner."
  default     = false
}

resource "terraform_data" "retire_public_owner_client" {
  count = var.heteronetwork_private_console_auth_enabled && var.heteronetwork_retire_public_owner_client ? 1 : 0
  triggers_replace = [
    filesha256("${path.module}/ansible/private-owner-retirement.yaml"),
    filesha256("${local.repo_root}/scripts/retire-public-owner-client.py"),
    filesha256("${local.repo_root}/scripts/verify-private-owner-proof.py"),
    filesha256("${local.repo_root}/scripts/reconcile-private-oidc-client.py"),
    var.heteronetwork_private_identity_origin,
    sha256(jsonencode(local.heteronetwork_private_identity_ips)),
  ]

  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/private-owner-retirement.yaml"
    environment = {
      HNN_IAC_INVENTORY           = local_file.inventory.filename
      HNN_PRIVATE_IDENTITY_ORIGIN = var.heteronetwork_private_identity_origin
      HNN_PRIVATE_IDENTITY_IPS    = jsonencode(local.heteronetwork_private_identity_ips)
      ANSIBLE_CALLBACK_PLUGINS    = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK     = "hnn_json"
    }
  }
  depends_on = [terraform_data.private_console_auth]
}
