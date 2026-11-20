variable "heteronetwork_private_console_auth_enabled" {
  type        = bool
  description = "Enable only after the existing owner has verified sign-in to the private realm."
  default     = false
}

variable "heteronetwork_private_identity_origin" {
  type        = string
  description = "VPN-only identity origin used for HeteroNetwork management sign-in."
  default     = "http://console.heteronetwork.internal:18079"
}

locals {
  heteronetwork_private_identity_ips = distinct([
    for node in [local.bootstrap, local.enrollment_issuer] : node.vpn_ip
    if !contains(local.stopped_hosts, node.name)
  ])
}

resource "terraform_data" "private_console_auth" {
  count = var.heteronetwork_private_console_auth_enabled ? 1 : 0
  triggers_replace = [
    filesha256("${path.module}/ansible/private-console-auth.yaml"),
    filesha256("${path.module}/ansible/private-console-rollback-host.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-private-console-auth.py"),
    filesha256("${local.repo_root}/scripts/verify-private-owner-proof.py"),
    var.heteronetwork_private_identity_origin,
    sha256(jsonencode(local.heteronetwork_private_identity_ips)),
  ]

  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/private-console-auth.yaml"
    environment = {
      HNN_IAC_INVENTORY           = local_file.inventory.filename
      HNN_PRIVATE_IDENTITY_ORIGIN = var.heteronetwork_private_identity_origin
      HNN_PRIVATE_IDENTITY_IPS    = jsonencode(local.heteronetwork_private_identity_ips)
      ANSIBLE_CALLBACK_PLUGINS    = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK     = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts, terraform_data.private_identity_client]
}
