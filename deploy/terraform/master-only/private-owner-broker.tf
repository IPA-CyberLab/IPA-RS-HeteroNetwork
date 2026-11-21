locals {
  heteronetwork_cloud_owner_issuer = jsondecode(file("${path.module}/private-owner-broker.json")).cloud_issuer
}

resource "terraform_data" "private_cloud_owner_broker" {
  triggers_replace = [
    filesha256("${path.module}/private-owner-broker.json"),
    filesha256("${path.module}/ansible/private-owner-broker.yaml"),
    filesha256("${local.repo_root}/scripts/reconcile-heterocloud-owner-broker.py"),
    filesha256("${local.repo_root}/scripts/reconcile-private-oidc-client.py"),
    local.heteronetwork_cloud_owner_issuer,
    var.heteronetwork_private_identity_origin,
  ]

  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/private-owner-broker.yaml"
    environment = {
      HNN_IAC_INVENTORY           = local_file.inventory.filename
      HNN_CLOUD_IDENTITY_ISSUER   = local.heteronetwork_cloud_owner_issuer
      HNN_PRIVATE_IDENTITY_ORIGIN = var.heteronetwork_private_identity_origin
      ANSIBLE_CALLBACK_PLUGINS    = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK     = "hnn_json"
    }
  }
  depends_on = [terraform_data.private_identity_client]
}
