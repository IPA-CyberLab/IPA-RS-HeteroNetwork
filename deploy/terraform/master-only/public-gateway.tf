resource "terraform_data" "public_gateway_stage" {
  triggers_replace = [
    filesha256("${path.module}/ansible/public-gateway-stage.yaml"),
    filesha256("${path.module}/ansible/templates/public-gateway-secondary.Caddyfile.j2"),
    sha256(jsonencode(local.bootstrap)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/public-gateway-stage.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}

resource "terraform_data" "public_gateway_activate" {
  triggers_replace = [
    filesha256("${path.module}/ansible/public-gateway-activate.yaml"),
    sha256(jsonencode(local.bootstrap)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/public-gateway-activate.yaml"
    environment = { HNN_IAC_INVENTORY = local_file.inventory.filename }
  }
  depends_on = [terraform_data.public_gateway_stage]
}
