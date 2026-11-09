terraform {
  required_version = ">= 1.5.0"
}

locals {
  root   = abspath("${path.module}/../../..")
  config = jsondecode(file("${path.module}/environment.json"))
}

resource "terraform_data" "dr_environment" {
  input = local.config
  triggers_replace = [
    filesha256("${path.module}/environment.json"),
    filesha256("${local.root}/scripts/reconcile-github-dr-environment.py"),
  ]

  provisioner "local-exec" {
    working_dir = local.root
    command     = "python3 scripts/reconcile-github-dr-environment.py --config deploy/terraform/github-dr-environment/environment.json"
  }
}
