# The short-lived CODER_SESSION_TOKEN is inherited by local-exec at apply time;
# it is never a Terraform variable, trigger, output or stored state value.
resource "terraform_data" "coder_workspace_image" {
  triggers_replace = [
    filesha256("${local.repo_root}/deploy/coder/workspace-image.json"),
    filesha256("${local.repo_root}/scripts/reconcile-coder-workspace-image.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/reconcile-coder-workspace-image.py --config deploy/coder/workspace-image.json"
  }
  depends_on = [kubernetes_manifest.external_application["heterocloud-flash"]]
}
