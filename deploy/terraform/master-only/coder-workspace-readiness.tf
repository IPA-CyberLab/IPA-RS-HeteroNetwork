# CODER_SESSION_TOKEN is inherited only by the provisioner; it is not stored
# in Terraform variables, triggers, outputs, or state.
resource "terraform_data" "coder_workspace_readiness" {
  triggers_replace = [
    filesha256("${local.repo_root}/deploy/coder/workspace-readiness.json"),
    filesha256("${local.repo_root}/scripts/reconcile-coder-workspace-readiness.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/reconcile-coder-workspace-readiness.py --config deploy/coder/workspace-readiness.json"
  }
  depends_on = [terraform_data.coder_workspace_image]
}
