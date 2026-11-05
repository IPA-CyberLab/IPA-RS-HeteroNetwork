# A short-lived CODER_SESSION_TOKEN is inherited by local-exec only; it is not
# stored in Terraform variables, triggers, outputs, or state. Existing workspace
# schedules are deliberately left as individual user choices on later applies.
resource "terraform_data" "coder_workspace_scheduling" {
  triggers_replace = [
    filesha256("${local.repo_root}/deploy/coder/workspace-scheduling.json"),
    filesha256("${local.repo_root}/scripts/reconcile-coder-template-scheduling.py"),
    filesha256("${local.repo_root}/scripts/reconcile-coder-workspace-readiness.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/reconcile-coder-template-scheduling.py --config deploy/coder/workspace-scheduling.json"
  }
  depends_on = [kubernetes_manifest.external_application["heterocloud-flash"]]
}
