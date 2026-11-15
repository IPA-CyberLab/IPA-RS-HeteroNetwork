resource "terraform_data" "overlay_hierarchy_policy" {
  input = jsondecode(file("${path.module}/overlay-hierarchy.json"))
  triggers_replace = [
    filesha256("${path.module}/overlay-hierarchy.json"),
    filesha256("${local.repo_root}/scripts/reconcile-overlay-hierarchy.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/reconcile-overlay-hierarchy.py --config \"$HNN_HIERARCHY_POLICY\""
    environment = {
      HNN_HIERARCHY_POLICY = abspath("${path.module}/overlay-hierarchy.json")
    }
  }
  depends_on = [terraform_data.console_configuration, terraform_data.control_plane_topology_rollout]
}
