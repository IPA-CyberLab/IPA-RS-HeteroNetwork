resource "terraform_data" "binary_cleanup" {
  triggers_replace = [
    filesha256("${path.module}/ansible/binary-cleanup.yaml"),
    filesha256("${local.repo_root}/scripts/prune-control-plane-releases.py"),
    var.control_plane_topology_binary_sha256,
    sha256(jsonencode(local.inventory)),
  ]

  provisioner "local-exec" {
    working_dir = path.module
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/binary-cleanup.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      HNN_CONTROL_PLANE_SHA256 = var.control_plane_topology_binary_sha256
    }
  }

  depends_on = [local_file.inventory, local_file.known_hosts, terraform_data.control_plane_topology_rollout]
}
