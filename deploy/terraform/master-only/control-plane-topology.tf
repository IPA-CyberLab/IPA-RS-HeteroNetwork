variable "control_plane_topology_binary_sha256" {
  type        = string
  description = "SHA-256 of the tested control-plane binary staged in work_dir; empty disables this rollout."
  # Hierarchy candidate, GitHub Actions 44055014302, source 6710f5b6fbb74a05750c1bb92b0ac9c54e9ea018.
  default = "092203b8ff013946a2d8a505db5b3eb5c305c755950f893a2efba55efa127bee"
  validation {
    condition     = var.control_plane_topology_binary_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.control_plane_topology_binary_sha256))
    error_message = "The control-plane binary digest must be a lowercase SHA-256."
  }
}

resource "terraform_data" "control_plane_topology_rollout" {
  count = var.control_plane_topology_binary_sha256 == "" ? 0 : 1
  triggers_replace = [
    var.control_plane_topology_binary_sha256,
    filesha256("${path.module}/ansible/control-plane-topology.yaml"),
    filesha256("${path.module}/overlay-boot-peers.json")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/control-plane-topology.yaml"
    environment = {
      HNN_CONTROL_PLANE_SHA256 = var.control_plane_topology_binary_sha256
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}
