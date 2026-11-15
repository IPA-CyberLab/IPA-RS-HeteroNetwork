variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "ssh_private_key_path" {
  type        = string
  description = "Path to the operator SSH key. Its contents never enter Terraform state."
}

variable "work_dir" {
  type        = string
  description = "Private operator directory for inventory, logs and the native binary archive."
}

variable "git_revision" {
  type    = string
  default = "master"
}

variable "git_repository_url" {
  type    = string
  default = "git://10.250.0.2:19419/heteronetwork-infrastructure.git"
}

variable "control_planes" {
  type    = list(string)
  default = ["10.250.0.2", "10.250.0.4", "10.250.0.5", "10.250.0.6", "10.250.0.10"]
}

variable "native_binary_sha256" {
  type = map(string)
  # Hierarchy candidate, GitHub Actions 43676701205, source 9b68a2baf9b47ee20b2356c61a43de560a1c4a42.
  default = {
    ipars  = "6f48e3163954001172a4612befb307ba4111f7525f3183f2458524ea97246f9f"
    iparsd = "761e171657aef9c65b5b96761c4f37ce4aaab609ad606045f7378d5c9de64529"
  }
}
