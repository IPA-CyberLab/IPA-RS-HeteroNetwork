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
  # Network-aware candidate, GitHub Actions 44055014302, source 6710f5b6fbb74a05750c1bb92b0ac9c54e9ea018.
  default = {
    ipars  = "bfa582b2d813955105e3741ebb82c2114c974f3220dafb389a4c6bb8135ac79e"
    iparsd = "092203b8ff013946a2d8a505db5b3eb5c305c755950f893a2efba55efa127bee"
  }
}
