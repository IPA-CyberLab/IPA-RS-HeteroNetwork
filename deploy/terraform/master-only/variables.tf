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
  # Hierarchy candidate, GitHub Actions 43684146035, source 985e184d5480eaa3f5579e8dc9a0f838588ffb60.
  default = {
    ipars  = "4e4b490433780309309341d0359df1c09e096fa77b57a65cf4bafa792ed655c0"
    iparsd = "7b3fb02b86c768a62f434ab2d7c31ff8d5a4b0cad32d052e0120ae087dc4abc3"
  }
}
