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
  # Hierarchy candidate, GitHub Actions 43690664637, source 92f5cd876ac0d3476487d4ebd33dbd8a59609bcc.
  default = {
    ipars  = "0e6bfb1a0ec10fc6b70059129942df2864ee582480a5b2997ca74c3d8c41e8da"
    iparsd = "5e2296dd34b3d61acf874feacd74d36a222be89e6fad99632f87447914194c92"
  }
}
