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
  default = "codex/flash-gpu-iac-20260916"
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
  default = {
    ipars  = "65bac35227f48864e990fc7fea35bbc356f0bf4356d44f2a4ad23fe72c2dfe3d"
    iparsd = "38793facec1120c5e800d9f086c3b5af9d44ad7749f685ec93e9a3de40b725a7"
  }
}
