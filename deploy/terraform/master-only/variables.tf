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
  # v0.1.15-dev.27, source 1f2341c60b751331b22b37771511ac6f213c13bc.
  default = {
    ipars  = "cf49968e0c34f47896e029bcc1a3cf1a3155497ca5d8a31847ebda8f911e9297"
    iparsd = "590385d6821dbff351d0caf6c7b3328efe0f3a1b3320f40ee5b2f9da5d4e6440"
  }
}
