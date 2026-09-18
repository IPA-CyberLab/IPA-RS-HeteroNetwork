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
  default = {
    ipars  = "6180a5a0a2fa6ad47bb80238507ce38086bdbca8e910a2a2f59c2a629dbbe927"
    iparsd = "0ea729eadbe67325ef49a680709dac08d5d1735779b701303a9b6db7f7923f69"
  }
}
