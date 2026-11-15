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
  # Hierarchy candidate, GitHub Actions 43687667849, source 2731c612e143b791e0087908f7000c495f20c545.
  default = {
    ipars  = "4e4b490433780309309341d0359df1c09e096fa77b57a65cf4bafa792ed655c0"
    iparsd = "22238a17d23c15ea4b3a5fe5b2b869b8cf36f0d4f1591c5768f50979cdca8fa2"
  }
}
