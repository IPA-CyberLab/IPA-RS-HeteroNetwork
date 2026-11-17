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
  # Hierarchy candidate, GitHub Actions 44026722221, source dd1cfe0e2ae677db86bebc084107614b8b04ef41.
  default = {
    ipars  = "3d6bf949bd531be0dd0d336a21169afb07570832c22a7ac5456d8a281789f9d6"
    iparsd = "691b597a8633f4552e18be4ca2313ae2b88c2ba5e847eb6705314640a3ace75e"
  }
}
