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
  # v0.1.15-dev.29, source c305077777566d9e3cc768a66b26343c48e0bf1c.
  default = {
    ipars  = "0c0a90d71d8cf0d5c86f726ca64d10441af3e38dfdc01b0d3780fe5ed0035d6f"
    iparsd = "54ab285b394a2a49c3fe00808ee61a560f67aa5e58760fb0bb68670ac34c2466"
  }
}
