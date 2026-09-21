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
  # v0.1.15-dev.26, source f7f342d42fbbad64ea4842adc61879df1aae6a93.
  default = {
    ipars  = "9d986a781fb962035c884cf653de1ca90f4cb5a7dc79b921857af8eabd038092"
    iparsd = "4032bf7c37eced9a74a567ac4e104e14eae70c65c57c359430ce1dc6108afe1e"
  }
}
