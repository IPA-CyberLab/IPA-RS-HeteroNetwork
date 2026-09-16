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
    ipars  = "167defe5933cbb3b452af0d8ec3edd2a4f99a5fbb5f02c360959ee6b3eee75f6"
    iparsd = "26c024cb3ec237cbbadc23abd921f4b33eb96332d70d89264c6a705fc42ac2b6"
  }
}
