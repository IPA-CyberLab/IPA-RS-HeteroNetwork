terraform {
  required_version = ">= 1.10, < 2.0"
  backend "kubernetes" {
    namespace     = "argocd"
    secret_suffix = "heteronetwork-master-only"
  }
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.38, < 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.5, < 3.0"
    }
  }
}

provider "kubernetes" {
  config_path = pathexpand(var.kubeconfig_path)
}
