locals {
  repo_root = abspath("${path.module}/../../..")
  nodes     = jsondecode(file("${path.module}/nodes.json"))
  managed_app_paths = {
    cluster-dns            = "deploy/gitops/cluster-dns"
    network-policy-engine  = "deploy/gitops/network-policy-engine"
    longhorn-prerequisites = "deploy/gitops/longhorn-prerequisites"
    flash-web              = "deploy/gitops/flash-web"
    heterocloud-edge       = "deploy/gitops/envoy-gateway"
  }
  bootstrap = {
    ssh_host     = "163.220.236.45"
    ssh_host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK038K5HfhW5BFKcXXK22/AunAU2mk2osPM98e0eZ1VI"
  }
  bundle_sha = sha256(join("", concat(
    [filesha256("${local.repo_root}/scripts/kubeadm-ha-node.sh")],
    [for f in sort(tolist(fileset(path.module, "ansible/**"))) : filesha256("${path.module}/${f}")
    if f != "ansible/git-source.yaml" && (endswith(f, ".yaml") || endswith(f, ".j2") || endswith(f, ".py"))],
    [sha256(jsonencode(var.native_binary_sha256))]
  )))
  inventory = {
    all = {
      vars = {
        ansible_user                 = "mizuame"
        ansible_ssh_private_key_file = pathexpand(var.ssh_private_key_path)
        ansible_ssh_common_args      = "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=${abspath(var.work_dir)}/known_hosts"
        hnn_repo_root                = local.repo_root
        hnn_work_dir                 = abspath(var.work_dir)
        hnn_control_planes           = var.control_planes
        hnn_native_binary_sha256     = var.native_binary_sha256
        hnn_git_revision             = var.git_revision
      }
      children = {
        master_only = {
          hosts = { for name, node in local.nodes : name => merge(node, { ansible_host = node.ssh_host }) }
        }
        bootstrap = {
          hosts = { uc-k8sp5 = { ansible_host = local.bootstrap.ssh_host } }
        }
      }
    }
  }
}

resource "local_file" "known_hosts" {
  filename             = "${abspath(var.work_dir)}/known_hosts"
  file_permission      = "0600"
  directory_permission = "0700"
  content = join("\n", concat(
    [for name, node in local.nodes : "${node.ssh_host} ${node.ssh_host_key}"],
    ["${local.bootstrap.ssh_host} ${local.bootstrap.ssh_host_key}", ""]
  ))
}

resource "local_file" "inventory" {
  filename             = "${abspath(var.work_dir)}/inventory.json"
  file_permission      = "0600"
  directory_permission = "0700"
  content              = jsonencode(local.inventory)
}

import {
  for_each = local.managed_app_paths
  to       = kubernetes_manifest.application_source[each.key]
  id       = "apiVersion=argoproj.io/v1alpha1,kind=Application,namespace=argocd,name=${each.key}"
}

resource "kubernetes_manifest" "application_source" {
  for_each = local.managed_app_paths
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata   = { name = each.key, namespace = "argocd" }
    spec = {
      source = {
        repoURL        = var.git_repository_url
        targetRevision = var.git_revision
        path           = each.value
      }
    }
  }
  field_manager {
    name            = "heteronetwork-terraform"
    force_conflicts = true
  }
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.git_source, kubernetes_manifest.gitops_project]
}

resource "terraform_data" "host_configuration" {
  for_each = local.nodes
  input = {
    name    = each.key
    vpn_ip  = each.value.vpn_ip
    profile = "control-plane-only"
  }
  triggers_replace = [local.bundle_sha, sha256(jsonencode(each.value)), sha256(jsonencode(var.control_planes))]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" --limit \"$HNN_IAC_NODE\" ansible/masters.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      HNN_IAC_NODE             = each.key
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.known_hosts, local_file.inventory]
}

resource "kubernetes_manifest" "master_only_application" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "control-plane-only"
      namespace = "argocd"
    }
    spec = {
      project = "hetero-platform"
      source = {
        repoURL        = var.git_repository_url
        targetRevision = var.git_revision
        path           = "deploy/gitops/control-plane-only"
      }
      destination = {
        server    = "https://kubernetes.default.svc"
        namespace = "kube-system"
      }
      ignoreDifferences = [{ kind = "Node", jsonPointers = ["/spec/taints"] }]
      syncPolicy = {
        automated   = { enabled = true, prune = true, selfHeal = true }
        retry       = { limit = 10, backoff = { duration = "5s", factor = 2, maxDuration = "3m" } }
        syncOptions = ["ServerSideApply=true", "RespectIgnoreDifferences=true", "DisableClientSideApplyMigration=true"]
      }
    }
  }
  field_manager { name = "heteronetwork-terraform" }
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.host_configuration, terraform_data.git_source, kubernetes_manifest.gitops_project]
}

resource "terraform_data" "git_source" {
  triggers_replace = [filesha256("${abspath(var.work_dir)}/infrastructure.bundle"), filesha256("${path.module}/ansible/git-source.yaml"), var.git_revision]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/git-source.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}

import {
  to = kubernetes_manifest.gitops_project
  id = "apiVersion=argoproj.io/v1alpha1,kind=AppProject,namespace=argocd,name=hetero-platform"
}

resource "kubernetes_manifest" "gitops_project" {
  manifest = yamldecode(file("${local.repo_root}/deploy/gitops/project.yaml"))
  field_manager {
    name            = "heteronetwork-terraform"
    force_conflicts = true
  }
  lifecycle { prevent_destroy = true }
}
