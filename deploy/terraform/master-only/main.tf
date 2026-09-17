locals {
  repo_root      = abspath("${path.module}/../../..")
  nodes          = jsondecode(file("${path.module}/nodes.json"))
  standard_nodes = jsondecode(file("${path.module}/standard-nodes.json"))
  gpu_expected_nodes = {
    uc-k8sp5 = 2
  }
  enrollment_issuer = {
    ssh_host     = "10.250.0.10"
    ssh_host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPW2fAH9gcshjerH7rdbXQU/siGharkb0JZHClS2YuPT"
  }
  managed_app_paths = {
    cluster-dns            = "deploy/gitops/cluster-dns"
    network-policy-engine  = "deploy/gitops/network-policy-engine"
    longhorn-prerequisites = "deploy/gitops/longhorn-prerequisites"
    flash-web              = "deploy/gitops/flash-web"
    heterocloud-edge       = "deploy/gitops/envoy-gateway"
  }
  managed_external_application_files = {
    heterocloud       = "deploy/gitops/applications/heterocloud.yaml"
    heterocloud-flash = "deploy/gitops/applications/heterocloud-flash.yaml"
  }
  bootstrap = {
    ssh_host     = "163.220.236.45"
    ssh_host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK038K5HfhW5BFKcXXK22/AunAU2mk2osPM98e0eZ1VI"
  }
  bundle_sha = sha256(join("", concat(
    [filesha256("${local.repo_root}/scripts/kubeadm-ha-node.sh")],
    [for f in sort(tolist(fileset(path.module, "ansible/**"))) : filesha256("${path.module}/${f}")
    if f != "ansible/git-source.yaml" && f != "ansible/gpu.yaml" && !strcontains(f, "/standard") && !strcontains(f, "/console") && (endswith(f, ".yaml") || endswith(f, ".j2") || endswith(f, ".py"))],
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
          hosts = { uc-k8sp5 = { ansible_host = local.bootstrap.ssh_host, gpu_expected_count = local.gpu_expected_nodes.uc-k8sp5 } }
        }
        standard = {
          hosts = { for name, node in local.standard_nodes : name => merge(node, { ansible_host = node.ssh_host }) }
        }
        enrollment_issuer = {
          hosts = {
            ichikawap1 = {
              ansible_host            = local.enrollment_issuer.ssh_host
              ansible_ssh_common_args = "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=${abspath(var.work_dir)}/known_hosts -o 'ProxyCommand=ssh -i ${pathexpand(var.ssh_private_key_path)} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${abspath(var.work_dir)}/known_hosts -W %h:%p mizuame@${local.bootstrap.ssh_host}'"
            }
          }
        }
        gpu_candidates = {
          hosts = merge(
            { uc-k8sp5 = { ansible_host = local.bootstrap.ssh_host, gpu_expected_count = local.gpu_expected_nodes.uc-k8sp5 } },
            { for name, node in local.standard_nodes : name => merge(node, { ansible_host = node.ssh_host }) },
            {
              ichikawap1 = {
                ansible_host            = local.enrollment_issuer.ssh_host
                ansible_ssh_common_args = "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=${abspath(var.work_dir)}/known_hosts -o 'ProxyCommand=ssh -i ${pathexpand(var.ssh_private_key_path)} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${abspath(var.work_dir)}/known_hosts -W %h:%p mizuame@${local.bootstrap.ssh_host}'"
              }
            }
          )
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
    [for name, node in local.standard_nodes : "${node.ssh_host} ${node.ssh_host_key}"],
    ["${local.enrollment_issuer.ssh_host} ${local.enrollment_issuer.ssh_host_key}"],
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

import {
  for_each = local.managed_external_application_files
  to       = kubernetes_manifest.external_application[each.key]
  id       = "apiVersion=argoproj.io/v1alpha1,kind=Application,namespace=argocd,name=${each.key}"
}

resource "kubernetes_manifest" "external_application" {
  for_each = local.managed_external_application_files
  manifest = yamldecode(file("${local.repo_root}/${each.value}"))
  field_manager {
    name            = "heteronetwork-terraform"
    force_conflicts = true
  }
  lifecycle { prevent_destroy = true }
  depends_on = [kubernetes_manifest.gitops_project]
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

resource "terraform_data" "console_configuration" {
  input = { hosts = concat(keys(local.nodes), keys(local.standard_nodes), ["uc-k8sp5", "ichikawap1"]), overlay_port = 9781, canonical_port = 80 }
  triggers_replace = [
    sha256(join("", [for f in sort(tolist(fileset(path.module, "ansible/console/**"))) : filesha256("${path.module}/${f}") if endswith(f, ".yaml") || endswith(f, ".j2")])),
    filesha256("${local.repo_root}/deploy/systemd/heteronetwork-agent-overlay-proxy.conf"),
    sha256(jsonencode(local.inventory)),
    sha256(jsonencode({ for name, host in terraform_data.host_configuration : name => host.id })),
    sha256(jsonencode({ for name, host in terraform_data.standard_host_configuration : name => host.id }))
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/console/configure.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.known_hosts, local_file.inventory, terraform_data.host_configuration, terraform_data.standard_host_configuration]
}

resource "terraform_data" "onboarding_acceptance" {
  input = { dedicated_masters = keys(local.nodes), standard_nodes = keys(local.standard_nodes), acceptance_requires = "live-e2e" }
  triggers_replace = [
    sha256(join("", [for f in ["scripts/accept-registered-nodes.py", "scripts/verify-console-gateways.mjs", "scripts/verify-master-only.py", "scripts/verify-standard-node.py"] : filesha256("${local.repo_root}/${f}")])),
    sha256(jsonencode({ for name, host in terraform_data.host_configuration : name => host.id })),
    sha256(jsonencode({ for name, host in terraform_data.standard_host_configuration : name => host.id })),
    terraform_data.console_configuration.id, terraform_data.git_source.id
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/accept-registered-nodes.py --work-dir \"$HNN_IAC_WORK_DIR\" --branch \"$HNN_IAC_BRANCH\""
    environment = {
      HNN_IAC_WORK_DIR = abspath(var.work_dir)
      HNN_IAC_BRANCH   = var.git_revision
      KUBECONFIG       = pathexpand(var.kubeconfig_path)
    }
  }
  depends_on = [terraform_data.console_configuration, terraform_data.gpu_acceptance, kubernetes_manifest.master_only_application, kubernetes_manifest.standard_application]
}

resource "terraform_data" "standard_host_configuration" {
  for_each = local.standard_nodes
  input    = { name = each.key, profile = "standard", workloads = "enabled", public_services = "enabled" }
  triggers_replace = [
    sha256(join("", concat(
      [for f in sort(tolist(fileset(path.module, "ansible/**"))) : filesha256("${path.module}/${f}") if strcontains(f, "/standard") && (endswith(f, ".yaml") || endswith(f, ".j2") || endswith(f, ".py"))],
      [filesha256("${local.repo_root}/scripts/kubeadm-ha-node.sh"), filesha256("${local.repo_root}/scripts/public-services-bootstrap.sh"), filesha256("${local.repo_root}/scripts/postgres-ha-node.sh"), sha256(jsonencode(var.native_binary_sha256))]
    ))),
    sha256(jsonencode(each.value)), sha256(jsonencode(var.control_planes))
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" --limit \"$HNN_IAC_NODE\" ansible/standard.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      HNN_IAC_NODE             = each.key
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}

resource "terraform_data" "gpu_host_configuration" {
  input = {
    candidates     = ["uc-k8sp5", "uc-k8sp4", "ichikawap1"]
    expected_nodes = local.gpu_expected_nodes
    policy         = "automatic-supported-hardware"
  }
  triggers_replace = [
    filesha256("${path.module}/ansible/gpu.yaml"),
    sha256(jsonencode(local.gpu_expected_nodes)),
    sha256(jsonencode(local.inventory))
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/gpu.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [
    local_file.inventory,
    local_file.known_hosts,
    terraform_data.host_configuration,
    terraform_data.standard_host_configuration
  ]
}

resource "kubernetes_manifest" "gpu_runtime_application" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata   = { name = "gpu-runtime", namespace = "argocd" }
    spec = {
      project = "hetero-platform"
      source = {
        repoURL        = var.git_repository_url
        targetRevision = var.git_revision
        path           = "deploy/gitops/gpu-runtime"
      }
      destination = { server = "https://kubernetes.default.svc", namespace = "kube-system" }
      syncPolicy = {
        automated   = { enabled = true, prune = true, selfHeal = true }
        retry       = { limit = 10, backoff = { duration = "5s", factor = 2, maxDuration = "3m" } }
        syncOptions = ["ServerSideApply=true", "DisableClientSideApplyMigration=true"]
      }
    }
  }
  field_manager { name = "heteronetwork-terraform" }
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.gpu_host_configuration, terraform_data.git_source, kubernetes_manifest.gitops_project]
}

resource "kubernetes_manifest" "nvidia_device_plugin_application" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata   = { name = "nvidia-device-plugin", namespace = "argocd" }
    spec = {
      project = "hetero-platform"
      source = {
        repoURL        = "https://nvidia.github.io/k8s-device-plugin"
        chart          = "nvidia-device-plugin"
        targetRevision = "0.20.0"
        helm = {
          releaseName = "nvidia-device-plugin"
          values = yamlencode({
            runtimeClassName   = "nvidia"
            nodeSelector       = { "nvidia.com/gpu.present" = "true" }
            failOnInitError    = true
            migStrategy        = "none"
            deviceListStrategy = "envvar"
            deviceIDStrategy   = "uuid"
            gfd                = { enabled = false }
          })
        }
      }
      destination = { server = "https://kubernetes.default.svc", namespace = "nvidia-device-plugin" }
      ignoreDifferences = [{
        group     = "apps"
        kind      = "DaemonSet"
        namespace = "nvidia-device-plugin"
        jqPathExpressions = [
          ".spec.template.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[].matchExpressions[] | select(.key == \"heteronetwork.io/control-plane-only\")"
        ]
      }]
      syncPolicy = {
        automated   = { enabled = true, prune = true, selfHeal = true }
        retry       = { limit = 10, backoff = { duration = "5s", factor = 2, maxDuration = "3m" } }
        syncOptions = ["CreateNamespace=true", "ServerSideApply=true", "DisableClientSideApplyMigration=true", "RespectIgnoreDifferences=true"]
      }
    }
  }
  field_manager { name = "heteronetwork-terraform" }
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.gpu_host_configuration, kubernetes_manifest.gpu_runtime_application, kubernetes_manifest.gitops_project]
}

resource "terraform_data" "gpu_acceptance" {
  input = {
    expected_nodes     = local.gpu_expected_nodes
    device_plugin      = "0.20.0"
    isolation          = "one-exclusive-gpu-per-pod"
    smoke_image_digest = "sha256:c87e78933f4c16e3272123bf2f75537306596d0fbaa395a29696a22786e5ee0e"
  }
  triggers_replace = [
    filesha256("${local.repo_root}/scripts/verify-gpu-runtime.py"),
    terraform_data.gpu_host_configuration.id,
    var.git_revision,
    "0.20.0"
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/verify-gpu-runtime.py --require-node uc-k8sp5=2"
    environment = {
      KUBECONFIG = pathexpand(var.kubeconfig_path)
    }
  }
  depends_on = [
    kubernetes_manifest.gpu_runtime_application,
    kubernetes_manifest.nvidia_device_plugin_application
  ]
}

resource "kubernetes_manifest" "standard_application" {
  manifest = {
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata   = { name = "standard-nodes", namespace = "argocd" }
    spec = {
      project           = "hetero-platform"
      source            = { repoURL = var.git_repository_url, targetRevision = var.git_revision, path = "deploy/gitops/standard-nodes" }
      destination       = { server = "https://kubernetes.default.svc", namespace = "kube-system" }
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
  depends_on = [terraform_data.standard_host_configuration, terraform_data.git_source, kubernetes_manifest.gitops_project]
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
