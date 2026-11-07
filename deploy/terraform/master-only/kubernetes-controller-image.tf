# Own only the controller container image. The rest of the Deployment remains
# under its existing Helm manager, including replicas, admission TLS and RBAC.
# The digest is updated only after the controller build and tests pass.
resource "kubernetes_manifest" "kubernetes_controller_image" {
  manifest = {
    apiVersion = "apps/v1"
    kind       = "Deployment"
    metadata = {
      name      = "heteronetwork-k8s-controller"
      namespace = "heteronetwork-system"
    }
    spec = {
      template = {
        spec = {
          containers = [{
            name = "controller"
            # d5a5f32d2b33b0e7ff00fd48621a9d03812d4df9; Actions 42356480088.
            image = "ghcr.io/ipa-cyberlab/heteronetwork-k8s-controller@sha256:47a7a1c8e0b33814b63fe48134e37263d3abda70bde40870f115d2a9e44b3ad1"
          }]
        }
      }
    }
  }

  field_manager {
    name            = "heteronetwork-controller-image-iac"
    force_conflicts = true
  }
  lifecycle { prevent_destroy = true }
}

import {
  to = kubernetes_manifest.kubernetes_controller_image
  id = "apiVersion=apps/v1,kind=Deployment,namespace=heteronetwork-system,name=heteronetwork-k8s-controller"
}
