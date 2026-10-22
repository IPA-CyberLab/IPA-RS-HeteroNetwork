# Coder selects ephemeral WireGuard UDP ports internally; they are not Flash
# published ports. Keep this administrative grant between these two existing
# services only, with both organization and VPC membership required on each end.
locals {
  coder_transport_organization = "019fbda8-eff3-7610-bdd5-8fe89e746c14"
  coder_transport_vpc          = "01a10c38-e129-7653-bc8c-d1b05fedd4b9"
  coder_transport_peers = {
    control = {
      service = "01a10c3a-2de7-7e13-b433-f99559f44349"
      peer    = "01a11ad4-9917-74b3-a34d-192aaf2a4c76"
    }
    hyperevm = {
      service = "01a11ad4-9917-74b3-a34d-192aaf2a4c76"
      peer    = "01a10c3a-2de7-7e13-b433-f99559f44349"
    }
  }
}

resource "kubernetes_manifest" "coder_peer_transport" {
  for_each = local.coder_transport_peers
  manifest = {
    apiVersion = "networking.k8s.io/v1"
    kind       = "NetworkPolicy"
    metadata = {
      name      = "coder-hyperevm-peer-${each.key}"
      namespace = "heterocloud-flash-workloads"
      labels = {
        "app.kubernetes.io/managed-by" = "heteronetwork-terraform"
        "heteronetwork.io/purpose"     = "coder-peer-transport"
      }
    }
    spec = {
      podSelector = {
        matchLabels = {
          "flash.heterocloud.io/instance"     = each.value.service
          "flash.heterocloud.io/organization" = local.coder_transport_organization
          "vpc.heterocloud.io/network"        = local.coder_transport_vpc
        }
      }
      policyTypes = ["Ingress", "Egress"]
      ingress = [{
        from = [{
          podSelector = {
            matchLabels = {
              "flash.heterocloud.io/instance"     = each.value.peer
              "flash.heterocloud.io/organization" = local.coder_transport_organization
              "vpc.heterocloud.io/network"        = local.coder_transport_vpc
            }
          }
        }]
        ports = [{ protocol = "UDP" }]
      }]
      egress = [{
        to = [{
          podSelector = {
            matchLabels = {
              "flash.heterocloud.io/instance"     = each.value.peer
              "flash.heterocloud.io/organization" = local.coder_transport_organization
              "vpc.heterocloud.io/network"        = local.coder_transport_vpc
            }
          }
        }]
        ports = [{ protocol = "UDP" }]
      }]
    }
  }
}
