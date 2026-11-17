locals {
  declared_node_localities = jsondecode(file("${path.module}/node-localities.json"))
  overlay_locality_roster  = jsondecode(file("${path.module}/overlay-boot-peers.json")).hosts
  overlay_zone_regions = {
    for locality in values(local.declared_node_localities.nodes) : locality.zone => locality.region...
  }
}

resource "terraform_data" "overlay_locality_validation" {
  input = local.declared_node_localities
  lifecycle {
    precondition {
      condition = length(distinct(local.declared_node_localities.remove)) == length(local.declared_node_localities.remove) && alltrue([
        for host in local.declared_node_localities.remove :
        contains(keys(local.overlay_locality_roster), host) && !contains(keys(local.declared_node_localities.nodes), host)
      ])
      error_message = "Locality removals must be unique known hosts that are not also assigned a locality."
    }
    precondition {
      condition     = alltrue([for regions in values(local.overlay_zone_regions) : length(toset(regions)) == 1])
      error_message = "A zone label must not be reused across regions."
    }
  }
}

# Only explicitly declared sites are labelled. Omitted/unknown hosts are never
# assigned a fabricated failure domain.
resource "kubernetes_labels" "overlay_node_locality" {
  for_each    = local.declared_node_localities.nodes
  api_version = "v1"
  kind        = "Node"
  metadata {
    name = each.key
  }
  field_manager = "heteronetwork-node-locality"
  force         = false
  labels = {
    "topology.kubernetes.io/region" = each.value.region
    "topology.kubernetes.io/zone"   = each.value.zone
  }
  depends_on = [terraform_data.overlay_locality_validation]
  lifecycle {
    precondition {
      condition = contains(keys(local.overlay_locality_roster), each.key) && alltrue([
        for label in [each.value.region, each.value.zone] :
        can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label))
      ])
      error_message = "Each locality must reference an existing overlay host and valid region/zone labels."
    }
  }
}

resource "terraform_data" "overlay_hierarchy_policy" {
  input = {
    hierarchy  = jsondecode(file("${path.module}/overlay-hierarchy.json"))
    localities = local.declared_node_localities
  }
  triggers_replace = [
    filesha256("${path.module}/overlay-hierarchy.json"),
    filesha256("${path.module}/node-localities.json"),
    filesha256("${path.module}/overlay-boot-peers.json"),
    filesha256("${local.repo_root}/scripts/reconcile-overlay-hierarchy.py")
  ]
  provisioner "local-exec" {
    working_dir = local.repo_root
    command     = "python3 scripts/reconcile-overlay-hierarchy.py --config \"$HNN_HIERARCHY_POLICY\" --localities \"$HNN_NODE_LOCALITIES\" --roster \"$HNN_OVERLAY_ROSTER\""
    environment = {
      HNN_HIERARCHY_POLICY = abspath("${path.module}/overlay-hierarchy.json")
      HNN_NODE_LOCALITIES  = abspath("${path.module}/node-localities.json")
      HNN_OVERLAY_ROSTER   = abspath("${path.module}/overlay-boot-peers.json")
    }
  }
  depends_on = [terraform_data.console_configuration, terraform_data.control_plane_topology_rollout, terraform_data.overlay_locality_validation, kubernetes_labels.overlay_node_locality]
}
