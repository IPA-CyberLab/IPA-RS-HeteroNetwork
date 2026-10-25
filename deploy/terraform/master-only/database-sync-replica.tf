resource "terraform_data" "database_sync_replica" {
  input = {
    name                 = "db-h"
    host                 = "ichikawap1"
    synchronous_standbys = 1
    synchronous_strict   = true
    primary_restart      = false
  }
  triggers_replace = [
    filesha256("${path.module}/ansible/database-sync-replica.yaml"),
    filesha256("${local.repo_root}/scripts/promote-database-sync-replica.py"),
    filesha256("${local.repo_root}/scripts/start-declared-sync-replica.py"),
    filesha256("${local.repo_root}/scripts/recover-database-authority.py"),
    filesha256("${local.repo_root}/scripts/postgres-ha-node.sh"),
    filesha256("${path.module}/overlay-boot-peers.json")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/database-sync-replica.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts]
}

# Per-host recovery remains deployable when another physical member is offline.
resource "terraform_data" "database_recovery_proxy" {
  for_each = toset(["uc-k8sp5", "ichikawap1", "uc-k8sp4"])
  triggers_replace = [
    filesha256("${path.module}/ansible/database-proxy.yaml"),
    filesha256("${local.repo_root}/scripts/postgres-ha-node.sh"),
    sha256(jsonencode(local.enrollment_issuer))
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/database-proxy.yaml --limit \"$HNN_IAC_HOST\""
    environment = {
      HNN_IAC_HOST             = each.key
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [terraform_data.database_sync_replica]
}
