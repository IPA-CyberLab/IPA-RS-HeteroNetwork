resource "kubernetes_manifest" "openbao_custodian_api" {
  manifest = {
    apiVersion = "networking.k8s.io/v1"
    kind       = "NetworkPolicy"
    metadata = {
      name      = "openbao-host-custodian-api"
      namespace = "openbao"
    }
    spec = {
      podSelector = {
        matchLabels = {
          "app.kubernetes.io/name"     = "openbao"
          "app.kubernetes.io/instance" = "openbao"
          component                    = "server"
        }
      }
      policyTypes = ["Ingress"]
      ingress = [{
        # Flannel uses these node-owned /32 addresses for host-to-Pod traffic.
        # They are not assignable tenant Pod addresses.
        from  = [for address in ["10.250.0.4/32", "10.250.0.5/32", "10.250.0.6/32", "10.244.0.0/32", "10.244.1.0/32", "10.244.2.0/32"] : { ipBlock = { cidr = address } }]
        ports = [{ protocol = "TCP", port = 8200 }]
      }]
    }
  }
}

resource "terraform_data" "openbao_custodians" {
  triggers_replace = [
    filesha256("${path.module}/ansible/openbao-custodian.yaml"),
    filesha256("${local.repo_root}/../IPA-RS-HeteroCloud-SecretManager/scripts/custodian-unseal.py")
  ]
  provisioner "local-exec" {
    working_dir = abspath(path.module)
    command     = "ansible-playbook -i \"$HNN_IAC_INVENTORY\" ansible/openbao-custodian.yaml"
    environment = {
      HNN_IAC_INVENTORY        = local_file.inventory.filename
      ANSIBLE_CALLBACK_PLUGINS = "${abspath(path.module)}/ansible/callback_plugins"
      ANSIBLE_STDOUT_CALLBACK  = "hnn_json"
    }
  }
  depends_on = [local_file.inventory, local_file.known_hosts, kubernetes_manifest.openbao_custodian_api]
}
