"""Fresh application CNPG resources; no identity database or credentials reused."""


def resources(namespaces, site, image):
    output = []
    operator = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "cnpg-system"}},
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "cloudnative-pg"}}}
    database = {"cnpg.io/cluster": "dev-postgres"}
    targets = []
    for ns in namespaces:
        name = ns.replace("-", "_")
        targets.append({"namespaceSelector": {"matchLabels": {
            "kubernetes.io/metadata.name": ns, "release.heteronetwork.io/channel": "dev"}},
            "podSelector": {"matchLabels": database}})
        output.append({"apiVersion": "postgresql.cnpg.io/v1", "kind": "Cluster",
            "metadata": {"name": "dev-postgres", "namespace": ns}, "spec": {
                "instances": 3, "imageName": image, "enableSuperuserAccess": False,
                "primaryUpdateStrategy": "unsupervised", "primaryUpdateMethod": "switchover",
                "postgresUID": 26, "postgresGID": 26,
                "podSecurityContext": {"runAsUser": 26, "runAsGroup": 26, "fsGroup": 26,
                                       "runAsNonRoot": True,
                                       "seccompProfile": {"type": "RuntimeDefault"}},
                "affinity": {"enablePodAntiAffinity": True, "podAntiAffinityType": "required",
                             "topologyKey": "kubernetes.io/hostname"},
                "bootstrap": {"initdb": {"database": name, "owner": name, "dataChecksums": True}},
                "postgresql": {
                    "synchronous": {"method": "any", "number": 1,
                                    "dataDurability": "required", "failoverQuorum": True},
                    "parameters": {"shared_buffers": "256MB", "max_wal_size": "512MB",
                                   "max_connections": "100" if ns == "heterocloud-syouyu-dev" else "200"}},
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "1", "memory": "1Gi"}},
                "storage": {"size": "5Gi", "storageClass": site["storage_class"],
                            "resizeInUseVolumes": False},
            }})
        output.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "dev-postgres", "namespace": ns}, "spec": {
                "podSelector": {"matchLabels": database}, "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {"from": [{"podSelector": {}}], "ports": [{"port": 5432, "protocol": "TCP"}]},
                    {"from": [operator], "ports": [{"port": 5432, "protocol": "TCP"},
                                                   {"port": 8000, "protocol": "TCP"}]},
                ],
                "egress": [
                    {"to": [{"podSelector": {"matchLabels": database}}],
                     "ports": [{"port": 5432, "protocol": "TCP"}]},
                    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                             "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                     "ports": [{"port": 53, "protocol": "TCP"}, {"port": 53, "protocol": "UDP"}]},
                    {"to": [{"ipBlock": {"cidr": cidr}} for cidr in
                            dict.fromkeys(site["service_cidrs"] + site["kubernetes_api_backend_cidrs"])],
                     "ports": [{"port": 443, "protocol": "TCP"}, {"port": 6443, "protocol": "TCP"}]},
                ],
            }})
    if targets:
        # An additive policy extends operator reach without rewriting identity policy.
        output.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "dev-application-databases", "namespace": "cnpg-system"},
            "spec": {"podSelector": operator["podSelector"], "policyTypes": ["Egress"],
                     "egress": [{"to": targets, "ports": [{"port": 5432, "protocol": "TCP"},
                                                          {"port": 8000, "protocol": "TCP"}]}]}})
    return output
