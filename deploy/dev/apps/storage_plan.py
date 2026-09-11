"""Fixed DEV local-PV reservations. Rendering performs no host or cluster writes."""
import json

CLUSTER_UID = "a39281cb-d273-4c5f-b7a7-fca722fb417b"
MOUNT = "/var/lib/heteronetwork-dev-app-storage"
CLASS = "dev-app-local"


def volumes():
    result = []
    for index in range(3):
        node = "hetero-dev-" + str(index + 1)
        for service in ("heterocloud", "heterocloud-flow", "heterocloud-syouyu"):
            result.append((node, service + "-dev", "dev-postgres-" + str(index + 1),
                           service + "-postgres", "5Gi", 26, 26))
        result.append((node, "heterocloud-flow-dev", "redis-data-heterocloud-flow-dev-redis-node-" + str(index),
                       "flow-redis", "8Gi", 1001, 1001))
        for part, size in (("meta", "2Gi"), ("data", "10Gi")):
            result.append((node, "heterocloud-syouyu-dev", part + "-heterocloud-syouyu-dev-garage-" + str(index),
                           "garage-" + part, size, 65532, 65532))
    return result


def manifest():
    labels = {"app.kubernetes.io/part-of": "dev-app-storage"}
    items = [{"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
              "metadata": {"name": CLASS, "labels": labels,
                           "annotations": {"storageclass.kubernetes.io/is-default-class": "false"}},
              "provisioner": "kubernetes.io/no-provisioner", "volumeBindingMode": "WaitForFirstConsumer",
              "reclaimPolicy": "Retain", "allowVolumeExpansion": False}]
    for node, namespace, claim, directory, size, _, _ in volumes():
        items.append({"apiVersion": "v1", "kind": "PersistentVolume",
            "metadata": {"name": "dev-app-" + directory + "-" + node.removeprefix("hetero-dev-"),
                         "labels": labels, "annotations": {"heteronetwork.dev/kube-system-uid": CLUSTER_UID}},
            "spec": {"capacity": {"storage": size}, "volumeMode": "Filesystem",
                     "accessModes": ["ReadWriteOnce"], "persistentVolumeReclaimPolicy": "Retain",
                     "storageClassName": CLASS,
                     "claimRef": {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                                  "namespace": namespace, "name": claim},
                     "local": {"path": MOUNT + "/" + directory},
                     "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                         {"key": "kubernetes.io/hostname", "operator": "In", "values": [node]}]}]}}}})
    return {"apiVersion": "v1", "kind": "List", "items": items}


if __name__ == "__main__":
    print(json.dumps(manifest(), indent=2))
