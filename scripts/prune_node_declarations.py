"""Remove exact retired-node references from the platform's declarative YAML."""
import copy
import ipaddress
from pathlib import Path
import yaml


DROP = object()
APP_PATHS = (
    "deploy/gitops/applications/heterocloud.yaml",
    "deploy/gitops/applications/heterocloud-flash.yaml",
    "deploy/gitops/applications/heterocloud-vpc.yaml",
    "deploy/gitops/applications/heterocloud-syouyu.yaml",
)


def prune(value, removed):
    if isinstance(value, str):
        return DROP if value in removed else value
    if isinstance(value, list):
        result = [filtered for item in value if (filtered := prune(item, removed)) is not DROP]
        if value and not result:
            raise ValueError("removing the node would leave a required service list empty")
        return result
    if isinstance(value, dict):
        if set(value) == {"ipBlock"} and value["ipBlock"].get("cidr") in removed:
            return DROP
        result = {}
        for key, item in value.items():
            if key in removed:
                continue
            filtered = prune(item, removed)
            if filtered is not DROP:
                result[key] = filtered
        return result
    return value


def removed_addresses(identity, pod_cidr):
    address = str(ipaddress.ip_address(identity["vpn_ip"]))
    values = {identity["hostname"], address, address + "/32"}
    if pod_cidr:
        network = ipaddress.ip_network(pod_cidr, strict=True)
        if network.version != 4 or network.num_addresses < 4:
            raise ValueError("unsupported retired node Pod CIDR")
        values.update({str(network.network_address) + "/32", str(network.network_address + 1) + "/32"})
    return values


def replacement_hostnames(document, target, candidates):
    for resource in document:
        if not resource or resource.get("kind") != "Deployment":
            continue
        affinity = resource.get("spec", {}).get("template", {}).get("spec", {}).get("affinity", {})
        terms = affinity.get("nodeAffinity", {}).get("requiredDuringSchedulingIgnoredDuringExecution", {}).get("nodeSelectorTerms", [])
        for term in terms:
            for expr in term.get("matchExpressions", []):
                if expr.get("key") != "kubernetes.io/hostname" or target not in expr.get("values", []):
                    continue
                values = [name for name in expr["values"] if name != target and name in candidates]
                values += [name for name in sorted(candidates) if name != target and name not in values][:max(0, 2 - len(values))]
                if len(set(values)) < 2:
                    raise ValueError("custom domain controller needs two surviving workers")
                expr["values"] = values


def plan(root, identity, pod_cidr, candidates):
    root = Path(root)
    removed = removed_addresses(identity, pod_cidr)
    updates = {}
    for path in APP_PATHS:
        file = root / path
        app = yaml.safe_load(file.read_text())
        values = yaml.safe_load(app["spec"]["source"]["helm"]["values"])
        new_values = prune(values, removed)
        if new_values != values:
            app["spec"]["source"]["helm"]["values"] = yaml.safe_dump(new_values, sort_keys=False)
            updates[Path(path)] = yaml.safe_dump(app, sort_keys=False)
    path = Path("deploy/environments/heteronet/values.yaml")
    document = yaml.safe_load((root / path).read_text())
    filtered = prune(document, removed)
    if filtered != document:
        updates[path] = yaml.safe_dump(filtered, sort_keys=False)
    path = Path("deploy/gitops/envoy-gateway/public-web-dns.yaml")
    documents = list(yaml.safe_load_all((root / path).read_text()))
    filtered = [prune(doc, removed) for doc in documents]
    for resource in filtered:
        if resource and resource.get("kind") == "DNSEndpoint":
            for endpoint in resource.get("spec", {}).get("endpoints", []):
                if not endpoint.get("targets"):
                    raise ValueError("retirement would empty a public DNS record")
    if filtered != documents:
        updates[path] = yaml.safe_dump_all(filtered, sort_keys=False)
    path = Path("deploy/gitops/custom-domains/infrastructure.yaml")
    documents = list(yaml.safe_load_all((root / path).read_text()))
    filtered = copy.deepcopy(documents)
    replacement_hostnames(filtered, identity["hostname"], candidates)
    if filtered != documents:
        updates[path] = yaml.safe_dump_all(filtered, sort_keys=False)
    path = Path("deploy/gitops/applications/public-dns-quorum.yaml")
    app = yaml.safe_load((root / path).read_text())
    ignored = app.get("spec", {}).get("ignoreDifferences", [])
    desired = [entry for entry in ignored if entry.get("name") != "public-dns-vote-" + identity["hostname"]]
    if desired != ignored:
        app["spec"]["ignoreDifferences"] = desired
        updates[path] = yaml.safe_dump(app, sort_keys=False)
    return updates
