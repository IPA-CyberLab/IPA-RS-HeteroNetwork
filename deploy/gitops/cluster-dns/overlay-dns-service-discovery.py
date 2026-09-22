#!/usr/bin/env python3
"""Reconcile Kubernetes service endpoints into the HeteroNetwork DNS zone."""

import ipaddress
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


DNS_SUFFIX = ".heteronetwork.internal"
DNS_ANNOTATION = "networking.heteronetwork.io/overlay-dns-name"
VPN_IP_ANNOTATION = "networking.heteronetwork.io/vpn-ip"
SERVICE_NAME_LABEL = "kubernetes.io/service-name"
MAX_DNS_NAMES = 256
MAX_ADDRESSES_PER_NAME = 16
MAX_DOCUMENT_BYTES = 64 * 1024


def normalize_dns_name(value):
    if not isinstance(value, str):
        raise ValueError("overlay DNS name must be a string")
    name = value.rstrip(".").lower()
    if not name.endswith(DNS_SUFFIX) or len(name) > 253:
        raise ValueError(
            f"overlay DNS name {value!r} must be below heteronetwork.internal"
        )
    labels = name.split(".")
    if any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not ("a" <= character <= "z" or "0" <= character <= "9" or character == "-")
               for character in label)
        for label in labels
    ):
        raise ValueError(f"overlay DNS name {value!r} is invalid")
    return name


def normalize_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"invalid overlay DNS address {value!r}") from error
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError(f"unusable overlay DNS address {value!r}")
    return str(address)


def ip_sort_key(value):
    address = ipaddress.ip_address(value)
    return (address.version, int(address))


def normalize_addresses(values, context):
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_ADDRESSES_PER_NAME:
        raise ValueError(
            f"{context} must contain 1-{MAX_ADDRESSES_PER_NAME} addresses"
        )
    addresses = [normalize_ip(value) for value in values]
    if len(set(addresses)) != len(addresses):
        raise ValueError(f"{context} repeats an address")
    return addresses


def parse_zone_document(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("overlay DNS document is empty or too large")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("overlay DNS document is invalid JSON") from error
    if not isinstance(document, dict) or set(document) - {
        "schema_version", "records", "gateway_records"
    }:
        raise ValueError("overlay DNS document contains unsupported fields")
    if document.get("schema_version") != 1:
        raise ValueError("overlay DNS document schema_version must be 1")
    raw_records = document.get("records")
    raw_gateway_records = document.get("gateway_records", {})
    if not isinstance(raw_records, dict) or len(raw_records) > MAX_DNS_NAMES:
        raise ValueError("overlay DNS records must be an object with at most 256 names")
    if not isinstance(raw_gateway_records, dict) or len(raw_gateway_records) > MAX_DNS_NAMES:
        raise ValueError("overlay DNS gateway_records must contain at most 256 names")

    records = {}
    for raw_name, raw_addresses in raw_records.items():
        name = normalize_dns_name(raw_name)
        if name in records:
            raise ValueError(f"overlay DNS name {name!r} is repeated")
        records[name] = normalize_addresses(raw_addresses, f"records[{name!r}]")

    gateway_records = {}
    for raw_name, raw_gateways in raw_gateway_records.items():
        name = normalize_dns_name(raw_name)
        if name not in records:
            raise ValueError(f"gateway record {name!r} has no base record")
        if not isinstance(raw_gateways, dict) or not raw_gateways:
            raise ValueError(f"gateway record {name!r} must contain gateways")
        gateways = {}
        for raw_gateway, raw_addresses in raw_gateways.items():
            gateway = normalize_ip(raw_gateway)
            if gateway in gateways:
                raise ValueError(f"gateway {gateway!r} is repeated for {name!r}")
            gateways[gateway] = normalize_addresses(
                raw_addresses, f"gateway_records[{name!r}][{gateway!r}]"
            )
        gateway_records[name] = gateways
    return {
        "schema_version": 1,
        "records": records,
        "gateway_records": gateway_records,
    }


def parse_rules(raw):
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("service discovery rules are invalid JSON") from error
    if not isinstance(document, dict) or set(document) != {"services"}:
        raise ValueError("service discovery rules must contain only services")
    rules = document["services"]
    if not isinstance(rules, list) or len(rules) > MAX_DNS_NAMES:
        raise ValueError("service discovery rules must be a list with at most 256 entries")
    result = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or set(rule) != {
            "dns_name", "namespace", "service_name"
        }:
            raise ValueError(f"service discovery rule {index} has unsupported fields")
        dns_name = normalize_dns_name(rule["dns_name"])
        namespace = rule["namespace"]
        service_name = rule["service_name"]
        for field, value in (("namespace", namespace), ("service_name", service_name)):
            if not isinstance(value, str) or not value or len(value) > 253:
                raise ValueError(f"service discovery rule {index} has invalid {field}")
        result.append({
            "dns_name": dns_name,
            "namespace": namespace,
            "service_name": service_name,
        })
    return result


def object_namespace(value):
    return (value.get("metadata") or {}).get("namespace") or "default"


def object_name(value):
    return (value.get("metadata") or {}).get("name")


def node_is_ready(node):
    metadata = node.get("metadata") or {}
    if metadata.get("deletionTimestamp"):
        return False
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in ((node.get("status") or {}).get("conditions") or [])
    )


def ready_node_vpn_ips(nodes):
    result = {}
    for node in nodes:
        name = object_name(node)
        raw_address = ((node.get("metadata") or {}).get("annotations") or {}).get(
            VPN_IP_ANNOTATION
        )
        if not name or not raw_address or not node_is_ready(node):
            continue
        result[name] = normalize_ip(raw_address)
    return result


def register_name(registrations, managed_names, dns_name, service_key):
    dns_name = normalize_dns_name(dns_name)
    managed_names.add(dns_name)
    current = registrations.get(dns_name)
    if current is not None and current != service_key:
        raise ValueError(
            f"overlay DNS name {dns_name!r} is assigned to both "
            f"{current[0]}/{current[1]} and {service_key[0]}/{service_key[1]}"
        )
    registrations[dns_name] = service_key


def desired_registrations(services, rules):
    service_keys = {
        (object_namespace(service), object_name(service))
        for service in services
        if object_name(service)
    }
    registrations = {}
    managed_names = set()
    for rule in rules:
        key = (rule["namespace"], rule["service_name"])
        managed_names.add(rule["dns_name"])
        if key in service_keys:
            register_name(registrations, managed_names, rule["dns_name"], key)

    for service in services:
        name = object_name(service)
        if not name:
            continue
        annotation = ((service.get("metadata") or {}).get("annotations") or {}).get(
            DNS_ANNOTATION, ""
        )
        for dns_name in (entry.strip() for entry in annotation.split(",")):
            if dns_name:
                register_name(
                    registrations,
                    managed_names,
                    dns_name,
                    (object_namespace(service), name),
                )
    if len(managed_names) > MAX_DNS_NAMES:
        raise ValueError("service discovery exceeds the 256-name limit")
    return registrations, managed_names


def ready_service_node_names(endpoint_slices):
    result = {}
    for endpoint_slice in endpoint_slices:
        metadata = endpoint_slice.get("metadata") or {}
        service_name = (metadata.get("labels") or {}).get(SERVICE_NAME_LABEL)
        if not service_name:
            continue
        key = (object_namespace(endpoint_slice), service_name)
        for endpoint in endpoint_slice.get("endpoints") or []:
            conditions = endpoint.get("conditions") or {}
            if conditions.get("ready") is False or conditions.get("terminating") is True:
                continue
            node_name = endpoint.get("nodeName")
            if node_name:
                result.setdefault(key, set()).add(node_name)
    return result


def build_effective_zone(base, services, endpoint_slices, nodes, rules):
    base = parse_zone_document(json.dumps(base, separators=(",", ":")))
    registrations, managed_names = desired_registrations(services, rules)
    records = dict(base["records"])
    gateway_records = dict(base["gateway_records"])
    for dns_name in managed_names:
        records.pop(dns_name, None)
        gateway_records.pop(dns_name, None)

    node_addresses = ready_node_vpn_ips(nodes)
    endpoint_nodes = ready_service_node_names(endpoint_slices)
    gateways = sorted(set(node_addresses.values()), key=ip_sort_key)
    discovered = []
    for dns_name, service_key in sorted(registrations.items()):
        addresses = sorted(
            {
                node_addresses[node_name]
                for node_name in endpoint_nodes.get(service_key, set())
                if node_name in node_addresses
            },
            key=ip_sort_key,
        )[:MAX_ADDRESSES_PER_NAME]
        if not addresses:
            continue
        records[dns_name] = addresses
        if gateways:
            gateway_records[dns_name] = {
                gateway: ([gateway] + [value for value in addresses if value != gateway])
                if gateway in addresses
                else list(addresses)
                for gateway in gateways
            }
        discovered.append({
            "dns_name": dns_name,
            "namespace": service_key[0],
            "service_name": service_key[1],
            "addresses": addresses,
        })

    if len(records) > MAX_DNS_NAMES:
        raise ValueError("effective overlay DNS zone exceeds the 256-name limit")
    effective = {
        "schema_version": 1,
        "records": dict(sorted(records.items())),
        "gateway_records": dict(sorted(gateway_records.items())),
    }
    parse_zone_document(json.dumps(effective, separators=(",", ":")))
    status = {"schema_version": 1, "services": discovered}
    return effective, status


class KubernetesApi:
    def __init__(self):
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if not host:
            raise RuntimeError("KUBERNETES_SERVICE_HOST is unavailable")
        self.base_url = f"https://{host}:{port}"
        self.token_path = Path(
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        )
        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.context = ssl.create_default_context(cafile=ca_path)

    def request(self, method, path, body=None):
        token = self.token_path.read_text().strip()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "heteronetwork-overlay-dns-discovery/1",
        }
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/merge-patch+json"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=5) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read(2048).decode(errors="replace")
            raise RuntimeError(
                f"Kubernetes API {method} {path} returned {error.code}: {detail}"
            ) from error

    def get(self, path):
        return self.request("GET", path)

    def list_items(self, path):
        result = []
        continuation = ""
        while True:
            separator = "&" if "?" in path else "?"
            query = f"{path}{separator}limit=500"
            if continuation:
                query += "&continue=" + urllib.parse.quote(continuation, safe="")
            page = self.get(query)
            result.extend(page.get("items") or [])
            continuation = (page.get("metadata") or {}).get("continue") or ""
            if not continuation:
                return result

    def config_map(self, namespace, name):
        return self.get(
            f"/api/v1/namespaces/{urllib.parse.quote(namespace, safe='')}/"
            f"configmaps/{urllib.parse.quote(name, safe='')}"
        )

    def patch_config_map_data(self, namespace, name, data):
        return self.request(
            "PATCH",
            f"/api/v1/namespaces/{urllib.parse.quote(namespace, safe='')}/"
            f"configmaps/{urllib.parse.quote(name, safe='')}",
            {"data": data},
        )


def canonical_json(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


def controller_once(api, rules_path):
    base_namespace = os.environ.get("BASE_CONFIGMAP_NAMESPACE", "heteronetwork-system")
    base_name = os.environ.get("BASE_CONFIGMAP_NAME", "heteronetwork-overlay-dns")
    effective_namespace = os.environ.get("EFFECTIVE_CONFIGMAP_NAMESPACE", "kube-system")
    effective_name = os.environ.get(
        "EFFECTIVE_CONFIGMAP_NAME", "heteronetwork-overlay-dns-effective"
    )
    base_config = api.config_map(base_namespace, base_name)
    base_raw = (base_config.get("data") or {}).get("records.json")
    if not base_raw:
        raise RuntimeError(f"{base_namespace}/{base_name} has no records.json")
    base = parse_zone_document(base_raw)
    rules = parse_rules(Path(rules_path).read_text())
    services = api.list_items("/api/v1/services")
    endpoint_slices = api.list_items("/apis/discovery.k8s.io/v1/endpointslices")
    nodes = api.list_items("/api/v1/nodes")
    effective, status = build_effective_zone(
        base, services, endpoint_slices, nodes, rules
    )
    desired = {
        "records.json": canonical_json(effective),
        "status.json": canonical_json(status),
    }
    current = api.config_map(effective_namespace, effective_name)
    current_data = current.get("data") or {}
    changed = any(current_data.get(key) != value for key, value in desired.items())
    if changed:
        api.patch_config_map_data(effective_namespace, effective_name, desired)
    Path("/tmp/last-success").touch()
    return changed, status


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"refusing to replace symlink {path}")
    try:
        if path.read_bytes() == data:
            return False
    except FileNotFoundError:
        pass
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return True


def sync_once(api, destination):
    namespace = os.environ.get("EFFECTIVE_CONFIGMAP_NAMESPACE", "kube-system")
    name = os.environ.get(
        "EFFECTIVE_CONFIGMAP_NAME", "heteronetwork-overlay-dns-effective"
    )
    config = api.config_map(namespace, name)
    raw = (config.get("data") or {}).get("records.json")
    if not raw:
        raise RuntimeError(f"{namespace}/{name} has no records.json")
    zone = parse_zone_document(raw)
    encoded = canonical_json(zone).encode()
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise RuntimeError("effective overlay DNS zone exceeds 64 KiB")
    changed = atomic_write(destination, encoded)
    Path("/tmp/last-success").touch()
    return changed


def run_loop(mode):
    api = KubernetesApi()
    interval = int(os.environ.get("RECONCILE_INTERVAL_SECONDS", "5"))
    if not 1 <= interval <= 300:
        raise RuntimeError("RECONCILE_INTERVAL_SECONDS must be between 1 and 300")
    rules_path = os.environ.get("DISCOVERY_RULES_PATH", "/config/services.json")
    destination = os.environ.get(
        "OVERLAY_DNS_DESTINATION", "/host/overlay-dns-records.json"
    )
    while True:
        started = time.monotonic()
        try:
            if mode == "controller":
                changed, status = controller_once(api, rules_path)
                if changed:
                    print(
                        f"reconciled {len(status['services'])} overlay DNS services",
                        flush=True,
                    )
            else:
                if sync_once(api, destination):
                    print("installed updated overlay DNS zone", flush=True)
        except Exception as error:
            print(f"overlay DNS {mode} failed: {error}", file=sys.stderr, flush=True)
        elapsed = time.monotonic() - started
        time.sleep(max(0.1, interval - elapsed))


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"controller", "sync"}:
        raise SystemExit("usage: overlay-dns-service-discovery.py controller|sync")
    run_loop(sys.argv[1])


if __name__ == "__main__":
    main()
