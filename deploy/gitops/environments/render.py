#!/usr/bin/env python3
"""Offline Argo renderer consuming scripts/release-channels.mjs channel state."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import string
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENTS = {
    "heterocloud": ("heterocloud", "IPA-RS-HeteroCloud"),
    "flow": ("heterocloud-flow", "IPA-RS-HeteroCloud-Flow"),
    "flash": ("heterocloud-flash", "IPA-RS-HeteroCloud-Flash"),
    "syouyu": ("heterocloud-syouyu", "IPA-RS-HeteroCloud-Syouyu"),
}
# These bindings concern auxiliary images, never primary release selection.
AUX = {
    "heterocloud": {"haproxy": ("ownerConsole.databaseProxy.image", "scalar")},
    "flow": {
        "flow-livekit": ("livekit.image", "tag"), "coturn": ("coturn.image", "tag"),
        "redis": ("redis.image", "digest"), "redis-sentinel": ("redis.sentinel.image", "digest"),
        "prometheus": ("monitoring.prometheus.image", "digest"),
        "prometheus-init": ("monitoring.prometheus.initImage", "digest"),
        "grafana": ("monitoring.grafana.image", "digest"),
        "busybox": ("coturn.performance.tuningImage", "tag"),
    },
    "flash": {}, "syouyu": {"garage": ("garage.image", "digest")},
}
IMAGE = re.compile(r"^([a-z0-9][a-z0-9._:/-]+)@(sha256:[a-f0-9]{64})$")
VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[.-][A-Za-z0-9._-]+)?$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024, "input must be a bounded regular file")
    return yaml.safe_load(path.read_text())


def artifact(value, component):
    require(isinstance(value, dict) and value.get("schema_version") == 1 and value.get("component") == component,
            "invalid release artifact component")
    require(component in {*COMPONENTS, "heteronetwork"} and VERSION.fullmatch(value.get("version", "")), "invalid release version")
    require(re.fullmatch(r"[a-f0-9]{40}", value.get("commit", "")), "chart revision must be a full immutable commit")
    require(re.fullmatch(r"ghcr\.io/ipa-cyberlab/[a-z0-9._/-]+@sha256:[a-f0-9]{64}", value.get("image", "")),
            "release image must match the immutable channel artifact contract")
    return {key: value[key] for key in ("schema_version", "component", "version", "commit", "image")}


def selected(state, channel):
    # transition validates the complete replay chain before making an in-memory
    # selection. No channel files are written; discard its return value.
    result = subprocess.run(["node", "--input-type=module", "-e", """
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
const {transition} = await import(pathToFileURL(process.argv[2]).href);
try {
  const state = JSON.parse(fs.readFileSync(0, 'utf8'));
  const artifact = Object.values(state.dev ?? {})[0] ?? Object.values(state.prod ?? {})[0];
  transition(state, 'stage', artifact, state.revision);
} catch (error) { console.error(error.message); process.exitCode = 1; }
""", "channel-render-validator", str(ROOT / "scripts/release-channels.mjs")], input=json.dumps(state), capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, "invalid release channel state: " + result.stderr.strip())
    require(state.get("schema_version") == 1 and type(state.get("revision")) is int and state["revision"] >= 0,
            "invalid release channel state")
    require(isinstance(state.get("history"), list) and len(state["history"]) == state["revision"], "invalid channel history")
    for name in ("dev", "prod"):
        require(isinstance(state.get(name), dict), "missing release channel")
        for component, value in state[name].items():
            artifact(value, component)
    return {name: artifact(value, name) for name, value in state[channel].items() if name in COMPONENTS}


def origin(value):
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            and parsed.path in ("", "/") and not parsed.query and not parsed.fragment, "cluster destination must be an HTTPS origin")
    return value.rstrip("/")


def validate_site(site, channel):
    require(isinstance(site, dict), "site configuration must be an object")
    if channel == "prod":
        return
    server = origin(site.get("destination_server", ""))
    prod = origin(site.get("production_destination_server", ""))
    require(server != prod and server != "https://kubernetes.default.svc", "dev requires a distinct cluster destination")
    for field in ("cluster_uid", "production_cluster_uid"):
        require(re.fullmatch(r"[a-f0-9-]{36}", site.get(field, "")), "provide verified kube-system UIDs for both clusters")
    require(site["cluster_uid"] != site["production_cluster_uid"], "dev and prod cluster identities must differ")
    domain = site.get("domain", "")
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]+", domain) and domain.startswith("dev."), "dev domain must have an explicit dev. prefix")
    issuer = urlsplit(site.get("oidc_issuer", ""))
    require(issuer.scheme == "https" and issuer.hostname == "id." + domain and issuer.path == "/realms/heterocloud-dev"
            and not issuer.query and not issuer.fragment and not issuer.username and not issuer.password,
            "dev requires its own HTTPS OIDC hostname and realm")
    require(site.get("oidc_client_id") == "heterocloud-dev-web", "dev must not reuse the production OIDC client")
    require(isinstance(site.get("owner_email"), str) and "@" in site["owner_email"], "dev owner email is required")
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]*", site.get("storage_class", "")), "dev storage class is required")
    for field in ("pod_cidrs", "service_cidrs", "dns_cidrs"):
        require(isinstance(site.get(field), list) and site[field], "dev network ranges are required")
        for value in site[field]:
            require(ipaddress.ip_network(value).prefixlen > 0, "dev network ranges must not be catch-all routes")


def substitute(value, site):
    if isinstance(value, dict):
        return {key: substitute(item, site) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, site) for item in value]
    return string.Template(value).substitute(site) if isinstance(value, str) else value


def dev_values(app, site):
    values = substitute(read(HERE / "dev" / (app + ".yaml")), site)
    if app == "heterocloud":
        values["trustedProxyNetworks"] = site["pod_cidrs"]
        values["ownerConsole"]["allowedNetworks"] = site["pod_cidrs"]
        values["ownerConsole"]["serviceProxyNetworks"] = []
        values["networkPolicy"]["databaseCidrs"] = site["pod_cidrs"]
        values["networkPolicy"]["providerCidrs"] = site["pod_cidrs"] + site["service_cidrs"]
        values["networkPolicy"]["registryCidrs"] = site["pod_cidrs"] + site["service_cidrs"]
    elif app == "heterocloud-flash":
        values["networkPolicy"] = {"dnsCidrs": site["dns_cidrs"]}
    elif app == "heterocloud-syouyu":
        values["networkPolicy"]["s3IngressCidrs"] = site["pod_cidrs"]
        values["networkPolicy"]["kubernetesApiCidrs"] = site["service_cidrs"]
    return values


def image_parameters(prefix, pin, mode="tag"):
    match = IMAGE.fullmatch(pin.get("image", ""))
    require(match and isinstance(pin.get("version"), str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", pin["version"]),
            "auxiliary images require an explicit version and immutable image digest")
    repository, digest = match.groups()
    if mode == "scalar":
        return {prefix: pin["image"]}
    result = {prefix + ".repository": repository, prefix + ".tag": pin["version"] if mode == "digest" else pin["version"] + "@" + digest}
    if mode == "digest":
        result[prefix + ".digest"] = digest
    return result


def render(state, channel, site):
    pins = selected(state, channel)
    require(pins, "no Helm service artifacts selected; native VM deployment is separate and not performed")
    validate_site(site, channel)
    profile = read(HERE / channel / "environment.json")
    applications = []
    for component, pin in sorted(pins.items()):
        app, repository = COMPONENTS[component]
        if channel == "prod":
            # Only these four explicit files may be read. Registry and argocd-values
            # are deliberately outside this renderer's inputs and ownership.
            application = read(ROOT / "deploy/gitops/applications" / (app + ".yaml"))
        else:
            application = {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
                "metadata": {"name": app + "-dev", "namespace": "argocd"},
                "spec": {"project": profile["project"], "source": {"helm": {
                    "releaseName": app + "-dev", "valuesObject": dev_values(app, site)}},
                    "destination": {"server": site["destination_server"], "namespace": profile["namespaces"][app]},
                    "syncPolicy": {"automated": {"enabled": False}, "syncOptions": ["CreateNamespace=true", "ServerSideApply=true"]}}}
        source = application["spec"]["source"]
        source.update(repoURL=f"https://github.com/IPA-CyberLab/{repository}.git", targetRevision=pin["commit"], path="deploy/helm/" + app)
        parameters = {entry["name"]: entry["value"] for entry in source["helm"].get("parameters", [])}
        parameters.update(image_parameters("image", pin))
        for name, (prefix, mode) in AUX[component].items():
            if name in site.get("auxiliary_images", {}):
                parameters.update(image_parameters(prefix, site["auxiliary_images"][name], mode))
        source["helm"]["parameters"] = [{"name": name, "value": value, "forceString": True} for name, value in sorted(parameters.items())]
        application["metadata"].setdefault("annotations", {}).update({
            "release.heteronetwork.io/channel": channel,
            "release.heteronetwork.io/revision": str(state["revision"]),
            "release.heteronetwork.io/image": pin["image"],
        })
        applications.append(application)
    return applications


def infrastructure(state, site, applications):
    """Fresh dev-only storage. Passwords/connection URLs are provisioned separately."""
    require(all(app["metadata"]["name"].endswith("-dev") for app in applications), "infrastructure is dev-only")
    pins = site.get("auxiliary_images", {})
    namespaces = [app["spec"]["destination"]["namespace"] for app in applications]
    resources = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": {"release.heteronetwork.io/channel": "dev"}}} for ns in namespaces]
    for ns in namespaces:
        services = []
        if ns != "heterocloud-flash-dev":
            services.append(("dev-postgres", "postgres", 5432, "5Gi"))
        if ns == "heterocloud-flow-dev":
            services.append(("redis", "redis", 6379, "1Gi"))
        for name, image, port, size in services:
            require(image in pins and IMAGE.fullmatch(pins[image].get("image", "")), "dev database/Redis images need immutable auxiliary pins")
            labels = {"app.kubernetes.io/name": name, "release.heteronetwork.io/channel": "dev"}
            env = []
            container = {"name": name, "image": pins[image]["image"], "ports": [{"containerPort": port}], "env": env,
                         "volumeMounts": [{"name": "data", "mountPath": "/var/lib/postgresql/data" if image == "postgres" else "/data"}]}
            if image == "postgres":
                database = ns.replace("-", "_")
                env.extend([{"name": "POSTGRES_DB", "value": database}, {"name": "POSTGRES_USER", "value": database},
                    {"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {"name": ns + "-postgres-auth", "key": "password"}}},
                    {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"}])
            else:
                env.append({"name": "REDIS_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "heterocloud-flow-dev-secrets", "key": "redis-password"}}})
                container["args"] = ["--appendonly", "yes", "--requirepass", "$(REDIS_PASSWORD)"]
            resources.extend([
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns}, "spec": {"selector": labels, "ports": [{"port": port, "targetPort": port}]}},
                {"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": {"name": name, "namespace": ns}, "spec": {
                    "serviceName": name, "replicas": 1, "selector": {"matchLabels": labels},
                    "template": {"metadata": {"labels": labels}, "spec": {"automountServiceAccountToken": False, "containers": [container]}},
                    "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {"accessModes": ["ReadWriteOnce"],
                        "storageClassName": site["storage_class"], "resources": {"requests": {"storage": size}}}}]}},
                {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns},
                 "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress"], "ingress": [{"from": [{"podSelector": {}}], "ports": [{"port": port, "protocol": "TCP"}]}]}},
            ])
    return resources


def dev_project(site):
    profile = read(HERE / "dev/environment.json")
    return {"apiVersion": "argoproj.io/v1alpha1", "kind": "AppProject",
        "metadata": {"name": profile["project"], "namespace": "argocd"},
        "spec": {
            "sourceRepos": [f"https://github.com/IPA-CyberLab/{repo}.git" for _, repo in COMPONENTS.values()],
            "destinations": [{"server": site["destination_server"], "namespace": ns}
                for ns in [*profile["namespaces"].values(), "heterocloud-flash-dev-workloads"]],
            "clusterResourceWhitelist": [
                {"group": "", "kind": "Namespace"},
                {"group": "apiextensions.k8s.io", "kind": "CustomResourceDefinition"},
                {"group": "rbac.authorization.k8s.io", "kind": "ClusterRole"},
                {"group": "rbac.authorization.k8s.io", "kind": "ClusterRoleBinding"}],
        }}


def check_helm(applications, state, channel, site, repository_root, inspect_documents=None):
    """Validate local chart working trees, not remote catalog commit contents."""
    allowed = {value["image"] for value in selected(state, channel).values()}
    allowed.update(pin["image"] for pin in site.get("auxiliary_images", {}).values())
    counts = {}
    for app in applications:
        source = app["spec"]["source"]
        repository = repository_root / source["repoURL"].rsplit("/", 1)[1].removesuffix(".git")
        chart = repository / source["path"]
        require(chart.is_dir(), "local chart checkout is required for Helm validation")
        helm = source["helm"]
        with tempfile.TemporaryDirectory(prefix="hetero-channel-helm-") as temporary:
            args = ["helm", "template", helm["releaseName"], str(chart), "--namespace", app["spec"]["destination"]["namespace"], "--include-crds"]
            for filename in helm.get("valueFiles", []):
                args.extend(["-f", str(chart / filename)])
            for index, values in enumerate((yaml.safe_load(helm.get("values", "{}")), helm.get("valuesObject", {}))):
                filename = Path(temporary) / f"values-{index}.json"
                filename.write_text(json.dumps(values or {}))
                args.extend(["-f", str(filename)])
            for parameter in helm.get("parameters", []):
                args.extend(["--set-string", parameter["name"] + "=" + parameter["value"]])
            result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=90)
            require(result.returncode == 0, f"Helm render failed for {app['metadata']['name']}: {result.stderr[-2000:]}")
            documents = list(yaml.safe_load_all(result.stdout))
            if inspect_documents:
                inspect_documents(app, documents)
            counts[app["metadata"]["name"]] = sum(document is not None for document in documents)
            for document in documents:
                for image in container_images(document):
                    require(canonical_image(image) in allowed, f"rendered image lacks a selected or auxiliary immutable pin: {image}")
    return counts


def container_images(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("containers", "initContainers", "ephemeralContainers") and isinstance(item, list):
                for container in item:
                    if "image" in container:
                        yield container["image"]
            else:
                yield from container_images(item)
    elif isinstance(value, list):
        for item in value:
            yield from container_images(item)


def canonical_image(image):
    require(isinstance(image, str) and "@sha256:" in image, "mutable rendered image is not permitted")
    repository, digest = image.rsplit("@", 1)
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    result = repository + "@" + digest
    require(IMAGE.fullmatch(result), "invalid immutable rendered image")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channels", type=Path, required=True)
    parser.add_argument("--environment", choices=("dev", "prod"), required=True)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--infrastructure-output", type=Path)
    parser.add_argument("--helm-check", action="store_true", help="validate local chart working trees, not remote commit contents")
    parser.add_argument("--repository-root", type=Path, default=ROOT.parent)
    args = parser.parse_args()
    state, site = read(args.channels), read(args.site)
    applications = render(state, args.environment, site)
    if args.helm_check:
        print(json.dumps({"helm_resources": check_helm(applications, state, args.environment, site, args.repository_root)}))
    outputs = {args.output: {"apiVersion": "v1", "kind": "List", "items":
        ([dev_project(site)] if args.environment == "dev" else []) + applications}}
    if args.infrastructure_output:
        require(args.environment == "dev", "production infrastructure must not be regenerated")
        outputs[args.infrastructure_output] = {"apiVersion": "v1", "kind": "List", "items": infrastructure(state, site, applications)}
    for filename, value in outputs.items():
        # Rendering is deterministic; updating these generated files never applies them.
        filename.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print("Rendered only; no Kubernetes or Argo changes applied.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
