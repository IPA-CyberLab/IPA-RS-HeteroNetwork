"""Offline tests. Synthetic digests are fixtures only, never deployment pins."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import render


def pin(component):
    value = {"schema_version": 1, "component": component, "version": "1.2.3",
            "commit": "a" * 40,
            "image": "ghcr.io/ipa-cyberlab/" + component + "@sha256:" + "b" * 64}
    if component == "flow":
        value["companions"] = {"livekit": {"image":
            "ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit@sha256:" + "c" * 64}}
    return value


def fixtures():
    artifacts = {name: pin(name) for name in render.COMPONENTS}
    state = {"schema_version": 1, "revision": 0, "dev": artifacts,
             "prod": copy.deepcopy(artifacts), "history": []}
    for command, channel in (("stage", "dev"), ("promote", "prod")):
        for name, artifact in artifacts.items():
            state["revision"] += 1
            state["history"].append({"revision": state["revision"], "command": command,
                "channel": channel, "component": name, "before": None, "after": copy.deepcopy(artifact),
                "at": "2026-09-10T00:00:00Z"})
    site = {"destination_server": "https://cluster.dev.example.invalid",
            "production_destination_server": "https://cluster.example.invalid",
            "cluster_uid": "11111111-1111-1111-1111-111111111111",
            "production_cluster_uid": "22222222-2222-2222-2222-222222222222",
            "domain": "dev.example.invalid", "oidc_issuer": "https://id.dev.example.invalid/realms/heterocloud-dev",
            "oidc_client_id": "heterocloud-dev-web", "owner_email": "owner@dev.example.invalid",
            "storage_class": "dev-storage", "pod_cidrs": ["172.20.0.0/16"],
            "service_cidrs": ["172.21.0.0/16"], "dns_cidrs": ["172.21.0.10/32"],
            "kubernetes_api_backend_cidrs": ["10.251.0.1/32", "10.251.0.2/32", "10.251.0.3/32"],
            "auxiliary_images": {name: pin(name) for name in
                                 ("postgres", "redis", "redis-sentinel", "coturn", "garage")}}
    for name in ("redis", "redis-sentinel"):
        site["auxiliary_images"][name]["image"] = "docker.io/bitnami/" + name + "@sha256:" + "b" * 64
    site["auxiliary_images"]["garage"]["version"] = "v2.3.0"
    return state, site


class RendererTests(unittest.TestCase):
    def test_redis_image_registry_is_not_duplicated(self):
        for name, prefix in (("redis", "redis.image"), ("redis-sentinel", "redis.sentinel.image")):
            image = {"version": "8.10.1", "image": "docker.io/bitnami/" + name + "@sha256:" + "a" * 64}
            values = render.image_parameters(prefix, image, render.AUX["flow"][name][1])
            self.assertEqual(values[prefix + ".registry"], "docker.io")
            self.assertEqual(values[prefix + ".repository"], "bitnami/" + name)
            self.assertEqual(values[prefix + ".registry"] + "/" + values[prefix + ".repository"] +
                             "@" + values[prefix + ".digest"], image["image"])
        with self.assertRaisesRegex(ValueError, "fully qualified"):
            render.image_parameters("redis.image", {"version": "8.10.1", "image":
                                    "bitnami/redis@sha256:" + "a" * 64}, "registry")

    def test_dev_keeps_redundant_cloud_and_flash_replicas(self):
        _, site = fixtures()
        cloud = render.dev_values("heterocloud", site)
        self.assertEqual(cloud["replicaCount"], 3)
        self.assertEqual(cloud["worker"]["replicaCount"], 3)
        self.assertEqual(cloud["ownerConsole"]["replicaCount"], 3)
        self.assertEqual(cloud["podDisruptionBudget"]["minAvailable"], 2)
        self.assertEqual(cloud["ownerConsole"]["podDisruptionBudget"]["minAvailable"], 2)
        flash = render.dev_values("heterocloud-flash", site)
        self.assertEqual(flash["api"]["replicaCount"], 3)
        self.assertEqual(flash["controller"]["replicaCount"], 2)

    def test_dev_turn_does_not_overlap_native_stun(self):
        _, site = fixtures()
        turn = render.dev_values("heterocloud-flow", site)["coturn"]
        self.assertEqual(turn["servicePort"], 13478)
        self.assertNotIn(turn["servicePort"], (3478, 3479))
        self.assertEqual(turn["additionalPools"], [])

    def test_dev_redis_uses_authenticated_sentinel(self):
        _, site = fixtures()
        values = render.dev_values("heterocloud-flow", site)
        redis = values["redis"]
        self.assertTrue(redis["enabled"])
        self.assertTrue(redis["auth"]["enabled"])
        self.assertTrue(redis["auth"]["sentinel"])
        self.assertEqual(redis["sentinel"]["quorum"], 2)
        self.assertEqual(redis["replica"]["replicaCount"], 3)
        self.assertEqual(redis["replica"]["persistence"]["storageClass"], "dev-storage")
        self.assertFalse(redis["networkPolicy"]["allowExternal"])
        self.assertEqual(values["externalRedis"]["address"], "")
        del site["auxiliary_images"]["redis-sentinel"]
        with self.assertRaisesRegex(ValueError, "Sentinel require"):
            render.dev_values("heterocloud-flow", site)

    def test_rendered_dev_owner_requires_secure_cookies(self):
        _, site = fixtures()
        owner = render.dev_values("heterocloud", site)["ownerConsole"]
        self.assertIs(owner["secureCookie"], True)
        args = ["--secure-cookie=true", "--public-origin=" + owner["origin"]]
        def documents(arguments):
            return [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
                {"name": "owner-console", "args": arguments}]}}}}]
        render.check_dev_owner_cookies(documents(args), owner)
        for bad in ([], ["--secure-cookie=false", args[1]], args + ["--secure-cookie=false"],
                    [args[0], "--public-origin=http://wrong.invalid"]):
            with self.subTest(args=bad), self.assertRaises(ValueError):
                render.check_dev_owner_cookies(documents(bad), owner)
        for bad in ([], documents(args) * 2):
            with self.assertRaises(ValueError):
                render.check_dev_owner_cookies(bad, owner)

    def test_deterministic_selection_and_digest_preserved(self):
        state, site = fixtures()
        dev = render.render(state, "dev", site)
        self.assertEqual(dev, render.render(state, "dev", site))
        for app in dev:
            self.assertFalse(app["spec"]["syncPolicy"]["automated"]["enabled"])
            self.assertEqual(app["spec"]["destination"]["server"], site["destination_server"])
            params = {p["name"]: p["value"] for p in app["spec"]["source"]["helm"]["parameters"]}
            image = render.canonical_image(params["image.repository"] + ":" + params["image.tag"])
            self.assertEqual(image, app["metadata"]["annotations"]["release.heteronetwork.io/image"])

    def test_prod_preserves_existing_settings(self):
        state, site = fixtures()
        for app in render.render(state, "prod", {}):
            original = render.read(render.ROOT / "deploy/gitops/applications" / (app["metadata"]["name"] + ".yaml"))
            actual = copy.deepcopy(app)
            old_params = {p["name"]: p["value"] for p in original["spec"]["source"]["helm"].get("parameters", [])}
            new_params = {p["name"]: p["value"] for p in actual["spec"]["source"]["helm"]["parameters"]}
            for name, value in old_params.items():
                if name not in ("image.repository", "image.tag", "livekit.image.repository", "livekit.image.tag"):
                    self.assertEqual(new_params[name], value)
            actual["metadata"] = original["metadata"]
            actual["spec"]["source"]["targetRevision"] = original["spec"]["source"]["targetRevision"]
            actual["spec"]["source"]["helm"].pop("parameters")
            original["spec"]["source"]["helm"].pop("parameters", None)
            self.assertEqual(actual, original)

    def test_flow_companion_is_release_bound_in_both_environments(self):
        state, site = fixtures()
        expected = state["dev"]["flow"]["companions"]["livekit"]["image"]
        for channel, config in (("dev", site), ("prod", {})):
            app = next(app for app in render.render(state, channel, config)
                       if app["metadata"]["name"].startswith("heterocloud-flow"))
            params = {p["name"]: p["value"] for p in app["spec"]["source"]["helm"]["parameters"]}
            self.assertEqual(render.canonical_image(
                params["livekit.image.repository"] + ":" + params["livekit.image.tag"]), expected)
        site["auxiliary_images"]["flow-livekit"] = pin("livekit")
        with self.assertRaisesRegex(ValueError, "auxiliary override"):
            render.render(state, "dev", site)
        state, site = fixtures()
        state["prod"]["flow"]["companions"]["livekit"]["image"] = expected[:-64] + "d" * 64
        with self.assertRaises(ValueError):
            render.render(state, "prod", site)

    def test_dev_rejects_shared_cluster_or_oidc(self):
        state, site = fixtures()
        for field, bad in (("cluster_uid", site["production_cluster_uid"]),
                           ("destination_server", site["production_destination_server"]),
                           ("oidc_client_id", "heterocloud-web"),
                           ("oidc_issuer", "https://id.example.invalid/realms/prod"),
                           ("pod_cidrs", ["0.0.0.0/0"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                render.render(state, "dev", {**site, field: bad})

    def test_rejects_mutable_release(self):
        state, site = fixtures()
        state["dev"]["flow"]["image"] = "ghcr.io/ipa-cyberlab/flow:latest"
        with self.assertRaises(ValueError):
            render.render(state, "dev", site)

    def test_rejects_broken_replay(self):
        state, site = fixtures()
        state["history"][0]["before"] = pin("heterocloud")
        with self.assertRaisesRegex(ValueError, "history"):
            render.render(state, "dev", site)
        state, site = fixtures()
        state["prod"]["flow"]["commit"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "history"):
            render.render(state, "prod", site)

    def test_no_inherited_production_networks(self):
        state, site = fixtures()
        values = render.dev_values("heterocloud", site)
        self.assertEqual(values["networkPolicy"]["databaseCidrs"], site["pod_cidrs"])
        for key in ("providerCidrs", "registryCidrs"):
            self.assertEqual(values["networkPolicy"][key], site["pod_cidrs"] + site["service_cidrs"])
        self.assertEqual(values["ownerConsole"]["allowedNetworks"], site["pod_cidrs"])
        self.assertEqual(values["ownerConsole"]["serviceProxyNetworks"], [])

    def test_fresh_infrastructure(self):
        state, site = fixtures()
        resources = render.infrastructure(state, site, render.render(state, "dev", site))
        sets = [r for r in resources if r["kind"] == "StatefulSet"]
        self.assertEqual(len(sets), 0)  # Redis/Sentinel belongs to the Flow chart.
        clusters = [r for r in resources if r["kind"] == "Cluster"]
        self.assertEqual({r["metadata"]["namespace"] for r in clusters},
                         {"heterocloud-dev", "heterocloud-flow-dev", "heterocloud-syouyu-dev"})
        for cluster in clusters:
            spec = cluster["spec"]
            self.assertEqual(spec["instances"], 3)
            self.assertEqual(spec["affinity"]["podAntiAffinityType"], "required")
            self.assertEqual(spec["storage"], {"size": "5Gi", "storageClass": "dev-storage", "resizeInUseVolumes": False})
            self.assertEqual(spec["postgresql"]["synchronous"],
                             {"method": "any", "number": 1, "dataDurability": "required", "failoverQuorum": True})
            self.assertEqual(spec["bootstrap"]["initdb"]["owner"], cluster["metadata"]["namespace"].replace("-", "_"))
            self.assertNotIn("externalClusters", spec)
            self.assertFalse(spec["enableSuperuserAccess"])
        self.assertFalse(any(r["kind"] == "Service" and r["metadata"]["name"] == "dev-postgres" for r in resources))
        operator = next(r for r in resources if r["metadata"]["name"] == "dev-application-databases")
        self.assertEqual(operator["metadata"]["namespace"], "cnpg-system")
        self.assertEqual({t["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                          for t in operator["spec"]["egress"][0]["to"]},
                         {c["metadata"]["namespace"] for c in clusters})
        self.assertNotIn("hetero-dev-identity", str(resources))
        self.assertFalse(any(r["kind"] == "Secret" for r in resources))
        site["storage_class"] = "dev-identity-local"
        with self.assertRaisesRegex(ValueError, "identity storage"):
            render.infrastructure(state, site, render.render(state, "dev", site))

    def test_syouyu_selector_and_explicit_api_backends(self):
        state, site = fixtures()
        site["kubernetes_api_backend_cidrs"] += [site["service_cidrs"][0], "10.251.0.1/32"]
        app = next(app for app in render.render(state, "dev", site)
                   if app["metadata"]["name"] == "heterocloud-syouyu-dev")
        policy = app["spec"]["source"]["helm"]["valuesObject"]["networkPolicy"]
        self.assertEqual(policy["database"]["podSelector"],
                         {"matchLabels": {"cnpg.io/cluster": "dev-postgres"}})
        self.assertEqual(policy["kubernetesApiCidrs"],
                         ["172.21.0.0/16", "10.251.0.1/32", "10.251.0.2/32", "10.251.0.3/32"])
        for bad in (None, [], "10.251.0.1/32", ["0.0.0.0/0"], ["::/0"], ["invalid"], [True], [1]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                render.render(state, "dev", {**site, "kubernetes_api_backend_cidrs": bad})
        del site["kubernetes_api_backend_cidrs"]
        with self.assertRaises(ValueError):
            render.render(state, "dev", site)

    def test_checkout_commit_and_cleanliness(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            def git(*args):
                return subprocess.run(["git", "-C", str(repository), *args], check=True,
                                      capture_output=True, text=True).stdout.strip()
            git("init", "--quiet")
            chart = repository / "deploy/helm/test"
            chart.mkdir(parents=True)
            source = chart / "Chart.yaml"
            source.write_text("apiVersion: v2\nname: test\nversion: 1.0.0\n")
            (repository / ".gitignore").write_text("charts/\n")
            git("add", ".")
            git("-c", "user.name=Renderer Test", "-c", "user.email=renderer@example.invalid",
                "commit", "--quiet", "-m", "fixture")
            revision = git("rev-parse", "HEAD")
            render.check_checkout(repository, revision, "deploy/helm/test")
            with self.assertRaisesRegex(ValueError, "HEAD differs"):
                render.check_checkout(repository, "a" * 40, "deploy/helm/test")
            original = source.read_text()
            source.write_text(original + "description: changed\n")
            with self.assertRaisesRegex(ValueError, "must be clean"):
                render.check_checkout(repository, revision, "deploy/helm/test")
            git("add", ".")
            with self.assertRaisesRegex(ValueError, "must be clean"):
                render.check_checkout(repository, revision, "deploy/helm/test")
            source.write_text(original)
            git("add", ".")
            extra = repository / "untracked"
            extra.write_text("not selected")
            with self.assertRaisesRegex(ValueError, "must be clean"):
                render.check_checkout(repository, revision, "deploy/helm/test")
            extra.unlink()
            (chart / "charts").mkdir()
            (chart / "charts/unpinned.tgz").write_bytes(b"not selected")
            with self.assertRaisesRegex(ValueError, "ignored chart files"):
                render.check_checkout(repository, revision, "deploy/helm/test")

    def test_helm_checks_checkout_before_and_after_render(self):
        state, site = fixtures()
        app = render.render(state, "dev", site)[0]
        helm_calls = []
        real_run = subprocess.run
        def run(args, **kwargs):
            if args[0] == "helm":
                helm_calls.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")
            return real_run(args, **kwargs)
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(render.subprocess, "run", side_effect=run):
            with patch.object(render, "check_checkout", side_effect=ValueError("dirty")):
                with self.assertRaisesRegex(ValueError, "dirty"):
                    render.check_helm([app], state, "dev", site, render.ROOT.parent)
                self.assertFalse(helm_calls)
            with patch.object(render, "check_checkout", side_effect=[None, ValueError("changed")]) as check:
                with self.assertRaisesRegex(ValueError, "changed"):
                    render.check_helm([app], state, "dev", site, render.ROOT.parent)
                self.assertEqual(check.call_count, 2)
                self.assertEqual(len(helm_calls), 1)
            bad_app = copy.deepcopy(app)
            bad_app["spec"]["source"]["targetRevision"] = "f" * 40
            with patch.object(render, "check_checkout") as check:
                with self.assertRaisesRegex(ValueError, "revision differs"):
                    render.check_helm([bad_app], state, "dev", site, render.ROOT.parent)
                check.assert_not_called()

    def test_project_has_only_dev_destinations(self):
        _, site = fixtures()
        project = render.dev_project(site)
        self.assertEqual(project["metadata"]["name"], "hetero-platform-dev")
        for destination in project["spec"]["destinations"]:
            self.assertEqual(destination["server"], site["destination_server"])
            self.assertIn("-dev", destination["namespace"])

    @unittest.skipUnless(os.environ.get("HELM_CHANNEL_TESTS") == "1" and shutil.which("helm"), "opt-in local Helm check")
    def test_local_helm_storage_reservations(self):
        _, site = fixtures()
        source = render.ROOT / "deploy/dev/apps/storage_plan.py"
        module_spec = importlib.util.spec_from_file_location("app_storage_plan", source)
        plan = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(plan)
        site["storage_class"] = plan.CLASS
        state = render.read(render.ROOT / "deploy/releases/channels.json")
        applications = render.render(state, "dev", site)
        claims = {}

        def inspect(app, documents):
            for d in documents:
                if not d or d.get("kind") != "StatefulSet":
                    continue
                ns = app["spec"]["destination"]["namespace"]
                for i in range(d["spec"]["replicas"]):
                    for claim in d["spec"].get("volumeClaimTemplates", []):
                        name = claim["metadata"]["name"] + "-" + d["metadata"]["name"] + "-" + str(i)
                        self.assertEqual(claim["spec"]["storageClassName"], plan.CLASS)
                        claims[(ns, name)] = claim["spec"]["resources"]["requests"]["storage"]

        render.check_helm(applications, state, "dev", site,
                          Path(os.environ.get("HELM_CHANNEL_REPOSITORY_ROOT", render.ROOT.parent)), inspect)
        for d in render.infrastructure(state, site, applications):
            if d["kind"] == "Cluster":
                for i in range(1, d["spec"]["instances"] + 1):
                    claims[(d["metadata"]["namespace"], d["metadata"]["name"] + "-" + str(i))] = d["spec"]["storage"]["size"]
        reserved = {(p["spec"]["claimRef"]["namespace"], p["spec"]["claimRef"]["name"]):
                    p["spec"]["capacity"]["storage"] for p in plan.manifest()["items"] if p["kind"] == "PersistentVolume"}
        self.assertEqual(claims, reserved)
        self.assertEqual(len(claims), 18)

    @unittest.skipUnless(os.environ.get("HELM_CHANNEL_TESTS") == "1" and shutil.which("helm"), "opt-in local Helm check")
    def test_local_helm_cloud_flash_redundancy(self):
        _, site = fixtures()
        state = render.read(render.ROOT / "deploy/releases/channels.json")
        expected = {
            "heterocloud-dev": (3, 2),
            "heterocloud-dev-worker": (3, 2),
            "heterocloud-dev-owner-console": (3, 2),
            "heterocloud-flash-dev-api": (3, 2),
            "heterocloud-flash-dev-controller": (2, 1),
        }
        deployments, budgets = {}, {}

        def inspect(app, documents):
            for document in documents:
                if not document:
                    continue
                name = document["metadata"]["name"]
                if document["kind"] == "Deployment":
                    spec = document["spec"]
                    pod = spec["template"]["spec"]
                    terms = pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                    labels = spec["template"]["metadata"]["labels"]
                    self.assertTrue(any(term["topologyKey"] == "kubernetes.io/hostname"
                        and term["labelSelector"]["matchLabels"]
                        and all(labels.get(k) == v for k, v in term["labelSelector"]["matchLabels"].items())
                        for term in terms))
                    deployments[name] = spec["replicas"]
                elif document["kind"] == "PodDisruptionBudget":
                    budgets[name] = document["spec"]["minAvailable"]

        apps = [app for app in render.render(state, "dev", site)
                if app["metadata"]["name"] in ("heterocloud-dev", "heterocloud-flash-dev")]
        render.check_helm(apps, state, "dev", site,
                          Path(os.environ.get("HELM_CHANNEL_REPOSITORY_ROOT", render.ROOT.parent)),
                          inspect_documents=inspect)
        self.assertEqual(deployments, {name: values[0] for name, values in expected.items()})
        self.assertEqual(budgets, {name: values[1] for name, values in expected.items()})

    @unittest.skipUnless(os.environ.get("HELM_CHANNEL_TESTS") == "1" and shutil.which("helm"), "opt-in local Helm check")
    def test_local_helm_all_dev_charts(self):
        _, site = fixtures()
        # Use actual selections; supplied repositories must be clean exact checkouts.
        state = json.loads((render.ROOT / "deploy/releases/channels.json").read_text())

        def inspect(app, documents):
            if app["metadata"]["name"] == "heterocloud-flow-dev":
                redis = next(d for d in documents if d and d.get("kind") == "StatefulSet"
                             and d["metadata"]["name"] == "heterocloud-flow-dev-redis-node")
                self.assertEqual(redis["spec"]["replicas"], 3)
                redis_pod = redis["spec"]["template"]["spec"]
                self.assertTrue(redis_pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"])
                claim = redis["spec"]["volumeClaimTemplates"][0]["spec"]
                self.assertEqual(claim["storageClassName"], "dev-storage")
                self.assertEqual(claim["resources"]["requests"]["storage"], "8Gi")
                self.assertNotIn("dataSource", claim)
                self.assertNotIn("volumeName", claim)
                budget = next(d for d in documents if d and d.get("kind") == "PodDisruptionBudget"
                              and d["metadata"]["name"] == "heterocloud-flow-dev-redis-node")
                self.assertEqual(budget["spec"]["minAvailable"], 2)
                policy = next(d for d in documents if d and d.get("kind") == "NetworkPolicy"
                              and d["metadata"]["name"] == "heterocloud-flow-dev-redis")
                self.assertTrue(all(rule.get("from") for rule in policy["spec"]["ingress"]))
                self.assertNotIn({}, policy["spec"]["egress"])
                clients = [c for d in documents if d and d.get("kind") == "Deployment"
                           for c in d["spec"]["template"]["spec"]["containers"] if c["name"] in ("api", "signaling")]
                self.assertEqual(len(clients), 2)
                for client in clients:
                    env = {e["name"]: e for e in client["env"]}
                    for key in ("REDIS_PASSWORD", "REDIS_SENTINEL_PASSWORD"):
                        self.assertEqual(env[key]["valueFrom"]["secretKeyRef"],
                                         {"name": "heterocloud-flow-dev-secrets", "key": "redis-password"})
                    self.assertNotIn("REDIS_URL", env)
                    self.assertEqual(len(env["REDIS_SENTINEL_URLS"]["value"].split(",")), 3)
                turn = next(d for d in documents if d and d.get("kind") == "Deployment"
                            and d["metadata"]["name"] == "heterocloud-flow-dev-coturn")
                pod = turn["spec"]["template"]["spec"]
                self.assertIs(pod["hostNetwork"], True)
                container = next(c for c in pod["containers"] if c["name"] == "coturn")
                self.assertIn("--listening-port=13478", " ".join(container["args"]))
                self.assertEqual({(p["protocol"], p["containerPort"], p["hostPort"])
                                  for p in container["ports"] if "hostPort" in p},
                                 {("UDP", 13478, 13478), ("TCP", 13478, 13478)})
                urls = [env["value"] for d in documents if d and d.get("kind") in ("Deployment", "Job")
                        for c in d["spec"]["template"]["spec"]["containers"]
                        for env in c.get("env", []) if env["name"] == "TURN_URLS"]
                self.assertTrue(urls)
                self.assertTrue(all(value == "turn:turn.dev.example.invalid:13478?transport=udp,"
                                    "turn:turn.dev.example.invalid:13478?transport=tcp" for value in urls))
            if app["metadata"]["name"] == "heterocloud-syouyu-dev":
                garage_images = [container["image"] for document in documents
                    if document and document.get("kind") == "StatefulSet"
                    for container in document["spec"]["template"]["spec"]["containers"]
                    if container["name"] == "garage"]
                self.assertEqual(len(garage_images), 1)
                self.assertEqual(render.canonical_image(garage_images[0]), site["auxiliary_images"]["garage"]["image"])
                policy = next(d for d in documents if d and d.get("kind") == "NetworkPolicy"
                              and d["metadata"]["name"] == "heterocloud-syouyu-dev-api")
                self.assertIn({"podSelector": {"matchLabels": {"cnpg.io/cluster": "dev-postgres"}}},
                              [peer for rule in policy["spec"]["egress"] for peer in rule.get("to", [])])
            if app["metadata"]["name"] != "heterocloud-dev":
                return
            policies = [d for d in documents if d and d.get("kind") == "NetworkPolicy"]
            self.assertEqual(len(policies), 3)
            serialized = str(policies)
            self.assertNotIn("10.250.0.0/24", serialized)
            self.assertNotIn("10.96.0.0/12", serialized)
            self.assertIn("172.20.0.0/16", serialized)
            self.assertIn("172.21.0.0/16", serialized)

        apps = render.render(state, "dev", site)
        counts = render.check_helm(apps, state, "dev", site,
                                   Path(os.environ.get("HELM_CHANNEL_REPOSITORY_ROOT", render.ROOT.parent)),
                                   inspect_documents=inspect)
        self.assertEqual(len(counts), 4)
        print("Local Helm resource counts:", counts)


if __name__ == "__main__":
    unittest.main()
