"""Offline tests. Synthetic digests are fixtures only, never deployment pins."""
import copy
import os
import shutil
import unittest

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
            "auxiliary_images": {name: pin(name) for name in
                                 ("postgres", "redis", "coturn", "garage")}}
    site["auxiliary_images"]["garage"]["version"] = "v2.3.0"
    return state, site


class RendererTests(unittest.TestCase):
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
        self.assertEqual(len(sets), 4)
        self.assertFalse(any(r["kind"] == "Secret" for r in resources))
        for resource in sets:
            self.assertTrue(resource["metadata"]["namespace"].endswith("-dev"))
            for claim in resource["spec"]["volumeClaimTemplates"]:
                self.assertNotIn("dataSource", claim["spec"])
                self.assertNotIn("volumeName", claim["spec"])
                self.assertEqual(claim["spec"]["storageClassName"], "dev-storage")

    def test_project_has_only_dev_destinations(self):
        _, site = fixtures()
        project = render.dev_project(site)
        self.assertEqual(project["metadata"]["name"], "hetero-platform-dev")
        for destination in project["spec"]["destinations"]:
            self.assertEqual(destination["server"], site["destination_server"])
            self.assertIn("-dev", destination["namespace"])

    @unittest.skipUnless(os.environ.get("HELM_CHANNEL_TESTS") == "1" and shutil.which("helm"), "opt-in local Helm check")
    def test_local_helm_all_dev_charts(self):
        state, site = fixtures()

        def inspect(app, documents):
            if app["metadata"]["name"] == "heterocloud-syouyu-dev":
                garage_images = [container["image"] for document in documents
                    if document and document.get("kind") == "StatefulSet"
                    for container in document["spec"]["template"]["spec"]["containers"]
                    if container["name"] == "garage"]
                self.assertEqual(len(garage_images), 1)
                self.assertEqual(render.canonical_image(garage_images[0]), site["auxiliary_images"]["garage"]["image"])
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
                                   render.ROOT.parent, inspect_documents=inspect)
        self.assertEqual(len(counts), 4)
        print("Local Helm resource counts:", counts)


if __name__ == "__main__":
    unittest.main()
