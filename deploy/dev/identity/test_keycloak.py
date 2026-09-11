import importlib.util
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlsplit

spec = importlib.util.spec_from_file_location("render_keycloak", Path(__file__).with_name("render-keycloak.py"))
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class KeycloakContract(unittest.TestCase):
    def test_origin_rejects_other_environments_and_ambiguous_authorities(self):
        for origin in ["http://id.dev.example.com", "https://id.example.com",
                       "https://id.dev.example.com/", "https://id.dev.example.com:443",
                       "https://admin@id.dev.example.com", "https://id.dev.example.com?x=1",
                       "https://id.dev.example.com#fragment", "https://id.dev.-bad.com"]:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                renderer.render(origin)

    def test_isolated_three_replica_contract(self):
        items = renderer.render("https://id.dev.example.com")["items"]
        self.assertEqual(items[0]["kind"], "NetworkPolicy")
        self.assertTrue(all(i["metadata"]["namespace"] == "hetero-dev-identity" for i in items))
        self.assertFalse(any(i["kind"] in ["Secret", "Ingress"] for i in items))
        deployment = next(i for i in items if i["kind"] == "Deployment")
        self.assertEqual(deployment["spec"]["replicas"], 3)
        pod = deployment["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"])
        container = pod["containers"][0]
        self.assertIn("@sha256:", container["image"])
        env = {item["name"]: item for item in container["env"]}
        self.assertEqual(env["KC_HTTP_ENABLED"]["value"], "false")
        self.assertIn("sslmode=verify-full", env["KC_DB_URL"]["value"])
        params = parse_qs(urlsplit(env["KC_DB_URL"]["value"].removeprefix("jdbc:")).query)
        self.assertEqual(params, {"sslmode": ["verify-full"], "sslrootcert": ["/var/run/postgres-ca/ca.crt"],
                                 "connectTimeout": ["5"], "loginTimeout": ["10"],
                                 "socketTimeout": ["30"], "tcpKeepAlive": ["true"]})
        self.assertNotIn("value", env["KC_DB_PASSWORD"])
        self.assertNotIn("value", env["KC_BOOTSTRAP_ADMIN_PASSWORD"])
        service = next(i for i in items if i["kind"] == "Service")
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual([p["port"] for p in service["spec"]["ports"]], [443])


if __name__ == "__main__":
    unittest.main()
