"""Synthetic public fixtures only; no runtime credentials or connections."""
import base64
import copy
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from database_credentials import connection_material, DATABASES


def secret(namespace, name, values, kind="Opaque"):
    return {"apiVersion": "v1", "kind": "Secret", "type": kind,
            "metadata": {"namespace": namespace, "name": name},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in values.items()}}


def fixture(namespace, password="fixture:/@?#%+ password"):
    database = DATABASES[namespace]
    credentials = secret(namespace, "dev-postgres-app", {
        "username": database, "user": database, "dbname": database,
        "password": password, "host": "dev-postgres-rw", "port": "5432",
        "uri": "postgres://untrusted.invalid/other?sslmode=disable"}, "kubernetes.io/basic-auth")
    ca = secret(namespace, "dev-postgres-ca", {
        "ca.crt": "-----BEGIN CERTIFICATE-----\nFIXTURE\n-----END CERTIFICATE-----\n",
        "ca.key": "must-not-be-copied"})
    return credentials, ca


class ConnectionMaterialTests(unittest.TestCase):
    def test_exact_target_and_password_roundtrip(self):
        for namespace, database in DATABASES.items():
            credentials, ca = fixture(namespace)
            original = copy.deepcopy((credentials, ca))
            result = connection_material(namespace, credentials, ca)
            self.assertEqual(set(result), {"database-url", "ca.crt"})
            url = urlsplit(result["database-url"])
            self.assertEqual(url.hostname, f"dev-postgres-rw.{namespace}.svc.cluster.local")
            self.assertEqual(url.username, database)
            self.assertEqual(unquote(url.password), "fixture:/@?#%+ password")
            self.assertEqual(parse_qs(url.query), {"sslmode": ["verify-full"]})
            self.assertEqual((credentials, ca), original)

    def test_reject_foreign_secret_or_target(self):
        namespace = "heterocloud-dev"
        for field, value in (("host", "production.invalid"), ("port", "25432"),
                             ("dbname", "production"), ("username", "postgres")):
            credentials, ca = fixture(namespace)
            credentials["data"][field] = base64.b64encode(value.encode()).decode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                connection_material(namespace, credentials, ca)
        for namespace in ("heterocloud", "kube-system", "other-dev"):
            with self.assertRaises(ValueError):
                connection_material(namespace, *fixture("heterocloud-dev"))
        credentials, ca = fixture("heterocloud-dev")
        ca["metadata"]["namespace"] = "heterocloud-flow-dev"
        with self.assertRaises(ValueError):
            connection_material("heterocloud-dev", credentials, ca)

    def test_bad_encoding_error_does_not_echo_secret(self):
        credentials, ca = fixture("heterocloud-dev")
        credentials["data"]["password"] = "PRIVATE-FIXTURE-INVALID-BASE64!"
        with self.assertRaises(ValueError) as caught:
            connection_material("heterocloud-dev", credentials, ca)
        self.assertNotIn("PRIVATE-FIXTURE", str(caught.exception))

    def test_private_key_in_public_field_rejected(self):
        credentials, ca = fixture("heterocloud-dev")
        ca["data"]["ca.crt"] = ca["data"]["ca.key"]
        with self.assertRaises(ValueError):
            connection_material("heterocloud-dev", credentials, ca)


if __name__ == "__main__":
    unittest.main()
