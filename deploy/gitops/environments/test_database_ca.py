"""Offline rendered-contract tests; no cluster or credentials."""
import copy
import unittest

import render


SETTINGS = {"caSecretName": "dev-postgres-ca", "caSecretKey": "ca.crt"}


def fixture():
    ca = {"name": "PGSSLROOTCERT", "valueFrom": {"secretKeyRef": {
        "name": "dev-postgres-ca", "key": "ca.crt", "optional": False}}}
    return [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
        {"name": "api", "env": [{"name": "DATABASE_URL", "value": "fixture"}, ca]},
        {"name": "worker", "args": ["--database-url-file=/runtime/database-url"], "env": [copy.deepcopy(ca)]},
        {"name": "unrelated"} ]}}}}]


class DatabaseCaTests(unittest.TestCase):
    def test_reference_on_every_client(self):
        render.check_database_ca(fixture(), SETTINGS)

    def test_missing_wrong_optional_duplicate_or_inline_ca_rejected(self):
        for replacement in ([], [{"name": "PGSSLROOTCERT", "value": "inline"}],
                            [{"name": "PGSSLROOTCERT", "valueFrom": {"secretKeyRef": {
                                "name": "other", "key": "ca.crt", "optional": False}}}],
                            [{"name": "PGSSLROOTCERT", "valueFrom": {"secretKeyRef": {
                                "name": "dev-postgres-ca", "key": "ca.crt", "optional": True}}}]):
            docs = fixture()
            docs[0]["spec"]["template"]["spec"]["containers"][1]["env"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                render.check_database_ca(docs, SETTINGS)
        docs = fixture()
        env = docs[0]["spec"]["template"]["spec"]["containers"][1]["env"]
        env.append(copy.deepcopy(env[0]))
        with self.assertRaises(ValueError):
            render.check_database_ca(docs, SETTINGS)

    def test_job_and_init_database_clients(self):
        docs = fixture()
        docs[0]["kind"] = "Job"
        pod = docs[0]["spec"]["template"]["spec"]
        pod["initContainers"] = [pod["containers"].pop(0)]
        render.check_database_ca(docs, SETTINGS)
        pod["initContainers"][0]["env"].pop()
        with self.assertRaises(ValueError):
            render.check_database_ca(docs, SETTINGS)

    def test_no_database_clients_is_not_success(self):
        with self.assertRaises(ValueError):
            render.check_database_ca([], SETTINGS)


if __name__ == "__main__":
    unittest.main()
