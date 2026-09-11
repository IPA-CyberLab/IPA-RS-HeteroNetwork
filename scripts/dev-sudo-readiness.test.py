"""Public fixtures only. No services, keys, ledgers, or guest access."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("readiness", Path(__file__).with_name("dev-sudo-readiness.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    guests = {f"hetero-dev-{i}": {"node_id": f"node-{i}", "voter_identifier": i,
                                "endpoint": f"https://10.251.0.{i}:8443", "machine_id": str(i) * 32}
              for i in range(1, 4)}
    return {"guests": guests, "service_sha256": "a" * 64, "policy": {
        "schema_version": 2, "manifest": {"schema_version": 1, "cluster_id": "dev-cluster", "epoch": 1,
            "public_key_package": [1, 2, 3],
            "members": [{"node_id": g["node_id"], "identifier": g["voter_identifier"], "endpoint": g["endpoint"]}
                        for g in guests.values()]},
        "hosts": {g["node_id"]: {"attestation_key_epoch": 1, "attestation_public_key": [g["voter_identifier"]] * 32, "callers": {
            "1000": {"issuer": "https://owner.example/realm", "subject": "fixture-owner"}}}
                  for g in guests.values()}}}


class Tests(unittest.TestCase):
    def test_exact_public_inventory(self):
        module.validate_expected(fixture(), "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_cluster_and_host_guard(self):
        for cluster, host, machine in (("production", "hetero-dev-1", "1" * 32),
                                       ("dev-cluster", "prod-host", "1" * 32),
                                       ("dev-cluster", "hetero-dev-1", "2" * 32)):
            with self.assertRaises(ValueError):
                module.validate_expected(fixture(), cluster, host, machine)

    def test_voter_host_and_owner_pins(self):
        original = fixture()
        for mutate in (
            lambda x: x["policy"]["manifest"]["members"][0].update(identifier=9),
            lambda x: x["policy"]["hosts"].pop("node-3"),
            lambda x: x["policy"]["hosts"]["node-1"]["callers"]["1000"].update(issuer="http://owner.example"),
            lambda x: x["guests"].pop("hetero-dev-3"),
        ):
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            module.unique_object([("policy", {}), ("policy", {})])

    def test_duplicate_host_keys_rejected(self):
        value = fixture()
        value["policy"]["hosts"]["node-2"]["attestation_public_key"] = [1] * 32
        with self.assertRaisesRegex(ValueError, "duplicate_host_public_pin"):
            module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_caller_uids_rejected(self):
        for uid in ("0", "-1", "01", "4294967296", "1000 ", "root"):
            value = fixture()
            callers = value["policy"]["hosts"]["node-1"]["callers"]
            callers[uid] = callers.pop("1000")
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_invalid_identity_and_epoch_rejected(self):
        for field, invalid in (("issuer", "https://owner.example/\nrealm"),
                               ("issuer", "https://" + "a" * 2048),
                               ("subject", "owner\x00"), ("subject", "a" * 257),
                               ("subject", "\u00e9" * 129)):
            value = fixture()
            value["policy"]["hosts"]["node-1"]["callers"]["1000"][field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)
        for epoch in (True, 1.5, 0, 2**64):
            value = fixture()
            value["policy"]["hosts"]["node-1"]["attestation_key_epoch"] = epoch
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)

    def test_relative_paths_rejected(self):
        with self.assertRaises(ValueError):
            module.read("config.json", 1024)

    def test_public_pin_shape_required(self):
        for field in ("public_key_package", "attestation_public_key"):
            value = fixture()
            if field == "public_key_package":
                value["policy"]["manifest"][field] = []
            else:
                value["policy"]["hosts"]["node-1"][field] = [256] * 32
            with self.assertRaises(ValueError):
                module.validate_expected(value, "dev-cluster", "hetero-dev-1", "1" * 32)


if __name__ == "__main__":
    unittest.main()
