import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("etcd_retirements", Path(__file__).with_name("reconcile-etcd-retirements.py"))
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
NOW = dt.datetime(2026, 11, 9, 12, 0, tzinfo=dt.timezone.utc)
ROSTER = {"node_states": {"retired": {"state": "stopped", "reason": "operator retirement"}},
          "hosts": {"retired": "target-id"}, "peers": [{"node_id": "target-id", "vpn_ip": "10.0.0.4"}]}
ITEM = {"node": "retired", "member_id": "4", "peer_url": "https://10.0.0.4:2380",
        "snapshot_file": "snapshot.db", "snapshot_sha256": "0" * 64,
        "snapshot_created_at": "2026-11-09T11:30:00Z"}
INTENT = {"schema_version": 1, "executor_node": "node1", "retirements": [ITEM]}
MEMBERS = {"members": [
    {"ID": n, "name": name, "peerURLs": [f"https://10.0.0.{n}:2380"],
     "clientURLs": [f"https://10.0.0.{n}:2379"]}
    for n, name in [(1, "node1"), (2, "node2"), (3, "node3"), (4, "retired")]
]}
NODE = {"metadata": {"name": "retired"}, "spec": {"unschedulable": True},
        "status": {"conditions": [{"type": "Ready", "status": "Unknown", "lastTransitionTime": "2026-11-09T11:00:00Z"}]}}


class RetirementTests(unittest.TestCase):
    def test_intent_requires_explicit_stopped_node_and_matching_registered_peer(self):
        self.assertEqual(subject.validate_intent(INTENT, ROSTER), ITEM)
        with self.assertRaisesRegex(ValueError, "explicitly stopped"):
            subject.validate_intent(INTENT, {**ROSTER, "node_states": {}})
        with self.assertRaisesRegex(ValueError, "registered VPN"):
            subject.validate_intent({**INTENT, "retirements": [{**ITEM, "peer_url": "https://10.0.0.9:2380"}]}, ROSTER)

    def test_node_must_be_cordoned_and_long_unready(self):
        subject.validate_node(NODE, "retired", NOW)
        with self.assertRaisesRegex(ValueError, "unschedulable"):
            subject.validate_node({**NODE, "spec": {}}, "retired", NOW)
        with self.assertRaisesRegex(ValueError, "not be Ready"):
            subject.validate_node({**NODE, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}, "retired", NOW)
        with self.assertRaisesRegex(ValueError, "ten minutes"):
            subject.validate_node(NODE, "retired", NOW - dt.timedelta(minutes=55))

    def test_member_identity_is_exact_and_retirement_is_idempotent(self):
        survivors, endpoints = subject.survivors_for_retirement(MEMBERS, ITEM)
        self.assertEqual(len(survivors), 3)
        self.assertEqual(len(endpoints), 3)
        self.assertIsNone(subject.survivors_for_retirement({"members": survivors}, ITEM))
        with self.assertRaisesRegex(ValueError, "identity"):
            subject.survivors_for_retirement(MEMBERS, {**ITEM, "member_id": "5"})
        with self.assertRaisesRegex(ValueError, "at least three"):
            subject.survivors_for_retirement({"members": MEMBERS["members"][1:]}, ITEM)

    def test_all_remaining_members_must_be_healthy_and_agree_on_leader(self):
        survivors, endpoints = subject.survivors_for_retirement(MEMBERS, ITEM)
        statuses = [{"Endpoint": url, "Status": {"header": {"member_id": member["ID"]}, "leader": 1,
                                                     "raftAppliedIndex": 100}}
                    for member, url in zip(survivors, endpoints)]
        health = [{"endpoint": url, "health": True} for url in endpoints]
        subject.validate_health(survivors, endpoints, statuses, health)
        with self.assertRaisesRegex(ValueError, "healthy"):
            subject.validate_health(survivors, endpoints, statuses, health[:-1])
        statuses[0]["Status"]["leader"] = 4
        with self.assertRaisesRegex(ValueError, "leader"):
            subject.validate_health(survivors, endpoints, statuses, health)

    def test_snapshot_must_be_private_recent_and_match_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.db"
            data = b"x" * (1024 * 1024)
            path.write_bytes(data)
            path.chmod(0o600)
            item = {**ITEM, "snapshot_sha256": hashlib.sha256(data).hexdigest()}
            subject.validate_snapshot(item, Path(directory), NOW)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                subject.validate_snapshot(item, Path(directory), NOW)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "checksum"):
                subject.validate_snapshot(ITEM, Path(directory), NOW)
            with self.assertRaisesRegex(ValueError, "six hours"):
                subject.validate_snapshot(item, Path(directory), NOW + dt.timedelta(hours=7))
            path.unlink()
            os.symlink("/dev/null", path)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                subject.validate_snapshot(item, Path(directory), NOW)

    def test_no_member_removed_when_surviving_health_fails(self):
        class FakeCluster:
            def __init__(self, *_):
                self.removed = False
            def members(self):
                return MEMBERS
            def kube(self, *_):
                return json.dumps(NODE)
            def healthy(self, *_):
                raise ValueError("remaining health failed")
            def etcd(self, *_):
                self.removed = True
        fake = FakeCluster()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "intent.json").write_text(json.dumps(INTENT))
            (root / "roster.json").write_text(json.dumps(ROSTER))
            with (patch.object(subject, "Cluster", return_value=fake),
                  patch.object(subject, "validate_snapshot"),
                  patch.object(subject, "validate_node"),
                  patch("sys.argv", ["reconcile", "--kubeconfig", "test", "--intent", str(root / "intent.json"),
                                     "--roster", str(root / "roster.json"), "--backup-dir", directory])):
                with self.assertRaisesRegex(ValueError, "health failed"):
                    subject.main()
            self.assertFalse(fake.removed)

    def test_committed_removal_with_client_timeout_is_verified_without_retry(self):
        class FakeCluster:
            def __init__(self, *_):
                self.removed = False
                self.remove_calls = 0
                self.health_calls = 0
            def members(self):
                return {"members": MEMBERS["members"][:-1] if self.removed else MEMBERS["members"]}
            def kube(self, *_):
                return json.dumps(NODE)
            def healthy(self, *_):
                self.health_calls += 1
            def etcd(self, _, *args):
                self.assert_remove(args)
                self.remove_calls += 1
                self.removed = True
                raise ValueError("client timed out after the server committed")
            @staticmethod
            def assert_remove(args):
                assert args == ("member", "remove", "4")
        fake = FakeCluster()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "intent.json").write_text(json.dumps(INTENT))
            (root / "roster.json").write_text(json.dumps(ROSTER))
            with (patch.object(subject, "Cluster", return_value=fake),
                  patch.object(subject, "validate_snapshot"),
                  patch.object(subject, "validate_node"),
                  patch("sys.argv", ["reconcile", "--kubeconfig", "test", "--intent", str(root / "intent.json"),
                                     "--roster", str(root / "roster.json"), "--backup-dir", directory])):
                subject.main()
            self.assertEqual(fake.remove_calls, 1)
            self.assertEqual(fake.health_calls, 2)


if __name__ == "__main__":
    unittest.main()
