import json
from pathlib import Path
import tempfile
import unittest

import retire_node_inventory as inventory


class RetireInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "deploy/terraform/master-only"
        self.base.mkdir(parents=True)
        self.dns = self.root / "deploy/gitops/public-dns-quorum"
        self.dns.mkdir(parents=True)
        self.roster = {"cluster_id": "cluster", "hosts": {"a": "a-id", "b": "b-id"},
                       "peers": [{"node_id": "a-id", "hostname": "a", "vpn_ip": "10.0.0.1"},
                                 {"node_id": "b-id", "hostname": "b", "vpn_ip": "10.0.0.2"}],
                       "node_states": {"a": {"state": "stopped", "reason": "lost"}}}
        self.standard = {"a": {"vpn_ip": "10.0.0.1", "ssh_host": "192.0.2.1"}}
        self.pool = {"members": [{"node": "a"}, {"node": "b"}, {"node": "c"}],
                     "origins": [{"id": "a"}, {"id": "b"}]}
        self.write("overlay-boot-peers.json", self.roster)
        self.write("standard-nodes.json", self.standard)
        self.write("etcd-retirements.json", {"retirements": [{"node": "a"}]})
        (self.dns / "pool.json").write_text(json.dumps(self.pool))

    def write(self, name, value):
        (self.base / name).write_text(json.dumps(value))

    def plan(self):
        return inventory.plan(self.root, "a", etcd_member_absent=True)

    def test_removes_only_identical_target_and_keeps_other_hosts(self):
        proposed = self.plan()
        self.assertEqual((proposed["node_id"], proposed["vpn_ip"]), ("a-id", "10.0.0.1"))
        inventory.apply(self.root, proposed)
        roster = json.loads((self.base / "overlay-boot-peers.json").read_text())
        self.assertEqual(roster["hosts"], {"b": "b-id"})
        self.assertEqual(roster["peers"], [self.roster["peers"][1]])
        self.assertEqual(roster["node_states"], {})
        self.assertEqual(json.loads((self.base / "standard-nodes.json").read_text()), {})
        self.assertEqual(json.loads((self.base / "etcd-retirements.json").read_text())["retirements"], [])
        self.assertEqual([x["node"] for x in json.loads((self.dns / "pool.json").read_text())["members"]], ["b", "c"])

    def test_requires_stopped_node_and_absent_etcd_member(self):
        with self.assertRaisesRegex(ValueError, "etcd"):
            inventory.plan(self.root, "a", etcd_member_absent=False)
        self.roster["node_states"] = {}
        self.write("overlay-boot-peers.json", self.roster)
        with self.assertRaisesRegex(ValueError, "stopped"):
            self.plan()
        proposed = inventory.plan(self.root, "a", etcd_member_absent=True, offline_retirement=True)
        self.assertEqual(proposed["hostname"], "a")

    def test_refuses_disagreeing_identity(self):
        self.standard["a"]["vpn_ip"] = "10.0.0.9"
        self.write("standard-nodes.json", self.standard)
        with self.assertRaisesRegex(ValueError, "VPN address"):
            self.plan()

    def test_refuses_last_origin_or_too_few_voters(self):
        for pool, expected in [({"members": [{"node": "a"}, {"node": "b"}], "origins": [{"id": "b"}]}, "voters"),
                               ({"members": self.pool["members"], "origins": [{"id": "a"}]}, "origin")]:
            with self.subTest(expected=expected):
                (self.dns / "pool.json").write_text(json.dumps(pool))
                with self.assertRaisesRegex(ValueError, expected):
                    self.plan()

    def test_refuses_stale_plan_before_writing_any_file(self):
        proposed = self.plan()
        before = (self.base / "overlay-boot-peers.json").read_bytes()
        (self.dns / "pool.json").write_text(json.dumps({**self.pool, "changed": True}))
        with self.assertRaisesRegex(ValueError, "changed since planning"):
            inventory.apply(self.root, proposed)
        self.assertEqual((self.base / "overlay-boot-peers.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
