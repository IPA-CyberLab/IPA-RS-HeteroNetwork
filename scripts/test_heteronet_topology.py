import json
from pathlib import Path
import tempfile
import unittest

import heteronet_topology as topology


class TopologyCliTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.config = root / "localities.json"
        self.roster = root / "roster.json"
        self.config.write_text(json.dumps({"nodes": {
            "a": {"region": "site", "zone": "room", "network": "main"},
        }, "remove": []}))
        self.roster.write_text(json.dumps({"hosts": {"a": "node-a", "b": "node-b"}}))

    def test_set_updates_only_the_requested_dimension(self):
        data = topology.update(self.config, self.roster, "a", network="backup")
        self.assertEqual(data["nodes"]["a"], {"region": "site", "zone": "room", "network": "backup"})
        topology.update(self.config, self.roster, "b", region="site", zone="room", network="main")
        self.assertEqual(topology.reconciler().load_localities(self.config, self.roster)[0]["node-b"]["network"], "main")

    def test_invalid_update_does_not_write(self):
        original = self.config.read_bytes()
        for changes in ({"network": "not a label"}, {"region": "SITE"}):
            with self.assertRaises(ValueError):
                topology.update(self.config, self.roster, "a", **changes)
            self.assertEqual(self.config.read_bytes(), original)
        with self.assertRaises(ValueError):
            topology.update(self.config, self.roster, "missing", network="main")
        self.assertEqual(self.config.read_bytes(), original)

    def test_remove_is_explicit_and_reassign_clears_the_removal(self):
        data = topology.update(self.config, self.roster, "a", remove=True)
        self.assertEqual(data, {"nodes": {}, "remove": ["a"]})
        data = topology.update(self.config, self.roster, "a", region="site", zone="room")
        self.assertEqual(data["remove"], [])
        topology.update(self.config, self.roster, "a", network="main")
        data = topology.update(self.config, self.roster, "a", clear_network=True)
        self.assertNotIn("network", data["nodes"]["a"])

    def test_bulk_update_moves_one_shared_zone_atomically(self):
        topology.update(self.config, self.roster, "b", region="site", zone="room", network="other")
        original = self.config.read_bytes()
        with self.assertRaises(ValueError):
            topology.update(self.config, self.roster, "a", region="new-site")
        self.assertEqual(self.config.read_bytes(), original)
        data = topology.update(self.config, self.roster, ["a", "b"], region="new-site")
        self.assertEqual(data["nodes"]["a"]["region"], "new-site")
        self.assertEqual(data["nodes"]["b"]["region"], "new-site")

    def test_plan_guard_rejects_unrelated_changes(self):
        plan = {"resource_changes": [
            {"address": 'kubernetes_labels.overlay_node_locality["a"]', "change": {"actions": ["create"]}},
            {"address": "terraform_data.overlay_hierarchy_policy", "change": {"actions": ["delete", "create"]}},
        ]}
        self.assertEqual(len(topology.planned_changes(plan)), 2)
        plan["resource_changes"].append({"address": "terraform_data.host_configuration", "change": {"actions": ["delete", "create"]}})
        with self.assertRaisesRegex(RuntimeError, "unrelated"):
            topology.planned_changes(plan)


if __name__ == "__main__":
    unittest.main()
