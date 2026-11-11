import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

from node_test_fixtures import roster_with_stopped_node

from node_lifecycle import ROSTER


spec = importlib.util.spec_from_file_location(
    "reconcile_stopped_wireguard", Path(__file__).with_name("reconcile-stopped-wireguard.py")
)
reconciler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconciler)


class ReconcileStoppedWireGuardTest(unittest.TestCase):
    def setUp(self):
        self.roster = roster_with_stopped_node()
        self.stopped = next(p["wireguard_public_key"] for p in self.roster["peers"] if p["hostname"] == "fixture-stopped")
        self.active = next(p["wireguard_public_key"] for p in self.roster["peers"] if p["hostname"] == "uc-k8sp5")
        self.calls = []

    def run_command(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ["ip", "link", "show"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["wg", "show", "heteronetwork0"]:
            return subprocess.CompletedProcess(argv, 0, self.active + "\n" + self.stopped + "\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def test_only_explicitly_stopped_peer_is_removed(self):
        self.assertEqual(reconciler.reconcile(self.roster, "heteronetwork0", self.run_command), 1)
        self.assertEqual(self.calls[-1], ["wg", "set", "heteronetwork0", "peer", self.stopped, "remove"])
        self.assertNotIn(["wg", "set", "heteronetwork0", "peer", self.active, "remove"], self.calls)

    def test_active_peer_is_never_removed_when_node_resumed(self):
        self.roster["node_states"]["fixture-stopped"] = {"state": "active"}
        self.assertEqual(reconciler.reconcile(self.roster, "heteronetwork0", self.run_command), 0)
        self.assertFalse(any(call[1] == "set" for call in self.calls))

    def test_invalid_roster_fails_before_any_command(self):
        roster = copy.deepcopy(self.roster)
        roster["peers"][0]["wireguard_public_key"] = base64.b64encode(b"wrong").decode()
        with self.assertRaises(ValueError):
            reconciler.reconcile(roster, "heteronetwork0", self.run_command)
        self.assertEqual(self.calls, [])

    def test_inventory_failure_never_removes_anything(self):
        def fail_inventory(argv, **kwargs):
            if argv[0] == "wg":
                raise subprocess.CalledProcessError(1, argv)
            return self.run_command(argv, **kwargs)
        with self.assertRaises(subprocess.CalledProcessError):
            reconciler.reconcile(self.roster, "heteronetwork0", fail_inventory)
        self.assertFalse(any(call[1] == "set" for call in self.calls))


if __name__ == "__main__":
    unittest.main()
