import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

from node_lifecycle import ROSTER


spec = importlib.util.spec_from_file_location(
    "stopped_overlay_firewall", Path(__file__).with_name("reconcile-stopped-overlay-firewall.py")
)
firewall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)


class StoppedOverlayFirewallTest(unittest.TestCase):
    def setUp(self):
        self.roster = json.loads(ROSTER.read_text())
        self.calls = []

    def run_command(self, argv, **kwargs):
        self.calls.append((argv, kwargs.get("input")))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def test_stopped_address_is_blocked_in_both_directions(self):
        self.assertEqual(firewall.reconcile(self.roster, self.run_command), 1)
        payload = next(payload for argv, payload in self.calls if argv[0] == "iptables-restore")
        self.assertIn("-s 10.250.0.11/32 -j DROP", payload)
        self.assertIn("-d 10.250.0.11/32 -j DROP", payload)
        self.assertNotIn("10.250.0.2", payload)
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            self.assertTrue(any(argv == ["iptables", "-I", hook, "1", "-j", firewall.CHAIN] for argv, _ in self.calls))

    def test_resuming_node_removes_its_fence(self):
        self.roster["node_states"]["uc-k8sp4"] = {"state": "active"}
        self.assertEqual(firewall.reconcile(self.roster, self.run_command), 0)
        payload = next(payload for argv, payload in self.calls if argv[0] == "iptables-restore")
        self.assertNotIn("10.250.0.11", payload)

    def test_invalid_address_fails_before_mutation(self):
        peer = next(p for p in self.roster["peers"] if p["hostname"] == "uc-k8sp4")
        peer["vpn_ip"] = "10.0.0.1/0 -j ACCEPT"
        with self.assertRaises(ValueError):
            firewall.reconcile(self.roster, self.run_command)
        self.assertEqual(self.calls, [])

    def test_shared_address_fails_before_mutation(self):
        stopped = next(p for p in self.roster["peers"] if p["hostname"] == "uc-k8sp4")
        active = next(p for p in self.roster["peers"] if p["hostname"] == "uc-k8sp5")
        stopped["vpn_ip"] = active["vpn_ip"]
        with self.assertRaises(ValueError):
            firewall.reconcile(self.roster, self.run_command)
        self.assertEqual(self.calls, [])

    def test_failed_restore_does_not_attach_incomplete_chain(self):
        def fail_restore(argv, **kwargs):
            if argv[0] == "iptables-restore":
                raise subprocess.CalledProcessError(1, argv)
            return self.run_command(argv, **kwargs)
        with self.assertRaises(subprocess.CalledProcessError):
            firewall.reconcile(self.roster, fail_restore)
        self.assertFalse(any(argv[:2] == ["iptables", "-I"] for argv, _ in self.calls))


if __name__ == "__main__":
    unittest.main()
