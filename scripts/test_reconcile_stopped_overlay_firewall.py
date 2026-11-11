import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

from node_test_fixtures import roster_with_stopped_node

from node_lifecycle import ROSTER


spec = importlib.util.spec_from_file_location(
    "stopped_overlay_firewall", Path(__file__).with_name("reconcile-stopped-overlay-firewall.py")
)
firewall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)


class StoppedOverlayFirewallTest(unittest.TestCase):
    def setUp(self):
        self.roster = roster_with_stopped_node()
        self.calls = []

    def run_command(self, argv, **kwargs):
        self.calls.append((argv, kwargs.get("input")))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def test_stopped_address_is_blocked_in_both_directions(self):
        self.assertEqual(firewall.reconcile(self.roster, self.run_command), 1)
        payload = next(payload for argv, payload in self.calls if argv[0] == "iptables-restore")
        self.assertIn("-s 10.250.0.250/32 -j DROP", payload)
        self.assertIn("-d 10.250.0.250/32 -j DROP", payload)
        self.assertNotIn("10.250.0.2/32", payload)
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            self.assertRegex(payload, rf"-I {hook} 1 -m comment --comment hnn-stopped-[0-9a-f]{{16}} -j {firewall.CHAIN}")

    def test_resuming_node_removes_its_fence(self):
        self.roster["node_states"]["fixture-stopped"] = {"state": "active"}
        def with_existing_fence(argv, **kwargs):
            if argv == ["iptables", "-S", firewall.CHAIN]:
                self.calls.append((argv, None))
                rules = f"-A {firewall.CHAIN} -s 10.250.0.250/32 -j DROP\n-A {firewall.CHAIN} -d 10.250.0.250/32 -j DROP\n"
                return subprocess.CompletedProcess(argv, 0, rules, "")
            return self.run_command(argv, **kwargs)
        self.assertEqual(firewall.reconcile(self.roster, with_existing_fence), 0)
        payload = next(payload for argv, payload in self.calls if argv[0] == "iptables-restore")
        self.assertNotIn("10.250.0.250", payload)

    def test_already_reconciled_firewall_is_not_rewritten(self):
        def already_reconciled(argv, **kwargs):
            self.calls.append((argv, kwargs.get("input")))
            output = ""
            if argv == ["iptables", "-S", firewall.CHAIN]:
                output = f"-A {firewall.CHAIN} -s 10.250.0.250/32 -j DROP\n-A {firewall.CHAIN} -d 10.250.0.250/32 -j DROP\n"
            elif argv[:2] == ["iptables", "-S"]:
                output = f"-A {argv[2]} -j {firewall.CHAIN}\n"
            return subprocess.CompletedProcess(argv, 0, output, "")
        self.assertEqual(firewall.reconcile(self.roster, already_reconciled), 1)
        self.assertFalse(any(argv[0] == "iptables-restore" or argv[:2] == ["iptables", "-I"] for argv, _ in self.calls))

    def test_invalid_address_fails_before_mutation(self):
        peer = next(p for p in self.roster["peers"] if p["hostname"] == "fixture-stopped")
        peer["vpn_ip"] = "10.0.0.1/0 -j ACCEPT"
        with self.assertRaises(ValueError):
            firewall.reconcile(self.roster, self.run_command)
        self.assertEqual(self.calls, [])

    def test_duplicate_hooks_are_removed_atomically_without_touching_other_rules(self):
        def duplicated(argv, **kwargs):
            self.calls.append((argv, kwargs.get("input")))
            output = ""
            if argv == ["iptables", "-S", firewall.CHAIN]:
                output = (f"-A {firewall.CHAIN} -s 10.250.0.250/32 -j DROP\n"
                          f"-A {firewall.CHAIN} -d 10.250.0.250/32 -j DROP\n")
            elif argv[:2] == ["iptables", "-S"]:
                hook = argv[2]
                output = (f"-A {hook} -j UNRELATED\n"
                          + f"-A {hook} -j {firewall.CHAIN}\n" * 3000
                          + f"-A {hook} -m comment --comment hnn-stopped-0123456789abcdef -j {firewall.CHAIN}\n")
            return subprocess.CompletedProcess(argv, 0, output, "")
        self.assertEqual(firewall.reconcile(self.roster, duplicated), 1)
        restores = [(argv, payload) for argv, payload in self.calls if argv[0] == "iptables-restore"]
        self.assertEqual(len(restores), 1)
        payload = restores[0][1]
        self.assertNotIn("UNRELATED", payload)
        for hook in ("INPUT", "OUTPUT", "FORWARD"):
            self.assertEqual(payload.count(f"-D {hook} -j {firewall.CHAIN}\n"), 3000)
            self.assertIn(f"-D {hook} -m comment --comment hnn-stopped-0123456789abcdef -j {firewall.CHAIN}", payload)
            self.assertRegex(payload, rf"-I {hook} 1 -m comment --comment hnn-stopped-[0-9a-f]{{16}} -j {firewall.CHAIN}")

    def test_existing_tagged_anchor_is_idempotent(self):
        def tagged(argv, **kwargs):
            self.calls.append((argv, kwargs.get("input")))
            if argv == ["iptables", "-S", firewall.CHAIN]:
                output = (f"-A {firewall.CHAIN} -s 10.250.0.250/32 -j DROP\n"
                          f"-A {firewall.CHAIN} -d 10.250.0.250/32 -j DROP\n")
            elif argv[:2] == ["iptables", "-S"]:
                output = f"-A {argv[2]} -m comment --comment hnn-stopped-0123456789abcdef -j {firewall.CHAIN}\n"
            else:
                output = ""
            return subprocess.CompletedProcess(argv, 0, output, "")
        self.assertEqual(firewall.reconcile(self.roster, tagged), 1)
        self.assertFalse(any(argv[0] == "iptables-restore" for argv, _ in self.calls))

    def test_shared_address_fails_before_mutation(self):
        stopped = next(p for p in self.roster["peers"] if p["hostname"] == "fixture-stopped")
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
