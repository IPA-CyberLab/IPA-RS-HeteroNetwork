#!/usr/bin/env python3
"""Offline checks only: no libvirt/root operations, no guests or real SSH keys."""
import copy
import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).with_name("provision-dev-libvirt.py")
spec = importlib.util.spec_from_file_location("provision_dev", SCRIPT)
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)


def rules(p, chain):
    return [entry["add"]["rule"] for entry in dev.firewall(p)["nftables"]
            if "rule" in entry["add"] and entry["add"]["rule"]["family"] == "inet"
            and entry["add"]["rule"]["chain"] == chain]


def evaluate(chain, packet):
    """Small declarative-rule model, not a substitute for kernel packet tests."""
    def member(value, expected):
        if isinstance(expected, dict) and "prefix" in expected:
            return value is not None and ipaddress.ip_address(value) in ipaddress.ip_network(
                f"{expected['prefix']['addr']}/{expected['prefix']['len']}")
        if isinstance(expected, dict) and "set" in expected:
            return any(member(value, item) for item in expected["set"])
        return value == expected

    def matches(expression):
        value = expression["match"]
        left = value["left"]
        if "meta" in left:
            actual = packet.get(left["meta"]["key"])
        elif "ct" in left:
            actual = packet.get("ct_" + left["ct"]["key"])
        else:
            actual = packet.get(left["payload"]["protocol"] + "_" + left["payload"]["field"])
        result = member(actual, value["right"])
        return not result if value["op"] == "!=" else result

    for rule in chain:
        if all(matches(expr) for expr in rule["expr"][:-1]):
            return next(iter(rule["expr"][-1]))
    return "accept"


class DevPlanTests(unittest.TestCase):
    def setUp(self):
        self.p = dev.profile()

    def test_budget_names_and_deterministic_identity(self):
        plan = dev.plan(self.p)
        self.assertEqual(plan, dev.plan(self.p))
        self.assertEqual((plan["vcpu_total"], plan["memory_mib_total"], plan["disk_gib_total"]), (12, 24576, 120))
        self.assertEqual(len({resource["uuid"] for resource in plan["resources"]}), 5)
        self.assertFalse(plan["autostart"])
        self.assertFalse(plan["activation_performed"])

    def test_xml_fresh_resources_and_no_existing_network(self):
        network = ET.fromstring(dev.network_xml(self.p))
        self.assertEqual(network.find("forward").get("mode"), "nat")
        self.assertEqual(network.find("bridge").get("name"), "virbr-hdev")
        self.assertEqual(len(network.findall("ip/dhcp/host")), 3)
        self.assertIsNone(network.find("forward/interface"))
        for name in self.p["vms"]:
            domain = ET.fromstring(dev.domain_xml(self.p, name))
            self.assertEqual(domain.findtext("memory"), "8192")
            self.assertEqual(domain.findtext("on_reboot"), "restart")
            self.assertEqual(domain.find("devices/interface/source").get("network"), "hetero-dev")
            self.assertIsNone(domain.find("devices/filesystem"))
            self.assertIsNone(domain.find("devices/hostdev"))
        pool = ET.fromstring(dev.pool_xml(self.p))
        self.assertEqual(pool.findtext("target/path"), "/var/lib/libvirt/hetero-dev")

    def test_existing_inventory_preserved_and_overlap_rejected(self):
        default = '<network><name>default</name><bridge name="virbr0"/><ip address="192.168.122.1" netmask="255.255.255.0"/></network>'
        routes = [{"dst": destination} for destination in ("default", "10.240.0.0/16", "10.244.0.0/16", "10.250.0.0/16", "10.96.0.0/12", "100.64.0.0/10", "163.220.236.0/23")]
        dev.check_conflicts(self.p, routes, [], [default], ["vercel-research"], ["vercel-research"], ["virbr0"])
        for field in dev.FIELDS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                dev.check_conflicts(self.p, routes + [{"dst": self.p[field]}], [], [default], [], [], [])
        for domains, pools, links in ((["hetero-dev-1"], [], []), ([], ["hetero-dev"], []), ([], [], ["virbr-hdev"])):
            with self.assertRaises(ValueError):
                dev.check_conflicts(self.p, [], [], [], domains, pools, links)
        with self.assertRaises(ValueError):
            dev.check_conflicts(self.p, [], [{"addr_info": [{"local": "172.29.0.1", "prefixlen": 16}]}], [], [], [], [])
        with self.assertRaises(ValueError):
            dev.check_conflicts(self.p, [], [], [default.replace("192.168.122.1", "172.28.240.1")], [], [], [])

    def test_guard_is_additive_scoped_and_has_bridge_ipv6_rules(self):
        guard = dev.firewall(self.p)
        for entry in guard["nftables"]:
            self.assertEqual(set(entry), {"add"})
            kind, obj = next(iter(entry["add"].items()))
            self.assertEqual(obj.get("table", obj.get("name")), dev.TABLE)
            if kind == "chain":
                self.assertEqual(obj["policy"], "accept")
                self.assertEqual(obj["prio"], -10)
            if kind == "rule":
                self.assertIn(self.p["bridge"], json.dumps(obj["expr"]))
        self.assertIn('"ibrname"', json.dumps(guard))
        self.assertIn('"obrname"', json.dumps(guard))

    def test_host_guard_policy(self):
        chain = rules(self.p, "input")
        packet = {"iifname": self.p["bridge"], "nfproto": "ipv4", "ip_saddr": self.p["addresses"][0],
                  "ip_daddr": self.p["gateway"], "l4proto": "tcp", "tcp_dport": 22}
        self.assertEqual(evaluate(chain, packet), "drop")
        self.assertEqual(evaluate(chain, {**packet, "ct_state": "established", "ct_direction": "reply"}), "accept")
        self.assertEqual(evaluate(chain, {**packet, "ct_state": "established", "ct_direction": "original"}), "drop")
        self.assertEqual(evaluate(chain, {**packet, "tcp_dport": 53}), "accept")
        self.assertEqual(evaluate(chain, {**packet, "tcp_dport": 53, "ip_daddr": "10.250.0.10"}), "drop")
        self.assertEqual(evaluate(chain, {**packet, "l4proto": "udp", "udp_sport": 68, "udp_dport": 67,
                                        "ip_saddr": "0.0.0.0", "ip_daddr": "255.255.255.255"}), "accept")
        self.assertEqual(evaluate(chain, {**packet, "nfproto": "ipv6"}), "drop")
        self.assertEqual(evaluate(chain, {**packet, "iifname": "virbr0"}), "accept")

    def test_forward_policy(self):
        chain = rules(self.p, "forward")
        packet = {"iifname": self.p["bridge"], "oifname": "eth0", "nfproto": "ipv4",
                  "ip_saddr": self.p["addresses"][0], "ip_daddr": "1.1.1.1"}
        self.assertEqual(evaluate(chain, packet), "accept")
        for address in ("10.250.0.10", "172.29.0.1", "192.168.122.1", "100.68.203.27", "169.254.169.254", "127.0.0.1", "224.0.0.1", "163.220.236.53"):
            with self.subTest(address=address):
                self.assertEqual(evaluate(chain, {**packet, "ip_daddr": address, "ct_state": "established"}), "drop")
        self.assertEqual(evaluate(chain, {**packet, "nfproto": "ipv6"}), "drop")
        self.assertEqual(evaluate(chain, {**packet, "oifname": self.p["bridge"], "ip_daddr": self.p["addresses"][1]}), "accept")
        inbound = {**packet, "iifname": "eth0", "oifname": self.p["bridge"]}
        self.assertEqual(evaluate(chain, inbound), "drop")
        self.assertEqual(evaluate(chain, {**inbound, "ct_state": "established", "ct_direction": "reply"}), "accept")

    def test_seed_no_credentials_or_host_bootstrap(self):
        # A format-only dummy public key; CLI uses ssh-keygen to validate actual input.
        outputs = dev.render(self.p, "ssh-ed25519 TEST_PUBLIC_KEY")
        self.assertEqual(outputs, dev.render(self.p, "ssh-ed25519 TEST_PUBLIC_KEY"))
        for name in self.p["vms"]:
            data = json.loads(outputs[name + "/user-data"].split("\n", 1)[1])
            self.assertFalse(data["ssh_pwauth"])
            self.assertTrue(data["disable_root"])
            self.assertTrue(data["users"][0]["lock_passwd"])
            self.assertNotIn("sudo", data["users"][0])
            self.assertNotIn("runcmd", data)
            self.assertNotIn("write_files", data)

    def test_render_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "render"
            dev.write_render(target, {"plan.json": "first"})
            with self.assertRaises(FileExistsError):
                dev.write_render(target, {"plan.json": "second"})
            self.assertEqual((target / "plan.json").read_text(), "first")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                dev.write_render(link, {})

    def test_verify_image_rejects_bad_signature_before_image_use(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "SHA256SUMS").write_text("invalid checksum")
            (folder / "SHA256SUMS.gpg").write_text("invalid signature")
            p = copy.deepcopy(self.p)
            p["image_keyring"] = "/usr/bin/true"  # Nonsecret root-owned file; mocked GPG rejects it.
            with patch.object(dev, "run", side_effect=ValueError("bad signature")):
                with self.assertRaises(ValueError):
                    dev.verify_image(p, folder)

    def test_apply_requires_explicit_confirmation(self):
        with patch.object(sys, "argv", [str(SCRIPT), "apply"]), patch.object(dev, "run") as runner:
            with self.assertRaisesRegex(ValueError, "confirm-create"):
                dev.main()
            runner.assert_not_called()
        result = subprocess.run([sys.executable, str(SCRIPT), "apply"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Dev provisioner failed", result.stderr)

    def test_nonroot_apply_refuses_before_host_commands(self):
        with patch.object(dev.os, "geteuid", return_value=1000), patch.object(dev, "run") as runner:
            with self.assertRaisesRegex(ValueError, "local root"):
                dev.apply(self.p, "/not-read")
            runner.assert_not_called()

    def test_subprocess_output_and_time_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "output limit"):
            dev.run([sys.executable, "-c", 'import sys; sys.stdout.write("x" * (17 * 1024 * 1024))'])
        with self.assertRaisesRegex(ValueError, "timeout"):
            dev.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)

    def test_guard_readback_detects_rule_changes_and_survives_json_journal(self):
        guard = dev.canonical_guard(dev.firewall(self.p))
        state = {"guard": json.loads(json.dumps(guard))}
        with patch.object(dev, "live_guard", return_value=guard):
            dev.verify_guard(state)
        changed = copy.deepcopy(guard)
        changed.pop()
        with patch.object(dev, "live_guard", return_value=changed):
            with self.assertRaisesRegex(ValueError, "changed"):
                dev.verify_guard(state)

    def test_qcow2_backing_and_external_data_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            header = bytearray(104)
            header[:4] = b"QFI\xfb"
            struct.pack_into(">I", header, 4, 3)
            path.write_bytes(header)
            dev.validate_base_header(path)
            struct.pack_into(">Q", header, 8, 4096)
            path.write_bytes(header)
            with self.assertRaises(ValueError):
                dev.validate_base_header(path)
            struct.pack_into(">Q", header, 8, 0)
            struct.pack_into(">Q", header, 72, 4)
            path.write_bytes(header)
            with self.assertRaises(ValueError):
                dev.validate_base_header(path)

    def test_seed_admin_and_pinned_host_key(self):
        seed = dev.guest_seed(self.p, "hetero-dev-1", "ssh-ed25519 TEST_PUBLIC",
                              "TEST PRIVATE HOST KEY", "ssh-ed25519 TEST_HOST")
        data = json.loads(seed["user-data"].split("\n", 1)[1])
        self.assertEqual(data["users"][0]["sudo"], ["ALL=(ALL) NOPASSWD:ALL"])
        self.assertEqual(data["ssh_keys"]["ed25519_private"], "TEST PRIVATE HOST KEY")
        self.assertEqual(data["ssh_genkeytypes"], [])
        self.assertFalse(data["ssh_pwauth"])

    def test_journal_pending_intent_is_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                journal = dev.Journal(fd, {"pending": None})
                journal.intent({"operation": "define", "uuid": "test-only"})
                self.assertEqual(json.loads((Path(directory) / "journal.json").read_text())["pending"]["operation"], "define")
                with self.assertRaises(ValueError):
                    journal.intent({"operation": "another"})
                journal.done()
                self.assertIsNone(json.loads((Path(directory) / "journal.json").read_text())["pending"])
            finally:
                os.close(fd)

    def test_exclusive_file_write_refuses_symlink_and_existing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                dev.exclusive(fd, "owned", "preserve")
                with self.assertRaises(FileExistsError):
                    dev.exclusive(fd, "owned", "replacement")
                (root / "link").symlink_to(root / "owned")
                with self.assertRaises(FileExistsError):
                    dev.exclusive(fd, "link", "replacement")
                self.assertEqual((root / "owned").read_text(), "preserve")
            finally:
                os.close(fd)

    def test_partial_boot_failure_stops_only_newly_started_owned_guest(self):
        journal = type("FakeJournal", (), {"value": {"resources": {"domain:" + name: {} for name in self.p["vms"]}},
                                            "save": lambda self: None})()
        active = {"hetero-dev-1"}
        calls = []

        def transport(args, *unused, **kwargs):
            calls.append(args)
            if args[0] == "virsh" and args[3] == "start":
                if args[-1] == dev.identity(self.p, "domain", "hetero-dev-3"):
                    raise ValueError("start failed")
                active.add("hetero-dev-2")
            return ""

        with patch.object(dev, "run", transport), patch.object(dev, "verify_guard"), \
             patch.object(dev, "resource_info", side_effect=lambda p, kind, name: {"State": "running" if name in active else "shut off"}), \
             patch.object(dev, "resource_xml", side_effect=lambda p, kind, name: dev.domain_xml(p, name)):
            with self.assertRaises(ValueError):
                dev.first_boot(self.p, journal)
        destroyed = [call[-1] for call in calls if call[0] == "virsh" and call[3] == "destroy"]
        self.assertEqual(destroyed, [dev.identity(self.p, "domain", "hetero-dev-2")])

    def test_guard_failure_prevents_first_guest_start(self):
        journal = type("FakeJournal", (), {"value": {}, "save": lambda self: None})()
        with patch.object(dev, "verify_guard", side_effect=ValueError("guard missing")), patch.object(dev, "run") as runner:
            with self.assertRaises(ValueError):
                dev.first_boot(self.p, journal)
            runner.assert_not_called()

    def test_resource_validation_distinguishes_cold_allowed_and_invalid_states(self):
        name = self.p["vms"][0]
        text = dev.domain_xml(self.p, name)
        record = {"uuid": dev.identity(self.p, "domain", name), "definition_sha256": dev.definition_hash(text)}
        journal = {"resources": {"domain:" + name: record}}
        info = {"Autostart": "no", "Managed save": "no", "State": "shut off"}
        with patch.object(dev, "resource_xml", return_value=text), patch.object(dev, "resource_info", return_value=info):
            dev.verify_resources(self.p, journal, allow_running=True)
            dev.verify_resources(self.p, journal)
            info["State"] = "running"
            dev.verify_resources(self.p, journal, allow_running=True)
            with self.assertRaises(ValueError):
                dev.verify_resources(self.p, journal)
            info["State"] = "paused"
            with self.assertRaises(ValueError):
                dev.verify_resources(self.p, journal, allow_running=True)
            info["State"] = "shut off"
            record["definition_sha256"] = "changed"
            with self.assertRaisesRegex(ValueError, "definition drift"):
                dev.verify_resources(self.p, journal, allow_running=True)

    def test_apply_fake_transport_order_idempotency_and_existing_preservation(self):
        # A complete simulated apply uses only this private temporary tree.
        # No libvirt, nft, SSH, qemu or key generation commands are executed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            images = root / "input"
            images.mkdir()
            p = copy.deepcopy(self.p)
            p["pool_path"] = str(root / "hetero-dev")
            header = bytearray(104)
            header[:4] = b"QFI\xfb"
            struct.pack_into(">I", header, 4, 3)
            p["image_sha256"] = hashlib.sha256(header).hexdigest()
            (images / p["image_url"].rsplit("/", 1)[1]).write_bytes(header)
            fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
            journal = dev.Journal(fd, {"resources": {}, "files": {}, "pending": None})
            calls = []
            definitions = {}
            active = set()
            guard = []

            @contextlib.contextmanager
            def locked(*args, **kwargs):
                yield journal

            def transport(args, input_data=None, timeout=20):
                calls.append(list(args))
                if args[0] == "nft":
                    if "tables" in args:
                        return json.dumps({"nftables": [entry for entry in guard if "table" in entry]})
                    if "--check" in args:
                        return ""
                    if "--echo" in args:
                        guard.extend(entry["add"] for entry in json.loads(input_data)["nftables"])
                        return input_data
                    family = args[-2]
                    return json.dumps({"nftables": [entry for entry in guard if next(iter(entry.values()))["family"] == family]})
                if args[0] == "ssh-keygen":
                    key = Path(args[-1])
                    key.write_text("TEST PRIVATE KEY")
                    key.with_suffix(".pub").write_text("ssh-ed25519 TEST_PUBLIC")
                    return ""
                if args[0] == "qemu-img":
                    if args[1] == "info":
                        return json.dumps([{"format": "qcow2", "virtual-size": 1024**3}])
                    if args[1] == "create":
                        Path(args[-2]).write_bytes(b"TEST DISK")
                    return ""
                if args[0] == "cloud-localds":
                    Path(args[2]).write_bytes(b"TEST PRIVATE SEED")
                    return ""
                if args[0] == "virsh":
                    command, rest = args[3], args[4:]
                    kind = "network" if command.startswith("net-") else "pool" if command.startswith("pool-") else "domain"
                    if command in ("list", "net-list", "pool-list"):
                        existing = ["default"] if kind == "network" else ["vercel-research"]
                        return "\n".join(existing + [name for key_kind, name in definitions if kind == key_kind])
                    if command in ("define", "net-define", "pool-define"):
                        text = Path(rest[0]).read_text()
                        name = ET.fromstring(text).findtext("name")
                        self.assertTrue(name.startswith("hetero-dev"))
                        definitions[(kind, name)] = text
                        return ""
                    name = next((name for (key_kind, name), text in definitions.items()
                                 if key_kind == kind and (rest[0] == name or rest[0] == ET.fromstring(text).findtext("uuid"))), None)
                    self.assertIsNotNone(name)
                    key = kind, name
                    if command in ("dumpxml", "net-dumpxml", "pool-dumpxml"):
                        return definitions[key]
                    if command in ("dominfo", "net-info", "pool-info"):
                        return "Autostart: no\nManaged save: no\nState: " + ("running" if key in active else "shut off") + "\nActive: " + ("yes" if key in active else "no")
                    if command in ("start", "net-start", "pool-start"):
                        active.add(key)
                        return ""
                    self.fail("Unexpected libvirt command")
                if args[0] == "ssh":
                    self.assertIn("StrictHostKeyChecking=yes", args)
                    address = next(value.split("@", 1)[1] for value in args if value.startswith("devadmin@"))
                    return p["vms"][p["addresses"].index(address)] if args[-1] == "hostname" else "status: done"
                self.fail("Unexpected transport")

            def open_directory(path, private=False):
                self.assertTrue(str(path).startswith(str(root)))
                return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

            try:
                with patch.object(dev, "STATE", state), patch.object(dev, "locked_journal", locked), \
                     patch.object(dev, "preflight"), patch.object(dev, "root_directory", open_directory), \
                     patch.object(dev, "verify_image", return_value={"image_sha256": p["image_sha256"], "signers": ["TEST"]}), \
                     patch.object(dev, "run", transport):
                    result = dev.apply(p, images)
                    self.assertEqual(result["guests_boot_verified"], p["vms"])
                    mutations = [call for call in calls if call[0] in ("qemu-img", "cloud-localds", "ssh-keygen") or
                                 call[0] == "virsh" and call[3] in ("define", "net-define", "pool-define", "start", "net-start", "pool-start")]
                    before = len(mutations)
                    guard_index = next(i for i, call in enumerate(calls) if call[0] == "nft" and "--echo" in call)
                    self.assertTrue(all(i > guard_index for i, call in enumerate(calls) if call[0] == "virsh" and call[3] in ("start", "net-start")))
                    checkpoint = len(calls)
                    dev.apply(p, images)
                    self.assertGreater(before, 0)
                    self.assertFalse(any(call[0] in ("qemu-img", "cloud-localds", "ssh-keygen") or call[0] == "virsh" and call[3] in
                        ("define", "net-define", "pool-define", "start", "net-start", "pool-start") for call in calls[checkpoint:]))
                    self.assertEqual(len(active), 5)
                    self.assertNotIn("TEST PRIVATE", json.dumps(result))
                    # Model a host reboot: no autostart and no transient nft tables.
                    active.clear()
                    guard.clear()
                    checkpoint = len(calls)
                    cold = dev.apply(p, images)
                    self.assertEqual(cold["guests_boot_verified"], p["vms"])
                    self.assertEqual(len(active), 5)
                    cold_calls = calls[checkpoint:]
                    guard_index = next(i for i, call in enumerate(cold_calls) if call[0] == "nft" and "--echo" in call)
                    self.assertTrue(all(i > guard_index for i, call in enumerate(cold_calls)
                                        if call[0] == "virsh" and call[3] in ("start", "net-start")))
                    self.assertFalse(any(call[0] in ("qemu-img", "cloud-localds", "ssh-keygen") or
                                         call[0] == "virsh" and call[3] in ("define", "net-define", "pool-define")
                                         for call in cold_calls))
            finally:
                os.close(fd)

    def live_guard_fixture(self):
        data = json.loads((dev.ROOT / "deploy/dev/libvirt/testdata/nft-1.0.9-live-guard.json").read_text())
        return {"nftables": data["inet"]["nftables"] + data["bridge"]["nftables"]}

    def test_actual_nft_109_readback_matches_exact_original_batch(self):
        batch = dev.firewall(self.p)
        self.assertEqual(hashlib.sha256(json.dumps(batch).encode()).hexdigest(),
                         "339f000d6e74f479d30bb01c04053631d7c3176d1abe25d80a074d4a76b12e73")
        self.assertEqual(dev.canonical_guard(batch), dev.canonical_guard(self.live_guard_fixture()))
        changed = self.live_guard_fixture()
        rule = next(entry["rule"] for entry in changed["nftables"] if "rule" in entry)
        rule["expr"][-1] = {"accept": None}
        self.assertNotEqual(dev.canonical_guard(batch), dev.canonical_guard(changed))

    def test_l4_normalization_preserves_conflicts_order_and_predicates(self):
        tcp = dev.match(dev.meta("l4proto"), "tcp")
        udp = dev.match(dev.meta("l4proto"), "udp")
        port = dev.match(dev.payload("tcp", "dport"), 53)
        source = dev.match(dev.payload("ip", "saddr"), "172.28.240.11")
        good = [source, tcp, port, {"accept": None}]
        self.assertEqual(dev.canonical_rule_expressions(good), [source, port, {"accept": None}])
        for expressions in ([tcp, udp, port, {"accept": None}],
                            [udp, port, {"accept": None}],
                            [port, tcp, {"accept": None}],
                            [tcp, source, {"accept": None}],
                            [tcp, {"counter": None}, port, {"accept": None}],
                            [tcp, dev.match(dev.payload("tcp", "dport"), 53, "!="), {"drop": None}]):
            self.assertEqual(dev.canonical_rule_expressions(expressions), expressions)

    def test_install_echo_with_explicit_protocol_matches_actual_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                journal = dev.Journal(fd, {"pending": None})
                calls = []

                def transport(args, input_data=None, **kwargs):
                    calls.append(args)
                    if "tables" in args:
                        return '{"nftables": []}'
                    return input_data if "--echo" in args else ""

                with patch.object(dev, "run", transport), patch.object(dev, "live_guard",
                        return_value=dev.canonical_guard(self.live_guard_fixture())):
                    dev.ensure_guard(self.p, journal)
                self.assertIsNone(journal.value["pending"])
                self.assertEqual(journal.value["guard"], dev.canonical_guard(self.live_guard_fixture()))
            finally:
                os.close(fd)

    def test_recovery_exact_pending_empty_state_and_no_firewall_writes(self):
        batch_hash = hashlib.sha256(json.dumps(dev.firewall(self.p)).encode()).hexdigest()
        initial = {"pending": {"operation": "install-guard", "batch_sha256": batch_hash},
                   "resources": {}, "files": {}}
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                dev.exclusive(fd, "lock", b"")
                journal = dev.Journal(fd, copy.deepcopy(initial))
                journal.save()

                @contextlib.contextmanager
                def locked(*args, **kwargs):
                    self.assertTrue(kwargs.get("allow_pending_guard"))
                    self.assertFalse(kwargs.get("create", False))
                    yield journal

                live = dev.canonical_guard(self.live_guard_fixture())
                with patch.object(dev, "locked_journal", locked), patch.object(dev, "preflight") as preflight, \
                     patch.object(dev, "live_guard", return_value=live) as guard, patch.object(dev, "run") as runner:
                    bad_states = [dict(initial, pending=None),
                                  dict(initial, pending={"operation": "install-guard", "batch_sha256": "wrong"}),
                                  dict(initial, resources={"domain:hetero-dev-1": {}}),
                                  dict(initial, files={"unexpected": {}}), dict(initial, pool_directory=[1, 2]),
                                  dict(initial, guard=live), dict(initial, ready=True)]
                    for state in bad_states:
                        journal.value = copy.deepcopy(state)
                        with self.assertRaises(ValueError):
                            dev.recover_guard(self.p, batch_hash)
                        self.assertEqual(journal.value, state)
                    journal.value = copy.deepcopy(initial)
                    with self.assertRaises(ValueError):
                        dev.recover_guard(self.p, "wrong")
                    dev.exclusive(fd, "unexpected", b"")
                    with self.assertRaises(ValueError):
                        dev.recover_guard(self.p, batch_hash)
                    os.unlink("unexpected", dir_fd=fd)
                    preflight.side_effect = ValueError("pool exists or inventory conflict")
                    with self.assertRaises(ValueError):
                        dev.recover_guard(self.p, batch_hash)
                    preflight.side_effect = None
                    guard.return_value = []
                    with self.assertRaises(ValueError):
                        dev.recover_guard(self.p, batch_hash)
                    guard.return_value = live
                    guard.side_effect = [live, []]
                    with self.assertRaises(ValueError):
                        dev.recover_guard(self.p, batch_hash)
                    self.assertEqual(journal.value, initial)
                    guard.side_effect = None
                    result = dev.recover_guard(self.p, batch_hash)
                    runner.assert_not_called()
                    self.assertFalse(result["firewall_modified"])
                    self.assertEqual(journal.value["guard"], live)
                    self.assertIsNone(journal.value["pending"])
                    saved = json.loads((Path(directory) / "journal.json").read_text())
                    self.assertEqual(saved, journal.value)
                    with self.assertRaises(ValueError):
                        dev.recover_guard(self.p, batch_hash)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
