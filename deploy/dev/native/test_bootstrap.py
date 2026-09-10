"""Offline only: synthetic archives are never executed; no services or guests touched."""
import copy
from contextlib import ExitStack
import base64
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("bootstrap", ROOT / "scripts/bootstrap-dev-guest.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def inventory():
    return {"schema_version": 1, "guests": [
        {"name": name, "address": f"172.28.240.{11+i}", "machine_id": f"{i+1:032x}",
         "product_uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:heteronetwork:dev:ichikawap1:domain:{name}"))}
        for i, name in enumerate(b.NAMES)]}


CLUSTER = {"cluster_id": "11111111-1111-4111-8111-111111111111", "issuer_node_id": "test-only-issuer",
           "issuer_public_key": "dGVzdC1vbmx5"}


class BootstrapTests(unittest.TestCase):
    def prerequisite_fixture(self, stack):
        artifact = self.archive()
        with patch.object(b, "run", side_effect=lambda args, timeout=60: json.dumps(
                CLUSTER if args[1] == "init" else {"test_only": True}).encode()):
            self.stage()
        bundle = self.root / "output" / b.NAMES[0]
        raw = (bundle / "bootstrap.json").read_bytes()
        stack.enter_context(patch.object(b, "checked_guest_bundle", return_value=(
            bundle, raw, json.loads(raw), artifact)))
        for name in ("CONFIG", "STATE", "BIN", "JOURNAL", "UNITS"):
            stack.enter_context(patch.object(b, name, self.root / name / "absent"))
        original_read = b.read
        stack.enter_context(patch.object(b, "read", side_effect=lambda path, *args:
            b'ID=ubuntu\n' if str(path) == "/usr/lib/os-release" else original_read(path, *args)))
        return bundle

    def test_prerequisites_repeat_preserves_bundle_and_uses_only_fixed_apt(self):
        with ExitStack() as stack:
            bundle = self.prerequisite_fixture(stack)
            before = {p.name: p.read_bytes() for p in bundle.iterdir()}
            run = stack.enter_context(patch.object(b, "run", return_value=b""))
            for _ in range(2):
                result = b.prerequisites(bundle)
                self.assertFalse(result["hn_installed"])
                self.assertFalse(result["vpn_verified"])
            self.assertEqual(run.call_count, 6)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0][-1], "update")
            self.assertIn("/usr/bin/apt-get", commands[1])
            self.assertEqual(commands[1][-6:], list(b.PREREQUISITE_PACKAGES))
            self.assertIn("--no-upgrade", commands[1])
            self.assertEqual(commands[2], ["/usr/bin/wg", "--version"])
            self.assertEqual(before, {p.name: p.read_bytes() for p in bundle.iterdir()})

    def test_prerequisites_reject_installed_guest_and_changed_token_before_apt(self):
        with ExitStack() as stack:
            bundle = self.prerequisite_fixture(stack)
            run = stack.enter_context(patch.object(b, "run"))
            b.CONFIG.mkdir(parents=True)
            with self.assertRaises(ValueError):
                b.prerequisites(bundle)
            b.CONFIG.rmdir()
            (bundle / "agent-api.token").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                b.prerequisites(bundle)
            run.assert_not_called()

    def test_prerequisites_identity_failure_never_calls_apt(self):
        with patch.object(b, "checked_guest_bundle", side_effect=ValueError("Wrong machine ID")), \
                patch.object(b, "run") as run:
            with self.assertRaises(ValueError):
                b.prerequisites(self.root)
            run.assert_not_called()

    def test_prerequisites_apt_failure_stops_without_install_or_enrollment(self):
        with ExitStack() as stack:
            bundle = self.prerequisite_fixture(stack)
            run = stack.enter_context(patch.object(b, "run", side_effect=ValueError("apt failed")))
            with self.assertRaises(ValueError):
                b.prerequisites(bundle)
            self.assertEqual(run.call_count, 1)
            self.assertFalse(b.JOURNAL.exists())

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="dev-bootstrap-test-", dir=Path.home()))

    def tearDown(self):
        for directory, _, _ in os.walk(self.root):
            os.chmod(directory, 0o700)
        shutil.rmtree(self.root)

    def archive(self):
        data = bytearray(512)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", data, 16, 3, 62)
        struct.pack_into("<I", data, 20, 1)
        struct.pack_into("<H", data, 52, 64)
        files = {name: bytes(data) for name in b.native().REQUIRED_BINARIES}
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, payload in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
        raw = gzip.compress(stream.getvalue(), mtime=0)
        artifact = {"schema_version": 1, "component": "heteronetwork", "version": "1.2.3-dev.1",
                    "commit": "1" * 40, "image": "ghcr.io/ipa-cyberlab/heteronetwork@sha256:" + "2" * 64,
                    "native": {"linux-amd64": {"asset": "heteronetwork-1.2.3-dev.1-linux-amd64.tar.gz",
                        "sha256": b.digest(raw), "files": {name: b.digest(payload) for name, payload in files.items()}}}}
        (self.root / "archive").write_bytes(raw)
        (self.root / "artifact").write_text(json.dumps(artifact))
        (self.root / "inventory").write_text(json.dumps(inventory()))
        return artifact

    def stage(self):
        return b.stage(self.root / "artifact", self.root / "archive", self.root / "inventory", self.root / "output")

    def test_fixed_inventory_and_distinct_machine_ids(self):
        self.assertEqual(b.inventory(inventory()), inventory())
        for field, value in (("name", "prod"), ("address", "10.250.0.5"),
                             ("product_uuid", str(uuid.uuid4())), ("machine_id", "0" * 32)):
            bad = inventory()
            bad["guests"][0][field] = value
            with self.assertRaises(ValueError):
                b.inventory(bad)
        bad = inventory()
        bad["guests"][1]["machine_id"] = bad["guests"][0]["machine_id"]
        with self.assertRaises(ValueError):
            b.inventory(bad)

    def test_archive_mismatch_never_executes_cli(self):
        self.archive()
        with (self.root / "archive").open("ab") as file:
            file.write(b"tampered")
        with patch.object(b, "run") as run:
            with self.assertRaises(ValueError):
                self.stage()
            run.assert_not_called()

    def test_non_dev_artifact_refused_before_output(self):
        artifact = self.archive()
        artifact["version"] = "1.2.3"
        artifact["native"]["linux-amd64"]["asset"] = "heteronetwork-1.2.3-linux-amd64.tar.gz"
        (self.root / "artifact").write_text(json.dumps(artifact))
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.root / "output").exists())

    def test_stage_private_separate_credentials_no_daemon_spawn(self):
        self.archive()
        calls = []
        def fake_run(args, timeout=60):
            calls.append([str(arg) for arg in args])
            return json.dumps(CLUSTER if args[1] == "init" else {"test_only": len(calls)}).encode()
        with patch.object(b, "run", side_effect=fake_run):
            result = self.stage()
        self.assertFalse(result["remote_execution"])
        self.assertEqual(result["verification_scope"], "base_archive_only")
        self.assertFalse(result["sudo_companion_verified"])
        self.assertFalse(result["sudo_installed"])
        self.assertEqual(len(calls), 4)
        self.assertNotIn("--spawn-daemons", calls[0])
        self.assertTrue(all("--max-uses" in command for command in calls))
        credentials = set()
        for name in b.NAMES:
            node = self.root / "output" / name
            self.assertFalse((node / "issuer.key").exists())
            credentials.add((node / "agent-api.token").read_bytes())
            config = json.loads((node / "bootstrap.json").read_text())
            for filename, expected in config["files"].items():
                self.assertEqual(b.digest((node / filename).read_bytes()), expected)
                self.assertEqual((node / filename).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(credentials), 3)
        self.assertFalse((self.root / "output" / b.NAMES[1] / "operator.token").exists())
        with self.assertRaises(FileExistsError):
            self.stage()

    def test_services_single_sqlite_cp_private_endpoints(self):
        units = b.service_files(inventory()["guests"][0], CLUSTER)
        cp = units["heteronetwork-control-plane.service"].decode()
        self.assertIn("--vpn-pool 10.251.0.0/24", cp)
        self.assertIn("--listen 172.28.240.11:8443", cp)
        self.assertIn("--web-ui-enabled false", cp)
        for flag in ("--service-instance-id", "--service-owner-host-id", "--service-owner-node-id"):
            self.assertIn(flag + " " + CLUSTER["issuer_node_id"], cp)
        self.assertIn("sqlite:///var/lib/heteronetwork/", cp)
        self.assertEqual(len(b.service_files(inventory()["guests"][1], CLUSTER)), 1)
        for data in units.values():
            self.assertNotIn(b"10.250.", data)
            self.assertNotIn(b"public-services-autopilot", data)

    def test_agent_disables_discovery_and_runtime_does_not_reuse_token(self):
        live = b.agent_args()
        self.assertNotIn("--join-token-path", live)
        self.assertIn("--join-token-path", b.agent_args(enroll=True))
        self.assertIn("--enroll-only", b.agent_args(enroll=True))
        self.assertIn("--disable-public-services-autopromotion", live)
        self.assertIn("--disable-public-stun-fallback", live)
        self.assertIn("--disable-overlay-services", live)
        self.assertIn(b"env -i", b.unit(live))
        self.assertIn(b"HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_ENABLED=false", b.unit(live))

    def test_unit_arguments_reject_shell_and_systemd_expansion(self):
        for arg in ("bad;command", "%n", "$(id)", "foo\nExecStart=/bin/sh"):
            with self.assertRaises(ValueError):
                b.unit(["/bin/false", arg])

    def test_kubeadm_canonical_contract(self):
        self.assertEqual(b.CONFIG, Path("/etc/heteronetwork"))
        self.assertEqual(b.STATE, Path("/var/lib/heteronetwork"))
        self.assertEqual(b.BIN.parent, Path("/opt/heteronetwork"))
        self.assertIn("heteronetwork0", b.agent_args())
        target, mode = b.target_file("agent-api.token")
        self.assertEqual(target, Path("/etc/heteronetwork/kubernetes/agent-api-token"))
        self.assertEqual(mode, 0o400)
        self.assertIn(str(target), b.agent_args())

    def test_owned_write_is_idempotent_but_never_overwrites(self):
        path = self.root / "file"
        b.owned_file(path, b"original", 0o600)
        b.owned_file(path, b"original", 0o600)
        with self.assertRaises(ValueError):
            b.owned_file(path, b"replacement", 0o600)
        self.assertEqual(path.read_bytes(), b"original")
        alias = self.root / "alias"
        alias.symlink_to(path)
        with self.assertRaises(ValueError):
            b.owned_file(alias, b"original", 0o600)

    def test_journal_is_private_atomic_and_preserves_binding(self):
        with patch.object(b, "JOURNAL", self.root):
            state = {"schema_version": 1, "binding": "fixture", "phase": "installed"}
            b.journal_write(state)
            next_state = copy.deepcopy(state)
            next_state["phase"] = "enrolling"
            b.journal_write(next_state)
            self.assertEqual(json.loads((self.root / "journal.json").read_text()), next_state)
            self.assertEqual((self.root / "journal.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual([p.name for p in self.root.iterdir()], ["journal.json"])

    def test_uncertain_enrollment_and_changed_bundle_never_start_services(self):
        self.archive()
        bundle = self.root
        artifact = (bundle / "artifact").read_bytes()
        (bundle / "artifact.json").write_bytes(artifact)
        (bundle / "archive.tar.gz").write_bytes((bundle / "archive").read_bytes())
        config = {"schema_version": 1, "guest": inventory()["guests"][0], "cluster_id": CLUSTER["cluster_id"],
                  "artifact_sha256": b.digest(artifact), "files": {}}
        raw = json.dumps(config).encode()
        (bundle / "bootstrap.json").write_bytes(raw)
        journal = self.root / "journal"
        journal.mkdir(mode=0o700)
        (journal / "lock").write_bytes(b"")
        for binding, phase in ((b.digest(raw), "enrolling"), ("changed", "installed")):
            (journal / "journal.json").write_text(json.dumps({"schema_version": 1, "binding": binding, "phase": phase}))
            with patch.object(b, "JOURNAL", journal), patch.object(b.os, "geteuid", return_value=0), \
                 patch.object(b, "private_path", side_effect=lambda path: Path(path)), \
                 patch.object(b, "guest_identity"), patch.object(b, "run") as run:
                with self.assertRaises(ValueError):
                    b.install(bundle, start=True)
                run.assert_not_called()

    def test_guest_boundary_rechecks_provisioning_uuid_and_address(self):
        guest = inventory()["guests"][0]
        b.validate_guest(guest)
        for field, value in (("address", "10.250.0.5"), ("product_uuid", str(uuid.uuid4()))):
            with self.assertRaises(ValueError):
                b.validate_guest({**guest, field: value})

    def roster(self):
        return {"schema_version": 1, "cluster_id": CLUSTER["cluster_id"], "nodes": [
            {"name": name, "node_id": f"test-node-{i}", "vpn_ip": f"10.251.0.{i}",
             "wireguard_public_key": base64.b64encode(bytes([i])*32).decode()}
            for i, name in enumerate(b.NAMES, 1)]}

    def test_vpn_roster_requires_exact_three_distinct_dev_nodes(self):
        roster = self.roster()
        b.checked_roster(roster, CLUSTER["cluster_id"])
        for field, value in (("vpn_ip", "10.250.0.5"), ("wireguard_public_key", "invalid"),
                             ("node_id", roster["nodes"][1]["node_id"])):
            bad = copy.deepcopy(roster)
            bad["nodes"][0][field] = value
            with self.assertRaises(ValueError):
                b.checked_roster(bad, CLUSTER["cluster_id"])
        with self.assertRaises(ValueError):
            b.checked_roster({**roster, "nodes": roster["nodes"][:2]}, CLUSTER["cluster_id"])

    def test_sustained_gate_and_failed_recheck_invalidate_evidence(self):
        config = {"schema_version": 1, "guest": inventory()["guests"][0], "cluster_id": CLUSTER["cluster_id"]}
        raw = json.dumps(config).encode()
        (self.root / "bootstrap.json").write_bytes(raw)
        (self.root / "roster.json").write_text(json.dumps(self.roster()))
        (self.root / "lock").write_bytes(b"")
        (self.root / "api.token").write_bytes(b"a" * 64)
        state = {"schema_version": 1, "binding": b.digest(raw), "phase": "started"}
        (self.root / "journal.json").write_text(json.dumps(state))
        clock = [0]
        with patch.object(b, "JOURNAL", self.root), patch.object(b.os, "geteuid", return_value=0), \
             patch.object(b, "private_path", side_effect=lambda path: Path(path)), patch.object(b, "guest_identity"), \
             patch.object(b, "target_file", return_value=(self.root / "api.token", 0o400)), \
             patch.object(b.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(b.time, "sleep", side_effect=lambda n: clock.__setitem__(0, clock[0]+n)), \
             patch.object(b, "vpn_sample") as sample:
            result = b.verify_vpn(self.root, self.root / "roster.json")
            self.assertEqual(sample.call_count, 13)
            self.assertEqual(result["duration_seconds"], 60)
            self.assertFalse(result["kubernetes_ready"])
            self.assertEqual(json.loads((self.root / "journal.json").read_text())["phase"], "vpn-verified-local")
            sample.side_effect = ValueError("encrypted health failed")
            with self.assertRaises(ValueError):
                b.verify_vpn(self.root, self.root / "roster.json")
            failed = json.loads((self.root / "journal.json").read_text())
            self.assertEqual(failed["phase"], "started")
            self.assertNotIn("vpn_check", failed)

    def test_vpn_sample_rejects_plain_route_or_no_encrypted_growth(self):
        local, *peers = self.roster()["nodes"]
        before = {p["wireguard_public_key"]: ["100", "100"] for p in peers}
        allowed = {p["wireguard_public_key"]: [p["vpn_ip"] + "/32"] for p in peers}
        handshakes = {p["wireguard_public_key"]: [str(int(b.time.time()))] for p in peers}
        for route_device in ("dev0", "heteronetwork0"):
            def fake_run(args, timeout=60):
                if args[0] == "/usr/bin/wg":
                    return local["wireguard_public_key"].encode()
                if args[0] == "/usr/sbin/ip":
                    return json.dumps([{"dev": route_device}]).encode()
                return b""
            with patch.object(b, "health_json", return_value=local), patch.object(b, "run", side_effect=fake_run), \
                 patch.object(b, "wg_table", side_effect=lambda field: {"transfer": before, "allowed-ips": allowed, "latest-handshakes": handshakes}[field]):
                with self.assertRaises(ValueError):
                    b.vpn_sample(local, peers, "test-token")


if __name__ == "__main__":
    unittest.main()
