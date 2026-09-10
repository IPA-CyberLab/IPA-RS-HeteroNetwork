"""Offline wrapper tests: inert CLI, synthetic packets, no guests or real keys."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("dev_dkg", Path(__file__).with_name("dev-sudo-dkg.py"))
dkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dkg)
TRUSTED = dkg.trusted


class DkgTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.root, self.bundle = self.base / "state", self.base / "bundle"
        self.bundle.mkdir()
        self.stack.enter_context(patch.object(dkg, "ROOT", self.root))
        self.stack.enter_context(patch.object(dkg, "BUNDLE", self.bundle))
        # Ownership checks are tested separately; fixtures are deliberately non-root.
        self.trust = self.stack.enter_context(patch.object(dkg, "trusted"))
        self.cli = self.stack.enter_context(patch.object(dkg.subprocess, "run", return_value=SimpleNamespace(returncode=0)))
        self.roster = json.dumps(dkg.expected_roster()).encode()
        (self.bundle / "roster.json").write_bytes(self.roster)

    def packets(self):
        self.root.mkdir()
        (self.root / "roster.json").write_bytes(self.roster)
        for member in range(1, 4):
            self.packet(f"round1-{member}.json", {"member_id": member})
        self.packet("round1.secret.json", {"fixture": "private-state"})
        self.packet("round2.secret.json", {"fixture": "private-state"})
        for sender in (1, 2):
            self.packet(f"round2-from-{sender}.json", {"sender": sender, "recipient": 3})

    def packet(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def test_frozen_roster_schema_and_endpoints(self):
        roster = dkg.expected_roster()
        self.assertEqual(set(roster), {"schema_version", "ceremony_id", "cluster_id", "epoch", "members"})
        self.assertEqual(roster["cluster_id"], dkg.CLUSTER)
        self.assertEqual([m["identifier"] for m in roster["members"]], [1, 2, 3])
        self.assertEqual([m["endpoint"] for m in roster["members"]],
                         [f"http://10.251.0.{i}:8981" for i in range(1, 4)])
        with self.assertRaises(ValueError):
            dkg.decode(b'{"epoch":1,"epoch":2}')

    def test_part1_fixed_command_and_no_regeneration(self):
        dkg.run_part("part1", 3)
        command = self.cli.call_args.args[0]
        self.assertEqual(command, [str(self.bundle / "ipars"), "quorum", "dkg", "part1",
            "--roster", str(self.root / "roster.json"), "--member-id", "3",
            "--secret-out", str(self.root / "round1.secret.json"),
            "--packet-out", str(self.root / "round1-3.json")])
        self.assertEqual(self.cli.call_args.kwargs, dict(env=dkg.ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60))
        with self.assertRaises(FileExistsError):
            dkg.run_part("part1", 3)
        self.assertEqual(self.cli.call_count, 1)
        self.assertEqual((self.root / "roster.json").read_bytes(), self.roster)

    def test_part2_only_local_secret_and_frozen_round1_paths(self):
        self.packets()
        dkg.run_part("part2", 3)
        command = self.cli.call_args.args[0]
        self.assertEqual(command[:4], [str(self.bundle / "ipars"), "quorum", "dkg", "part2"])
        self.assertEqual([command[i + 1] for i, arg in enumerate(command) if arg == "--round1-packet"],
                         [str(self.root / f"round1-{i}.json") for i in range(1, 4)])
        self.assertEqual(command[-6:], ["--secret", str(self.root / "round1.secret.json"),
            "--secret-out", str(self.root / "round2.secret.json"), "--packets-out", str(self.root / "outgoing-round2")])

    def test_part3_only_recipient_packets_and_private_outputs(self):
        self.packets()
        dkg.run_part("part3", 3)
        command = self.cli.call_args.args[0]
        self.assertEqual([command[i + 1] for i, arg in enumerate(command) if arg == "--round2-packet"],
                         [str(self.root / f"round2-from-{i}.json") for i in (1, 2)])
        self.assertEqual(command[-6:], ["--secret", str(self.root / "round2.secret.json"),
            "--key-share-out", str(self.root / "key-share.json"), "--manifest-out", str(self.root / "manifest.json")])

    def test_misrouted_or_wrong_sender_packet_never_executes_cli(self):
        self.packets()
        for bad in ({"sender": 2, "recipient": 3}, {"sender": 1, "recipient": 2}):
            self.packet("round2-from-1.json", bad)
            with self.assertRaises(ValueError):
                dkg.run_part("part3", 3)
        self.cli.assert_not_called()

    def test_wrong_round1_member_or_changed_roster_never_executes_cli(self):
        self.packets()
        self.packet("round1-1.json", {"member_id": 2})
        with self.assertRaises(ValueError):
            dkg.run_part("part2", 3)
        (self.root / "roster.json").write_bytes(self.roster + b"\n")
        with self.assertRaises(ValueError):
            dkg.run_part("part2", 3)
        self.cli.assert_not_called()

    def test_failed_part1_preserves_root_and_refuses_retry(self):
        self.cli.return_value.returncode = 1
        with self.assertRaises(ValueError):
            dkg.run_part("part1", 3)
        self.assertTrue(self.root.is_dir())
        with self.assertRaises(FileExistsError):
            dkg.run_part("part1", 3)
        self.assertEqual(self.cli.call_count, 1)

    def test_write_new_never_overwrites_or_follows_symlink(self):
        target = self.base / "target"
        dkg.write_new(target, b"original")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            dkg.write_new(target, b"replacement")
        alias = self.base / "alias"
        alias.symlink_to(target)
        with self.assertRaises(OSError):
            dkg.write_new(alias, b"replacement")
        self.assertEqual(target.read_bytes(), b"original")

    def identity_fixture(self):
        member = 3
        _, machine, node = dkg.GUESTS[member - 1]
        self.stack.enter_context(patch.object(dkg.os, "getuid", return_value=0))
        self.stack.enter_context(patch.object(dkg.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.object(dkg.socket, "gethostname", return_value="hetero-dev-3"))
        self.stack.enter_context(patch.object(dkg.os, "access", return_value=True))
        self.stack.enter_context(patch.object(Path, "read_text", return_value=machine))
        values = {"/etc/machine-id": machine.encode(),
                  "/opt/heteronetwork-dev-bootstrap/bootstrap.json": json.dumps(
                      {"cluster_id": dkg.CLUSTER, "guest": {"machine_id": machine}}).encode(),
                  "/etc/heteronetwork/kubernetes/agent-api-token": b"fixture-api-token",
                  str(self.bundle / "roster.json"): self.roster, str(self.bundle / "ipars"): b"inert-fixture"}
        self.stack.enter_context(patch.object(dkg, "read", side_effect=lambda path, *args, **kw: values[str(path)]))
        self.stack.enter_context(patch.object(dkg, "CLI_SHA256", hashlib.sha256(b"inert-fixture").hexdigest()))
        opener = self.stack.enter_context(patch.object(dkg.urllib.request, "build_opener"))
        opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"node_id": node, "vpn_ip": "10.251.0.3"}).encode()
        return values, opener

    def test_identity_fixed_authenticated_local_endpoint(self):
        _, opener = self.identity_fixture()
        self.assertEqual(dkg.check_identity(), 3)
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:9780/v1/status")
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture-api-token")
        self.assertEqual(opener.return_value.open.call_args.kwargs, {"timeout": 5})
        with self.assertRaises(ValueError):
            dkg.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_identity_machine_dmi_api_roster_and_binary_mismatches(self):
        values, opener = self.identity_fixture()
        for key in values:
            saved = values[key]
            if key.endswith("agent-api-token"):
                continue
            values[key] = b"invalid"
            with self.assertRaises(ValueError):
                dkg.check_identity()
            values[key] = saved
        with patch.object(Path, "read_text", return_value="0" * 32):
            with self.assertRaises(ValueError):
                dkg.check_identity()
        opener.return_value.open.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"node_id": dkg.GUESTS[2][2], "vpn_ip": "10.250.0.3"}).encode()
        with self.assertRaises(ValueError):
            dkg.check_identity()
        self.cli.assert_not_called()

    def test_identity_rejects_foreign_bootstrap_cluster_and_machine(self):
        values, _ = self.identity_fixture()
        key = "/opt/heteronetwork-dev-bootstrap/bootstrap.json"
        original = json.loads(values[key])
        for field in ("cluster", "machine"):
            value = json.loads(json.dumps(original))
            if field == "cluster":
                value["cluster_id"] = "foreign-cluster"
            else:
                value["guest"]["machine_id"] = "0" * 32
            values[key] = json.dumps(value).encode()
            with self.assertRaises(ValueError):
                dkg.check_identity()
        self.cli.assert_not_called()

    def test_main_sanitizes_failures_and_does_not_run_after_identity_failure(self):
        output = io.StringIO()
        with patch.object(dkg.sys, "argv", ["dev-sudo-dkg.py", "part1"]), \
                patch.object(dkg, "check_identity", side_effect=ValueError("fixture-secret")), \
                contextlib.redirect_stderr(output):
            self.assertEqual(dkg.main(), 1)
        self.assertNotIn("fixture-secret", output.getvalue())
        self.cli.assert_not_called()

    def test_trusted_rejects_symlink_writable_foreign_or_hardlinked_file(self):
        target = Path("/fixture/private.json")
        for mode, uid, links in ((stat.S_IFLNK | 0o600, 0, 1),
                                 (stat.S_IFREG | 0o644, 0, 1),
                                 (stat.S_IFREG | 0o600, 1000, 1),
                                 (stat.S_IFREG | 0o600, 0, 2)):
            def info(path):
                return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links) if path == target else \
                    SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_nlink=1)
            with patch.object(Path, "lstat", info):
                with self.assertRaises(ValueError):
                    TRUSTED(target, private=True)

    def test_read_bounds_and_inspect_do_not_emit_key_share(self):
        oversized = self.base / "oversized"
        oversized.write_bytes(b"12345")
        with self.assertRaises(ValueError):
            dkg.read(oversized, maximum=4)
        self.packets()
        manifest = {key: value for key, value in dkg.expected_roster().items()
                    if key != "ceremony_id"}
        manifest["public_key_package"] = "fixture-public-package"
        self.packet("manifest.json", manifest)
        self.packet("key-share.json", {"fixture": "never-emit-private-share"})
        result = dkg.inspect(3)
        self.assertFalse(result["sudo_activation_performed"])
        self.assertFalse(result["signer_start_performed"])
        self.assertNotIn("never-emit", json.dumps(result))
        self.assertEqual(result["manifest_file_sha256"], hashlib.sha256(
            (self.root / "manifest.json").read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
