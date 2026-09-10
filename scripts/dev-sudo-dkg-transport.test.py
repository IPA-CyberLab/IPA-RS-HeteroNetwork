"""Offline transport contract tests; no SSH, real packets or guest operations."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("transport", Path(__file__).with_name("dev-sudo-dkg-transport.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
LOCAL_POPEN = subprocess.Popen


class TransportTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(t.subprocess, "Popen", side_effect=AssertionError("unmocked process launch prohibited"))
        guard.start()
        self.addCleanup(guard.stop)

    def test_ssh_pins_and_no_interactive_fallback(self):
        self.assertEqual(t.SSH[:5], ["/usr/bin/ssh", "-F", "/dev/null", "-i",
                                   "/var/lib/hetero-dev-provisioner/admin_ed25519"])
        for option in ("BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes",
                       "ConnectTimeout=10", "UserKnownHostsFile=/var/lib/hetero-dev-provisioner/known_hosts"):
            self.assertIn(option, t.SSH)

    def test_invalid_members_and_phases_never_invoke(self):
        with patch.object(t, "invoke") as invoke:
            for sender, recipient, round_number in ((0, 2, 1), (1, 4, 1), (1, 1, 1), (1, 2, 3)):
                with self.assertRaises(ValueError):
                    t.transfer(sender, recipient, round_number)
            for phase in ("shell", "reset", "sudo-enable", "part1;id"):
                with self.assertRaises(ValueError):
                    t.phase(1, phase)
            invoke.assert_not_called()

    def test_invoke_fixed_ssh_quoting_timeout_and_sanitized_environment(self):
        arguments = ["sudo", "-n", "/usr/bin/python3", "-c", "print('fixture only')"]
        def local_child(command, **kwargs):
            return LOCAL_POPEN([sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"], **kwargs)
        with patch.object(t.subprocess, "Popen", side_effect=local_child) as spawn:
            self.assertEqual(t.invoke(3, arguments, b"fixture-input"), b"fixture-input")
        self.assertEqual(spawn.call_args.args[0], [*t.SSH, "devadmin@172.28.240.13", shlex.join(arguments)])
        self.assertEqual(spawn.call_args.kwargs, {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL, "env": t.ENV, "start_new_session": True})

    def test_invoke_rejects_failure_and_kills_overflowing_local_child(self):
        for script in ("raise SystemExit(1)",
                       "import os,time; os.write(1,b'x'*65537); time.sleep(30)"):
            processes = []
            def local_child(command, **kwargs):
                child = LOCAL_POPEN([sys.executable, "-c", script], **kwargs)
                processes.append(child)
                return child
            with patch.object(t.subprocess, "Popen", side_effect=local_child):
                with self.assertRaises(ValueError):
                    t.invoke(1, ["fixed-fixture"])
            self.assertIsNotNone(processes[0].poll())

    def test_invoke_deadline_kills_local_child(self):
        processes = []
        def local_child(command, **kwargs):
            child = LOCAL_POPEN([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
            processes.append(child)
            return child
        with patch.object(t.subprocess, "Popen", side_effect=local_child), \
                patch.object(t.time, "monotonic", side_effect=[0, 81]):
            with self.assertRaises(ValueError):
                t.invoke(1, ["fixed-fixture"])
        self.assertIsNotNone(processes[0].poll())

    def transfer_fixture(self, sender, recipient, round_number):
        packet = {"member_id": sender} if round_number == 1 else {"sender": sender, "recipient": recipient}
        packet["package"] = "synthetic-confidential-fixture"
        raw = json.dumps(packet).encode()
        receipt = json.dumps({"received": True, "sha256": hashlib.sha256(raw).hexdigest()}).encode()
        return raw, receipt

    def test_all_six_recipient_paths_for_both_rounds(self):
        for round_number in (1, 2):
            for sender in (1, 2, 3):
                for recipient in (1, 2, 3):
                    if sender == recipient:
                        continue
                    raw, receipt = self.transfer_fixture(sender, recipient, round_number)
                    with patch.object(t, "invoke", side_effect=[raw, receipt]) as invoke:
                        result = t.transfer(sender, recipient, round_number)
                    send, receive = invoke.call_args_list
                    self.assertEqual(send.args[0], sender)
                    self.assertEqual(receive.args[0], recipient)
                    self.assertEqual(receive.args[2], raw)
                    for call in (send, receive):
                        self.assertEqual(call.args[1][:4], ["sudo", "-n", "/usr/bin/python3", "-c"])
                        for forbidden in ("round1.secret", "round2.secret", "key-share.json"):
                            self.assertNotIn(forbidden, call.args[1][4])
                        self.assertNotIn("synthetic-confidential-fixture", call.args[1][4])
                        self.assertNotIn(hashlib.sha256(raw).hexdigest(), call.args[1][4])
                    source = f"round1-{sender}.json" if round_number == 1 else f"outgoing-round2/to-{recipient}.json"
                    target = f"round1-{sender}.json" if round_number == 1 else f"round2-from-{sender}.json"
                    self.assertIn(source, send.args[1][4])
                    self.assertIn(target, receive.args[1][4])
                    self.assertEqual(result, {"sender": sender, "recipient": recipient,
                                             "round": round_number, "delivered": True})
                    self.assertNotIn(hashlib.sha256(raw).hexdigest(), json.dumps(result))

    def test_bad_packet_identity_stops_before_recipient_call(self):
        for packet, round_number in (({"member_id": 2}, 1),
                                    ({"sender": 2, "recipient": 3}, 2),
                                    ({"sender": 1, "recipient": 2}, 2)):
            with patch.object(t, "invoke", return_value=json.dumps(packet).encode()) as invoke:
                with self.assertRaises(ValueError):
                    t.transfer(1, 3, round_number)
                self.assertEqual(invoke.call_count, 1)

    def test_malformed_packet_stops_before_recipient_call(self):
        with patch.object(t, "invoke", return_value=b"not-json") as invoke:
            with self.assertRaises(ValueError):
                t.transfer(1, 3, 2)
            self.assertEqual(invoke.call_count, 1)

    def test_wrong_receipt_not_reported_delivered(self):
        raw, _ = self.transfer_fixture(1, 3, 2)
        for receipt in ({"received": True, "sha256": "wrong"}, {"received": False, "sha256": "wrong"}):
            with patch.object(t, "invoke", side_effect=[raw, json.dumps(receipt).encode()]):
                with self.assertRaises(ValueError):
                    t.transfer(1, 3, 2)

    def test_phase_fixed_command_and_activation_flags(self):
        for name in ("preflight", "part1", "part2", "part3", "inspect"):
            response = {"member_id": 3, "phase": name, "sudo_activation_performed": False,
                        "signer_start_performed": False}
            with patch.object(t, "invoke", return_value=json.dumps(response).encode()) as invoke:
                t.phase(3, name)
                invoke.assert_called_once_with(3, ["sudo", "-n", "/usr/bin/python3", t.HELPER, name])
            for field in ("sudo_activation_performed", "signer_start_performed"):
                bad = {**response, field: True}
                with patch.object(t, "invoke", return_value=json.dumps(bad).encode()):
                    with self.assertRaises(ValueError):
                        t.phase(3, name)

    def test_remote_receive_is_exclusive_and_retry_compares_bytes(self):
        raw, receipt = self.transfer_fixture(1, 3, 2)
        with patch.object(t, "invoke", side_effect=[raw, receipt]) as invoke:
            t.transfer(1, 3, 2)
        source = invoke.call_args_list[1].args[1][4]
        compile(source, "receiver", "exec")
        self.assertIn("os.O_EXCL", source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("0o600", source)
        self.assertIn("except FileExistsError:", source)
        self.assertIn("stream.read(65537)==data", source)
        self.assertIn("os.fsync", source)

    def test_main_rejects_wrong_physical_host_without_ssh(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["transport", "part1"]), \
                patch.object(t.os, "getuid", return_value=0), patch.object(t.os, "geteuid", return_value=0), \
                patch.object(t.socket, "gethostname", return_value="other-host"), \
                patch.object(t, "invoke") as invoke, contextlib.redirect_stderr(output):
            self.assertEqual(t.main(), 1)
            invoke.assert_not_called()
        self.assertIn("inspect", output.getvalue())


if __name__ == "__main__":
    unittest.main()
