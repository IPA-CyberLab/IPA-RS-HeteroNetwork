#!/usr/bin/env python3

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("macos-client-live-e2e.py")
SPEC = importlib.util.spec_from_file_location("macos_client_live_e2e", MODULE_PATH)
assert SPEC and SPEC.loader
live = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = live
SPEC.loader.exec_module(live)


class PrivateFileTests(unittest.TestCase):
    def test_private_file_round_trip_and_rejects_exposed_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            live.write_private(path, b"secret")
            self.assertEqual(live.read_private(path, 100), b"secret")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            path.chmod(0o640)
            with self.assertRaisesRegex(live.LiveE2EError, "private input"):
                live.read_private(path, 100)

    def test_private_file_rejects_symbolic_and_hard_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"secret")
            source.chmod(0o600)
            symbolic = root / "symbolic"
            symbolic.symlink_to(source)
            with self.assertRaisesRegex(live.LiveE2EError, "private input"):
                live.read_private(symbolic, 100)

            hard = root / "hard"
            os.link(source, hard)
            with self.assertRaisesRegex(live.LiveE2EError, "private input"):
                live.read_private(source, 100)


class SponsorshipTests(unittest.TestCase):
    def test_sponsor_keeps_password_and_registration_out_of_command_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_uri = "heteronetwork://register?request=e30"
            import_uri = "heteronetwork://import?profile=e30"
            password = "test-password-value"
            paths = {}
            for name, value in {
                "request": request_uri,
                "password": password,
                "key": "test-key",
                "known": "test-host-key",
            }.items():
                paths[name] = root / name
                paths[name].write_text(value)
                paths[name].chmod(0o600)
            profile = root / "profile"
            args = type(
                "Args",
                (),
                {
                    "request_file": str(paths["request"]),
                    "profile_file": str(profile),
                    "ssh_key_file": str(paths["key"]),
                    "known_hosts_file": str(paths["known"]),
                    "sudo_password_file": str(paths["password"]),
                    "host": "192.0.2.10",
                    "user": "runner",
                },
            )()
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=import_uri + "\n", stderr=""
            )
            output = io.StringIO()
            with patch.object(live.subprocess, "run", return_value=completed) as run:
                with contextlib.redirect_stdout(output):
                    live.sponsor(args)

            command = run.call_args.args[0]
            self.assertNotIn(password, " ".join(command))
            self.assertNotIn(request_uri, " ".join(command))
            self.assertIn(password, run.call_args.kwargs["input"])
            self.assertIn(request_uri, run.call_args.kwargs["input"])
            self.assertNotIn(password, output.getvalue())
            self.assertNotIn(request_uri, output.getvalue())
            self.assertNotIn(import_uri, output.getvalue())
            self.assertEqual(profile.read_text(), import_uri + "\n")
            self.assertEqual(profile.stat().st_mode & 0o777, 0o600)

    def test_failure_message_redacts_all_private_values(self):
        message = live.sanitized_failure(
            "failure test-password-value heteronetwork://register?request=e30",
            ("test-password-value", "heteronetwork://register?request=e30"),
        )
        self.assertNotIn("test-password-value", message)
        self.assertNotIn("heteronetwork://", message)


class ConsoleProbeTests(unittest.TestCase):
    def test_probe_requires_fast_ui_and_keycloak_configuration(self):
        class Response:
            status = 200

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, _limit):
                return self.body

        class Opener:
            def __init__(self):
                self.responses = iter(
                    [
                        Response(b'<div id="root"></div><script src="/ui/app.js" async></script>'),
                        Response(b'{"auth_enabled":true,"provider":"keycloak"}'),
                    ]
                )

            def open(self, _request, timeout):
                self.timeout = timeout
                return next(self.responses)

        opener = Opener()
        with (
            patch.object(live.socket, "getaddrinfo", return_value=[("ok",)]),
            patch.object(live.urllib.request, "build_opener", return_value=opener),
            patch.object(live.time, "monotonic", side_effect=[0.0, 0.01, 0.02, 0.20, 0.21, 0.30]),
        ):
            result = live.console_probe(3)
        self.assertEqual(result["console_http_status"], 200)
        self.assertLess(result["console_open_ms"], 3000)
        self.assertEqual(opener.timeout, 3)


if __name__ == "__main__":
    unittest.main()
