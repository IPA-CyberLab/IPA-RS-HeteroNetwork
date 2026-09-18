#!/usr/bin/env python3
"""Unit checks for the live overlay console convergence gate."""

import importlib.util
import ipaddress
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("verify-overlay-client-console.py")
SPEC = importlib.util.spec_from_file_location("verify_overlay_client_console", MODULE_PATH)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def dns_response(query, address, *, flags=0x8180, response_id=None):
    query_id = struct.unpack("!H", query[:2])[0]
    response_id = query_id if response_id is None else response_id
    question = query[12:]
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 5, 4)
        + ipaddress.ip_address(address).packed
    )
    return struct.pack("!HHHHHH", response_id, flags, 1, 1, 0, 0) + question + answer


class OverlayConsoleConvergenceTests(unittest.TestCase):
    def test_dns_answer_must_match_query_and_gateway(self):
        query = verify.dns_a_query(verify.CONSOLE_DNS_NAME, 0x1234)
        self.assertEqual(
            verify.dns_a_answers(dns_response(query, "10.250.0.5"), 0x1234),
            ["10.250.0.5"],
        )
        with self.assertRaisesRegex(ValueError, "invalid DNS response"):
            verify.dns_a_answers(
                dns_response(query, "10.250.0.5", response_id=0x5678), 0x1234)
        with self.assertRaisesRegex(ValueError, "invalid DNS response"):
            verify.dns_a_answers(
                dns_response(query, "10.250.0.5", flags=0x8380), 0x1234)

    def test_gateway_readiness_requires_client_probe_dns_and_direct_console(self):
        with (
            patch.object(verify, "gateway_client_probe_is_ready", return_value=True) as health,
            patch.object(verify, "overlay_dns_resolves_to_gateway", return_value=True) as dns,
            patch.object(verify, "gateway_console_ui_is_ready", return_value=True) as console,
        ):
            self.assertTrue(verify.gateway_route_is_ready("10.250.0.5"))
        health.assert_called_once_with("10.250.0.5")
        dns.assert_called_once_with("10.250.0.5")
        console.assert_called_once_with("10.250.0.5")

        with (
            patch.object(verify, "gateway_client_probe_is_ready", return_value=True),
            patch.object(verify, "overlay_dns_resolves_to_gateway", return_value=False),
            patch.object(verify, "gateway_console_ui_is_ready", return_value=True) as console,
        ):
            self.assertFalse(verify.gateway_route_is_ready("10.250.0.5"))
        console.assert_not_called()

    def test_console_readiness_checks_direct_port_ui_and_auth_config(self):
        class Response:
            status = 200

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, _size=-1):
                return self.body

        class Opener:
            def __init__(self):
                self.calls = []
                self.responses = iter([
                    Response(b'<div id="root"></div><script src="/ui/app.js" async></script>'),
                    Response(b'{"auth_enabled":true,"provider":"keycloak"}'),
                ])

            def open(self, request, timeout):
                self.calls.append((request.full_url, request.get_header("Host"), timeout))
                return next(self.responses)

        opener = Opener()
        with patch.object(verify.urllib.request, "build_opener", return_value=opener):
            self.assertTrue(verify.gateway_console_ui_is_ready("10.250.0.5"))
        self.assertEqual(opener.calls, [
            ("http://10.250.0.5:9781/ui/", "console.heteronetwork.internal:9781", 1),
            ("http://10.250.0.5:9781/ui/config", "console.heteronetwork.internal:9781", 1),
        ])

    def test_convergence_requires_two_consecutive_complete_probes(self):
        probes = iter([False, True, True])
        with (
            patch.object(verify, "gateway_route_is_ready", side_effect=lambda _: next(probes)) as ready,
            patch.object(verify.time, "sleep"),
        ):
            elapsed = verify.wait_for_gateway_routes("10.250.0.5")
        self.assertEqual(ready.call_count, 3)
        self.assertGreaterEqual(elapsed, 0)


if __name__ == "__main__":
    unittest.main()
