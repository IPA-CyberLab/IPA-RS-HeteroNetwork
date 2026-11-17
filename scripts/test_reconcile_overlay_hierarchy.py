import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SPEC = importlib.util.spec_from_file_location(
    "reconcile_overlay_hierarchy", Path(__file__).with_name("reconcile-overlay-hierarchy.py")
)
reconcile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconcile)


class HierarchyPolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = {"idle_timeout_seconds": 60, "acl_rules": [{"id": "existing"}]}
        self.writes = []
        test = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def response(self, data):
                content = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def do_GET(self):
                test.assertEqual(self.headers.get("Authorization"), "Bearer owner-token")
                self.response({"cluster_policy": test.policy})

            def do_PUT(self):
                test.assertEqual(self.headers.get("Authorization"), "Bearer owner-token")
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.policy = data["cluster_policy"]
                test.writes.append(test.policy)
                self.response({"cluster_policy": test.policy})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_check_then_update_preserves_other_policy(self):
        config = {"overlay_strict_hierarchy": True}
        self.assertEqual(reconcile.reconcile(config, self.endpoint, "owner-token", check=True), 2)
        self.assertEqual(self.writes, [])
        self.assertEqual(reconcile.reconcile(config, self.endpoint, "owner-token"), 0)
        self.assertEqual(self.policy, {
            "idle_timeout_seconds": 60,
            "acl_rules": [{"id": "existing"}],
            "overlay_strict_hierarchy": True,
        })
        self.assertEqual(reconcile.reconcile(config, self.endpoint, "owner-token"), 0)
        self.assertEqual(len(self.writes), 1)

    def test_refuses_insecure_endpoint_and_other_policy_fields(self):
        with self.assertRaises(ValueError):
            reconcile.endpoint_url("http://192.0.2.1:19088")
        with self.assertRaises(ValueError):
            reconcile.reconcile({"acl_rules": []}, self.endpoint, "owner-token")

    def test_localities_merge_preserves_unmanaged_nodes_and_removes_explicit_entries(self):
        self.policy["overlay_strict_hierarchy"] = True
        self.policy["overlay_node_localities"] = {
            "node-unmanaged": {"region": "old", "zone": "site-a"},
            "node-removed": {"region": "old", "zone": "site-b"},
        }
        desired = {"node-a": {"region": "east", "zone": "site-a"}}
        config = {"overlay_strict_hierarchy": True}
        self.assertEqual(reconcile.reconcile(config, self.endpoint, "owner-token", True, desired, {"node-removed"}), 2)
        self.assertEqual(self.writes, [])
        self.assertEqual(reconcile.reconcile(config, self.endpoint, "owner-token", False, desired, {"node-removed"}), 0)
        self.assertEqual(self.policy["overlay_node_localities"], {
            "node-unmanaged": {"region": "old", "zone": "site-a"},
            "node-a": {"region": "east", "zone": "site-a"},
        })
        self.assertEqual(reconcile.reconcile(config, self.endpoint, "owner-token", False, desired, {"node-removed"}), 0)
        self.assertEqual(len(self.writes), 1)

    def test_locality_input_requires_known_hosts_and_real_dns_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            roster = root / "roster.json"
            localities = root / "localities.json"
            roster.write_text(json.dumps({"hosts": {"host-a": "node-a", "host-b": "node-b"}}))
            localities.write_text(json.dumps({"nodes": {"host-a": {"region": "east", "zone": "site-a"}}, "remove": ["host-b"]}))
            self.assertEqual(reconcile.load_localities(localities, roster),
                             ({"node-a": {"region": "east", "zone": "site-a"}}, {"node-b"}))
            localities.write_text(json.dumps({"nodes": {"host-a": {"region": "east", "zone": "site-a", "network": "uplink-a"}}, "remove": []}))
            self.assertEqual(reconcile.load_localities(localities, roster)[0]["node-a"]["network"], "uplink-a")
            for invalid in (
                {"nodes": {"unknown": {"region": "east", "zone": "site-a"}}, "remove": []},
                {"nodes": {"host-a": {"region": "Tokyo", "zone": "site-a"}}, "remove": []},
                {"nodes": {"host-a": {"region": "east", "zone": "site-a", "network": "Bad network"}}, "remove": []},
                {"nodes": {"host-a": {"region": "east", "zone": "site-a"}}, "remove": ["host-a"]},
                {"nodes": {}, "remove": ["host-b", "host-b"]},
                {"nodes": {"host-a": {"region": "east"}}, "remove": []},
                {"nodes": {"host-a": {"region": "east", "zone": "site-a"},
                           "host-b": {"region": "west", "zone": "site-a"}}, "remove": []},
            ):
                localities.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    reconcile.load_localities(localities, roster)

    def test_token_file_must_be_private_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("owner-token\n")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                reconcile.read_token(path)
            path.chmod(0o600)
            self.assertEqual(reconcile.read_token(path), "owner-token")
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                reconcile.read_token(alias)


if __name__ == "__main__":
    unittest.main()
