#!/usr/bin/env python3
"""Exercise placement request timeouts with an isolated HTTP server and real curl."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest


SCRIPT = Path(__file__).resolve().with_name('keycloak-autopilot.sh')


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path.startswith('/slow'):
            time.sleep(10)
        elif self.path.startswith('/delayed'):
            time.sleep(3)
        try:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"fixture":true}')
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


class RequestTimeoutE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_request(self, commands):
        with tempfile.TemporaryDirectory(prefix='identity-timeout-e2e-') as root:
            env = dict(os.environ, HETERONETWORK_KEYCLOAK_AUTOPILOT_TESTING='1',
                       HETERONETWORK_KEYCLOAK_AUTOPILOT_TEST_ROOT=root,
                       NO_PROXY='127.0.0.1', no_proxy='127.0.0.1',
                       FIXTURE_PORT=str(self.server.server_port))
            script = '''
source "$1" help >/dev/null
mkdir -p "$runtime_dir" "$state_dir"
request_file="$runtime_dir/request"
printf '{}' > "$request_file"
autopilot_bearer_token=fixture-only-secret
''' + commands
            result = subprocess.run(['bash', '-c', script, 'fixture', str(SCRIPT)], env=env,
                                    text=True, capture_output=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('fixture-only-secret', result.stdout + result.stderr)

    def test_response_slower_than_old_two_second_timeout_succeeds(self):
        started = time.monotonic()
        self.run_request('''
control_plane_urls=("http://127.0.0.1:$FIXTURE_PORT/delayed")
request_reconciliation
grep -q '"fixture":true' "$response_file"
''')
        self.assertGreaterEqual(time.monotonic() - started, 3)

    def test_slow_directory_scan_is_bounded_and_resumes_at_next_endpoint(self):
        started = time.monotonic()
        self.run_request('''
control_plane_urls=("http://127.0.0.1:$FIXTURE_PORT/slow-1" "http://127.0.0.1:$FIXTURE_PORT/slow-2" "http://127.0.0.1:$FIXTURE_PORT/fast")
if request_reconciliation; then exit 1; fi
test "$(cat "$control_plane_cursor_path")" = 2
rm -f "$response_file" "$curl_config_file"
request_reconciliation
grep -q '"fixture":true' "$response_file"
test "$(cat "$control_plane_cursor_path")" = 0
''')
        self.assertLess(time.monotonic() - started, 22)


if __name__ == '__main__':
    unittest.main()
