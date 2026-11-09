import importlib.util
import ipaddress
from pathlib import Path
import threading
import unittest
import urllib.error
import urllib.request


spec = importlib.util.spec_from_file_location('postgres_dcs_metrics', Path(__file__).with_name('postgres-dcs-metrics.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
DATA = b'''# etcd metrics
etcd_network_active_peers{Local="a",Remote="b"} 1
etcd_network_active_peers{Local="a",Remote="c"} 0
etcd_server_has_leader 1
etcd_server_leader_changes_seen_total 1.086e+03
other_metric{secret="do-not-forward"} 42
'''


class MetricsTests(unittest.TestCase):
    def test_projection_contains_only_aggregate_health(self):
        result = module.project(DATA)
        self.assertIn(b'heteronetwork_postgres_dcs_active_peers 1\n', result)
        self.assertIn(b'heteronetwork_postgres_dcs_leader_changes_total 1086\n', result)
        self.assertNotIn(b'do-not-forward', result)
        self.assertNotIn(b'Remote', result)
        self.assertIn(b'heteronetwork_postgres_dcs_leader_changes_total 1086123\n',
                      module.project(DATA.replace(b'1.086e+03', b'1086123')))

    def test_missing_duplicated_or_invalid_data_is_not_reported_as_healthy(self):
        for value in (b'', DATA + b'etcd_server_has_leader 1\n',
                      DATA.replace(b'has_leader 1', b'has_leader 2'),
                      DATA.replace(b'Remote="b"} 1', b'Remote="b"} 2'),
                      DATA + b'etcd_network_active_peers{Local="a",Remote="b"} 1\n',
                      DATA.replace(b'Remote="b"} 1', b'Remote="b"} NaN'),
                      b'x' * (module.MAX_BODY + 1)):
            with self.subTest(value=value[:40]), self.assertRaises(ValueError):
                module.project(value)

    def test_real_http_reports_upstream_failure_and_rejects_other_paths(self):
        def unavailable():
            raise OSError('unavailable')
        for collector, path, expected in ((lambda: module.project(DATA), '/metrics', 200),
                                           (unavailable, '/metrics', 503),
                                           (lambda: b'ok', '/not-metrics', 404)):
            with module.Server(('127.0.0.1', 0), module.handler([ipaddress.ip_network('127.0.0.1/32')], collector)) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}{path}', timeout=2) as response:
                            status = response.status
                    except urllib.error.HTTPError as error:
                        status = error.code
                    self.assertEqual(status, expected)
                finally:
                    server.shutdown()
                    thread.join()

    def test_http_rejects_a_source_outside_the_allowed_overlay(self):
        with module.Server(('127.0.0.1', 0), module.handler([ipaddress.ip_network('10.250.0.2/32')], lambda: b'ok')) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/metrics', timeout=2)
                self.assertEqual(error.exception.code, 403)
            finally:
                server.shutdown()
                thread.join()


if __name__ == '__main__':
    unittest.main()
