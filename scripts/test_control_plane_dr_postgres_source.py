import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pg_source', ROOT / 'control_plane_dr_postgres_source.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def source(**overrides):
    config = {'binary_dir': '/usr/lib/postgresql/17/bin', 'host': '/run/postgresql',
              'port': 55432, 'user': 'postgres', 'allow_standby': True,
              'max_receiver_age_seconds': 120, 'max_replay_lag_bytes': 16777216,
              'max_rate_mib': 20}
    config.update(overrides)
    return module.Source(config, None)


def completed(stdout=b''):
    return SimpleNamespace(returncode=0, stdout=stdout)


class PostgresSourceTests(unittest.TestCase):
    def check(self, row, **config):
        with mock.patch.object(module.subprocess, 'run', side_effect=[completed(row), completed(b'pg_basebackup (PostgreSQL) 17.11')]):
            return source(**config).inspect()

    def test_streaming_standby_with_bounded_lag_is_accepted(self):
        self.assertEqual(self.check(b'170011|t|0|12345|67890|t\n'), ['170011', 't', '0', '12345', '67890'])

    def test_stale_or_disconnected_standby_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'disconnected or lagging'):
            self.check(b'170011|t|0|12345|67890|f\n')

    def test_standby_is_opt_in(self):
        with self.assertRaisesRegex(RuntimeError, 'not enabled'):
            self.check(b'170011|t|0|12345|67890|t\n', allow_standby=False)

    def test_custom_tablespaces_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'tablespaces'):
            self.check(b'170011|f|1|12345|67890|t\n')

    def test_client_major_must_match_server(self):
        with mock.patch.object(module.subprocess, 'run', side_effect=[completed(b'170011|f|0|12345|67890|t\n'),
                                                                       completed(b'pg_basebackup (PostgreSQL) 16.9')]):
            with self.assertRaisesRegex(RuntimeError, 'major versions differ'):
                source().inspect()

    def test_failover_during_stream_does_not_succeed(self):
        client = source()
        with mock.patch.object(client, 'inspect', side_effect=[['170011', 't', '0', '12345', '67890'],
                                                               ['170011', 'f', '0', '12345', '67890']]):
            with mock.patch.object(module.subprocess, 'run', return_value=completed()):
                with self.assertRaisesRegex(RuntimeError, 'changed during backup'):
                    client.backup()


if __name__ == '__main__':
    unittest.main()
