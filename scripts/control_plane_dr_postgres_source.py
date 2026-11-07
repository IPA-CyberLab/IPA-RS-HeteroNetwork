#!/usr/bin/env python3
"""Stream a consistent PostgreSQL base backup from a verified local server.

The backup is written only to stdout; diagnostic output never includes database
contents or credentials. The calling recovery program must encrypt the stream.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

from control_plane_dr import private_file

USER = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,62}$')


def config_from_file(path):
    value = json.loads(private_file(path).read_text())
    allowed = {'binary_dir', 'host', 'port', 'user', 'run_as', 'password_file',
               'ssl_root_cert', 'allow_standby', 'max_replay_lag_bytes',
               'max_receiver_age_seconds', 'max_rate_mib', 'checkpoint_mode', 'library_path'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError('Invalid PostgreSQL source configuration')
    directory = Path(value['binary_dir'])
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError('An absolute trusted PostgreSQL binary directory is required')
    directory_info = directory.stat()
    if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
        raise ValueError('The PostgreSQL binary directory must be root-owned and protected')
    for name in ('psql', 'pg_basebackup'):
        binary = directory / name
        info = binary.stat()
        if (binary.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or not os.access(binary, os.X_OK)):
            raise ValueError('PostgreSQL binaries must be root-owned and not writable by other users')
    host = value['host']
    if (not isinstance(host, str) or not host or len(host) > 253
            or any(ord(char) < 33 or ord(char) == 127 for char in host)):
        raise ValueError('Invalid PostgreSQL host')
    if host.startswith('/') and (not Path(host).is_absolute() or '..' in Path(host).parts):
        raise ValueError('Invalid PostgreSQL socket directory')
    for key, default, lower, upper in [('port', 5432, 1, 65535),
                                        ('max_replay_lag_bytes', 16777216, 0, 1073741824),
                                        ('max_receiver_age_seconds', 120, 1, 3600),
                                        ('max_rate_mib', 20, 1, 1024)]:
        item = value.get(key, default)
        if not isinstance(item, int) or isinstance(item, bool) or not lower <= item <= upper:
            raise ValueError('Invalid PostgreSQL source limit')
        value[key] = item
    if not isinstance(value.get('user'), str) or not USER.fullmatch(value['user']):
        raise ValueError('Invalid PostgreSQL role name')
    if not isinstance(value.get('allow_standby', False), bool):
        raise ValueError('Invalid standby policy')
    if value.get('checkpoint_mode', 'spread') not in ('spread', 'fast'):
        raise ValueError('Invalid PostgreSQL checkpoint mode')
    account = None
    if 'run_as' in value:
        if os.geteuid() != 0 or not isinstance(value['run_as'], str) or not USER.fullmatch(value['run_as']):
            raise ValueError('A root-owned source must select a valid Unix account')
        account = pwd.getpwnam(value['run_as'])
        if account.pw_uid == 0:
            raise ValueError('The PostgreSQL client must not run as root')
    if not host.startswith('/'):
        cert = value.get('ssl_root_cert')
        if not cert or not Path(cert).is_absolute() or not Path(cert).is_file():
            raise ValueError('TCP PostgreSQL requires a CA certificate and hostname verification')
    if 'password_file' in value:
        file = Path(value['password_file'])
        info = file.stat()
        expected = account.pw_uid if account else os.geteuid()
        if (not file.is_absolute() or file.is_symlink() or not stat.S_ISREG(info.st_mode)
                or info.st_uid != expected or info.st_mode & 0o077):
            raise ValueError('The PostgreSQL password file must be private to the client account')
    if 'library_path' in value:
        directory = Path(value['library_path'])
        info = directory.stat()
        if not directory.is_absolute() or directory.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('The PostgreSQL library directory must be root-owned and protected')
    return value, account


class Source:
    def __init__(self, config, account):
        self.config = config
        self.account = account
        self.env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                    'PGHOST': config['host'], 'PGPORT': str(config['port']), 'PGUSER': config['user']}
        if config['host'].startswith('/'):
            self.env['PGSSLMODE'] = 'disable'
        else:
            self.env['PGSSLMODE'] = 'verify-full'
            self.env['PGSSLROOTCERT'] = config['ssl_root_cert']
        if 'password_file' in config:
            self.env['PGPASSFILE'] = config['password_file']
        if 'library_path' in config:
            self.env['LD_LIBRARY_PATH'] = config['library_path']
        self.identity = {} if account is None else {
            'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}

    def binary(self, name):
        return str(Path(self.config['binary_dir']) / name)

    def inspect(self):
        query = """SELECT current_setting('server_version_num'),
            pg_is_in_recovery(),
            (SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')),
            (SELECT system_identifier FROM pg_control_system()),
            extract(epoch FROM pg_postmaster_start_time())::bigint,
            CASE WHEN pg_is_in_recovery() THEN
              COALESCE((SELECT status = 'streaming' AND
                 extract(epoch FROM clock_timestamp() - last_msg_receipt_time) <= %d
                 FROM pg_stat_wal_receiver LIMIT 1), false)
              AND COALESCE(pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())
                 BETWEEN 0 AND %d, false)
            ELSE true END""" % (self.config['max_receiver_age_seconds'], self.config['max_replay_lag_bytes'])
        result = subprocess.run([self.binary('psql'), '-X', '--no-password', '-d', 'postgres',
                                 '-A', '-t', '-F', '|', '-v', 'ON_ERROR_STOP=1', '-c', query],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=self.env, timeout=30, check=False, **self.identity)
        if result.returncode:
            raise RuntimeError('PostgreSQL source health check failed')
        fields = result.stdout.decode('ascii').strip().split('|')
        if (len(fields) != 6 or not fields[0].isdigit() or fields[1] not in ('t', 'f')
                or not fields[2].isdigit() or not fields[3].isdigit() or not fields[4].isdigit()
                or fields[5] not in ('t', 'f')):
            raise RuntimeError('PostgreSQL source health result is invalid')
        if int(fields[2]) != 0:
            raise RuntimeError('Streaming recovery does not support extra tablespaces')
        if fields[1] == 't' and not self.config.get('allow_standby', False):
            raise RuntimeError('Standby backup is not enabled')
        if fields[5] != 't':
            raise RuntimeError('PostgreSQL standby is disconnected or lagging')
        version = subprocess.run([self.binary('pg_basebackup'), '--version'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.env,
                                 timeout=10, check=False, **self.identity)
        match = re.search(rb'\b(\d+)\.', version.stdout)
        if version.returncode or not match or int(match.group(1)) != int(fields[0]) // 10000:
            raise RuntimeError('PostgreSQL server and backup client major versions differ')
        return fields[:5]

    def backup(self):
        before = self.inspect()
        result = subprocess.run([self.binary('pg_basebackup'), '--no-password', '--format=tar',
                                 '--pgdata=-', '--wal-method=fetch',
                                 '--checkpoint=' + self.config.get('checkpoint_mode', 'spread'),
                                 '--max-rate=' + str(self.config['max_rate_mib']) + 'M'],
                                stdin=subprocess.DEVNULL, stdout=sys.stdout.buffer,
                                stderr=subprocess.DEVNULL, env=self.env, check=False, **self.identity)
        if result.returncode:
            raise RuntimeError('PostgreSQL physical backup failed')
        if self.inspect() != before:
            raise RuntimeError('PostgreSQL server identity or role changed during backup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config, account = config_from_file(args.config)
    Source(config, account).backup()


if __name__ == '__main__':
    main()
