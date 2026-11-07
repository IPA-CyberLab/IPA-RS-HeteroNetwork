#!/usr/bin/env python3
"""Restore a real disposable PostgreSQL database through the recovery store.

Both servers, credentials, data and the repository are generated fixtures. The
script never connects to production and cleans up only its own temporary paths.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location('control_plane_dr', Path(__file__).with_name('control_plane_dr.py'))
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restic', required=True)
    parser.add_argument('--pg-bin', type=Path, required=True)
    parser.add_argument('--pg-share', type=Path, required=True)
    parser.add_argument('--pg-lib', type=Path, required=True)
    parser.add_argument('--os-user', default='nobody')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('This disposable test uses runuser and requires root')

    import pwd
    identity = pwd.getpwnam(args.os_user)
    pg_env = {'PATH': str(args.pg_bin) + ':/usr/bin:/bin',
              'LD_LIBRARY_PATH': str(args.pg_lib), 'LANG': 'C', 'LC_ALL': 'C'}
    servers = []
    private = tempfile.TemporaryDirectory(prefix='hc-dr-pg-e2e-')
    pg_root = Path(tempfile.mkdtemp(prefix='hc-dr-postgres-'))
    os.chown(pg_root, identity.pw_uid, identity.pw_gid)
    os.chmod(pg_root, 0o700)

    def command(*argv, stdin=None):
        return subprocess.run(argv, env=pg_env, input=stdin, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True, timeout=120)

    def start(name, username):
        data = pg_root / name
        listen = port()
        command('/usr/sbin/runuser', '-u', args.os_user, '--', str(args.pg_bin / 'initdb'),
                '-D', str(data), '-L', str(args.pg_share), '--auth=trust',
                '--no-locale', '--encoding=UTF8', '--username=' + username)
        servers.append(data)
        command('/usr/sbin/runuser', '-u', args.os_user, '--', str(args.pg_bin / 'pg_ctl'),
                '-D', str(data), '-l', str(pg_root / (name + '.log')),
                '-o', f'-h 127.0.0.1 -p {listen} -k {pg_root}', '-w', 'start')
        return listen

    try:
        source_port = start('source', 'source_admin')
        target_port = start('target', 'target_admin')
        marker = secrets.token_hex(24)
        source_psql = [str(args.pg_bin / 'psql'), '-X', '-h', '127.0.0.1', '-p', str(source_port),
                       '-U', 'source_admin', '-v', 'ON_ERROR_STOP=1']
        command(*source_psql, '-d', 'postgres', '-c', 'CREATE DATABASE recovery_fixture')
        command(*source_psql, '-d', 'recovery_fixture', '-c',
                "CREATE TABLE probe(marker text NOT NULL); INSERT INTO probe VALUES ('" + marker + "')")
        root = Path(private.name)
        password = root / 'password'
        password.write_text(secrets.token_urlsafe(32) + '\n')
        password.chmod(0o600)
        source = root / 'source-backup'
        source.write_text('#!/bin/sh\nexec env LD_LIBRARY_PATH=' + shlex.quote(str(args.pg_lib)) + ' '
                          + shlex.quote(str(args.pg_bin / 'pg_dumpall')) + ' -h 127.0.0.1 -p '
                          + str(source_port) + ' -U source_admin --no-password\n')
        source.chmod(0o700)
        config_file = root / 'config.json'
        config_file.write_text(json.dumps({'repository': str(root / 'repository'),
            'password_file': str(password), 'sources': [{'name': 'postgres', 'executable': str(source)}],
            'max_component_bytes': 64 * 1024 * 1024, 'max_total_bytes': 64 * 1024 * 1024,
            'timeout_seconds': 120}))
        config_file.chmod(0o600)
        config = dr.read_config(config_file, allow_local=True)
        subprocess.run([args.restic, 'init', '--quiet'], env=dr.restic_env(config), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        result = dr.backup(config, args.restic)
        dr.verify(config, args.restic, result['snapshot'])
        restore_dir = root / 'restore'
        restore_dir.mkdir(mode=0o700)
        dr.restore(config, args.restic, result['snapshot'], restore_dir)
        target_psql = [str(args.pg_bin / 'psql'), '-X', '-h', '127.0.0.1', '-p', str(target_port),
                       '-U', 'target_admin', '-v', 'ON_ERROR_STOP=1']
        with (restore_dir / 'postgres').open('rb') as dump:
            restored = subprocess.run(target_psql + ['-d', 'postgres'], env=pg_env, stdin=dump,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if restored.returncode:
            raise RuntimeError('The isolated PostgreSQL restore failed')
        actual = command(*target_psql, '-d', 'recovery_fixture', '-At', '-c', 'SELECT marker FROM probe')
        if actual.stdout.decode().strip() != marker:
            raise RuntimeError('The recovered PostgreSQL value did not match')

        # A physical base backup preserves all databases at one consistent
        # checkpoint. The disposable fixture has no additional tablespaces.
        physical_config = root / 'postgres-source.json'
        physical_config.write_text(json.dumps({'binary_dir': str(args.pg_bin), 'host': str(pg_root),
            'port': source_port, 'user': 'source_admin', 'run_as': args.os_user,
            'library_path': str(args.pg_lib), 'max_rate_mib': 100, 'checkpoint_mode': 'fast'}))
        physical_config.chmod(0o600)
        source_program = Path(__file__).with_name('control_plane_dr_postgres_source.py').resolve()
        source.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -B '
                          + shlex.quote(str(source_program)) + ' --config '
                          + shlex.quote(str(physical_config)) + '\n')
        physical = dr.backup(config, args.restic)
        dr.verify(config, args.restic, physical['snapshot'])
        physical_restore = root / 'physical-restore'
        physical_restore.mkdir(mode=0o700)
        dr.restore(config, args.restic, physical['snapshot'], physical_restore)
        physical_data = pg_root / 'physical'
        physical_data.mkdir(mode=0o700)
        with tarfile.open(physical_restore / 'postgres', 'r:') as archive:
            archive.extractall(physical_data, filter='data')
        for directory, dirs, files in os.walk(physical_data, followlinks=False):
            os.chown(directory, identity.pw_uid, identity.pw_gid)
            for name in dirs + files:
                os.lchown(Path(directory) / name, identity.pw_uid, identity.pw_gid)
        physical_port = port()
        servers.append(physical_data)
        command('/usr/sbin/runuser', '-u', args.os_user, '--', str(args.pg_bin / 'pg_ctl'),
                '-D', str(physical_data), '-l', str(pg_root / 'physical.log'),
                '-o', f'-h 127.0.0.1 -p {physical_port} -k {pg_root}', '-w', 'start')
        physical_psql = [str(args.pg_bin / 'psql'), '-X', '-h', '127.0.0.1', '-p', str(physical_port),
                         '-U', 'source_admin', '-v', 'ON_ERROR_STOP=1']
        actual = command(*physical_psql, '-d', 'recovery_fixture', '-At', '-c', 'SELECT marker FROM probe')
        if actual.stdout.decode().strip() != marker:
            raise RuntimeError('The physical PostgreSQL backup did not restore')
        print(json.dumps({'result': 'passed', 'real_postgresql_dump_restored': True,
                          'real_postgresql_basebackup_restored': True,
                          'repository_encrypted': True, 'fixture_only': True}))
    finally:
        cleanup_ok = True
        for data in reversed(servers):
            if (data / 'postmaster.pid').exists():
                stopped = subprocess.run(['/usr/sbin/runuser', '-u', args.os_user, '--', str(args.pg_bin / 'pg_ctl'),
                                          '-D', str(data), '-m', 'immediate', '-w', 'stop'], env=pg_env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                cleanup_ok = cleanup_ok and stopped.returncode == 0
        private.cleanup()
        if cleanup_ok:
            shutil.rmtree(pg_root)
        else:
            raise RuntimeError('The disposable PostgreSQL fixture could not be stopped')


if __name__ == '__main__':
    main()
