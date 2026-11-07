#!/usr/bin/env python3
"""Back up and restore an isolated TLS etcd cluster through encrypted restic."""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('control_plane_dr', Path(__file__).with_name('control_plane_dr.py'))
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)


def freeport():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextmanager
def noswap_tmpfs(path):
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'noswap,nodev,nosuid,noexec,mode=0700,size=32M',
                    'tmpfs', str(path)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=30)
    try:
        yield
    finally:
        subprocess.run(['umount', str(path)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restic', required=True)
    parser.add_argument('--etcd-bin', type=Path, required=True)
    args = parser.parse_args()
    processes = []
    with tempfile.TemporaryDirectory(prefix='hc-dr-etcd-e2e-') as private, \
         tempfile.TemporaryDirectory(prefix='hc-dr-etcd-shm-') as memory, noswap_tmpfs(memory):
        root = Path(private)
        memory_path = Path(memory)
        os.chmod(memory_path, 0o700)
        def run(*arguments):
            return subprocess.run(arguments, check=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=120)
        def openssl(*arguments):
            run('openssl', *arguments)
        ca = root / 'ca.crt'
        ca_key = root / 'ca.key'
        key = root / 'server.key'
        cert = root / 'server.crt'
        csr = root / 'server.csr'
        ext = root / 'extensions'
        ext.write_text('subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n')
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca_key),
                '-out', str(ca), '-subj', '/CN=hc-dr-fixture-ca', '-days', '1')
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                '-out', str(csr), '-subj', '/CN=hc-dr-fixture')
        openssl('x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key),
                '-CAcreateserial', '-out', str(cert), '-days', '1', '-extfile', str(ext))
        key.chmod(0o600)
        etcd = str(args.etcd_bin / 'etcd')
        ctl = str(args.etcd_bin / 'etcdctl')
        utl = str(args.etcd_bin / 'etcdutl')
        def client(endpoint, *arguments):
            return run(ctl, '--endpoints', endpoint, '--cacert', str(ca), '--cert', str(cert),
                       '--key', str(key), *arguments)
        def start(name, data, client_port, peer_port):
            endpoint = f'https://127.0.0.1:{client_port}'
            peer = f'http://127.0.0.1:{peer_port}'
            process = subprocess.Popen([etcd, '--name', name, '--data-dir', str(data),
                '--listen-client-urls', endpoint, '--advertise-client-urls', endpoint,
                '--listen-peer-urls', peer, '--initial-advertise-peer-urls', peer,
                '--initial-cluster', name + '=' + peer, '--initial-cluster-state', 'new',
                '--cert-file', str(cert), '--key-file', str(key), '--trusted-ca-file', str(ca),
                '--client-cert-auth'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError('The disposable etcd fixture stopped')
                try:
                    client(endpoint, 'endpoint', 'health')
                    return endpoint
                except subprocess.CalledProcessError:
                    time.sleep(.1)
            raise RuntimeError('The disposable etcd fixture did not start')

        try:
            original = start('source', root / 'source', freeport(), freeport())
            marker = secrets.token_hex(24)
            client(original, 'put', '/hc-dr-test/marker', marker)
            password = root / 'password'
            password.write_text(secrets.token_urlsafe(32) + '\n')
            password.chmod(0o600)
            source_config = root / 'etcd-source.json'
            source_config.write_text(json.dumps({'etcdctl': ctl, 'etcdutl': utl, 'endpoint': original,
                'ca': str(ca), 'cert': str(cert), 'key': str(key), 'tmp_dir': str(memory_path),
                'max_snapshot_bytes': 16 * 1024 * 1024}))
            source_config.chmod(0o600)
            source = root / 'source-backup'
            source_program = Path(__file__).with_name('control_plane_dr_etcd_source.py').resolve()
            source.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -B '
                              + shlex.quote(str(source_program)) + ' --config '
                              + shlex.quote(str(source_config)) + '\n')
            source.chmod(0o700)
            checked = subprocess.run([str(source)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
            if checked.returncode:
                raise RuntimeError('The isolated etcd snapshot source failed: ' + checked.stderr.decode(errors='replace')[-1200:])
            config_file = root / 'config.json'
            config_file.write_text(json.dumps({'repository': str(root / 'repository'),
                'password_file': str(password), 'sources': [{'name': 'etcd', 'executable': str(source)}],
                'max_component_bytes': 16 * 1024 * 1024, 'max_total_bytes': 16 * 1024 * 1024,
                'timeout_seconds': 120}))
            config_file.chmod(0o600)
            config = dr.read_config(config_file, allow_local=True)
            subprocess.run([args.restic, 'init', '--quiet'], env=dr.restic_env(config), check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            created = dr.backup(config, args.restic)
            dr.verify(config, args.restic, created['snapshot'])
            restored = root / 'restored'
            restored.mkdir(mode=0o700)
            dr.restore(config, args.restic, created['snapshot'], restored)
            peer_port, client_port = freeport(), freeport()
            peer = f'http://127.0.0.1:{peer_port}'
            restored_data = root / 'restored-etcd'
            run(utl, 'snapshot', 'restore', str(restored / 'etcd'), '--data-dir', str(restored_data),
                '--name', 'restored', '--initial-cluster', 'restored=' + peer,
                '--initial-advertise-peer-urls', peer)
            replacement = start('restored', restored_data, client_port, peer_port)
            found = client(replacement, 'get', '/hc-dr-test/marker', '--print-value-only').stdout.decode().strip()
            if found != marker:
                raise RuntimeError('The restored etcd fixture did not contain the marker')
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    print(json.dumps({'result': 'passed', 'real_etcd_snapshot_restored': True,
                      'mutual_tls': True, 'fixture_only': True}))


if __name__ == '__main__':
    main()
