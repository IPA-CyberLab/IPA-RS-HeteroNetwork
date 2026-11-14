#!/usr/bin/env python3
"""Atomically install a Caddy base after validating it with live TLS blocks."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

TLS_BEGIN = b'# BEGIN managed flash-web TLS\n'
TLS_END = b'# END managed flash-web TLS\n'
CUSTOM_BEGIN = b'# BEGIN managed Flash custom domains\n'
CUSTOM_END = b'# END managed Flash custom domains\n'
ANCHOR = b'http://heterocloud.mizuame.app {\n'


def secure_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
            raise ValueError('untrusted gateway file')
        data = stream.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError('gateway file too large')
        return data


def managed_block(data, begin, end, required):
    if data.count(begin) != data.count(end) or data.count(begin) > 1:
        raise ValueError('ambiguous generated gateway block')
    if begin not in data:
        if required:
            raise ValueError('TLS synchronization has not completed')
        return b''
    start = data.index(begin)
    stop = data.index(end) + len(end)
    if stop <= start:
        raise ValueError('invalid generated gateway block')
    return data[start:stop]


def install(host, validator='/opt/heteronetwork/bin/caddy'):
    host = Path(host)
    candidate = host / 'public-gateway-base.candidate.Caddyfile'
    base = host / 'public-gateway-base.Caddyfile'
    extra = host / 'public-gateway-extra.Caddyfile'
    data = secure_read(candidate)
    if data.count(ANCHOR) != 1 or any(x in data for x in (TLS_BEGIN, TLS_END, CUSTOM_BEGIN, CUSTOM_END)):
        raise ValueError('invalid gateway base')
    lockfd = os.open(host / '.flash-web-tls.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(lockfd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
            raise ValueError('untrusted synchronization lock')
        fcntl.flock(lockfd, fcntl.LOCK_EX)
        try:
            current = secure_read(base)
        except FileNotFoundError:
            current = None
        try:
            effective = secure_read(extra)
        except FileNotFoundError:
            effective = None
        if effective is not None:
            tls = managed_block(effective, TLS_BEGIN, TLS_END, True)
            custom = managed_block(effective, CUSTOM_BEGIN, CUSTOM_END, False)
            combined = data.replace(ANCHOR, tls + custom + ANCHOR)
            fd, temporary = tempfile.mkstemp(prefix='.gateway-validate-', dir=host)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(combined)
                    stream.flush()
                    os.fsync(stream.fileno())
                subprocess.run([validator, 'validate', '--config', temporary, '--adapter', 'caddyfile'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30, check=True)
            finally:
                os.unlink(temporary)
        if current == data:
            candidate.unlink()
            return False
        os.replace(candidate, base)
        if effective is None:
            # Initial staging is not served until the TLS synchronizer has
            # populated this file and activation has validated it again.
            fd, temporary = tempfile.mkstemp(prefix='.gateway-seed-', dir=host)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    os.fchmod(stream.fileno(), 0o644)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, extra)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return True
    finally:
        os.close(lockfd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-dir', default='/etc/heteronetwork')
    args = parser.parse_args()
    print(json.dumps({'changed': install(args.host_dir)}))


if __name__ == '__main__':
    main()
