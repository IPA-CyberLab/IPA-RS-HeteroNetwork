#!/usr/bin/env python3
"""Repair the known legacy HeteroCloud issuer in managed console bootstrap state.

The existing public verification origin is the source of truth. All other
settings, including owner identity and private credentials, remain byte-for-byte
unchanged. This utility is deliberately limited to the known legacy realm.
"""
import base64
import binascii
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit

BOOTSTRAP = Path('/etc/heteronetwork/public-services/bootstrap.env')
PREFIX = 'HETERONETWORK_PUBLIC_SERVICES_'
OLD_ISSUER = 'http://console.heteronetwork.internal:18079/realms/heterocloud'


def decode(values, name):
    encoded = values.get(PREFIX + name + '_B64')
    if encoded is None:
        return None
    try:
        return base64.b64decode(encoded, validate=True).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError, ValueError) as error:
        raise ValueError('Invalid managed OIDC configuration') from error


def read_private(path, expected_uid):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 131072):
            raise ValueError('Unsafe managed OIDC configuration file')
        chunks = []
        while True:
            data = os.read(descriptor, 65536)
            if not data:
                break
            chunks.append(data)
        return b''.join(chunks), info
    finally:
        os.close(descriptor)


def atomic_replace(path, content, info):
    descriptor, temporary = tempfile.mkstemp(prefix='.console-issuer-', dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, info.st_uid, info.st_gid)
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def reconcile(path, expected_uid, schedule):
    try:
        original, info = read_private(path, expected_uid)
    except FileNotFoundError:
        return 'skipped'
    try:
        lines = original.decode('utf-8').splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise ValueError('Invalid managed OIDC configuration') from error
    values = {}
    relevant = {PREFIX + name + '_B64' for name in (
        'OIDC_ISSUER_URL', 'OIDC_CLIENT_ID', 'OIDC_DEVICE_VERIFICATION_ORIGIN')}
    for line in lines:
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        key, value = line.rstrip('\r\n').split('=', 1)
        if key not in relevant:
            continue
        if key in values:
            raise ValueError('Duplicate managed OIDC configuration key')
        values[key] = value
    issuer = decode(values, 'OIDC_ISSUER_URL')
    if issuer != OLD_ISSUER or decode(values, 'OIDC_CLIENT_ID') != 'ipars-web':
        return 'unchanged'
    origin = decode(values, 'OIDC_DEVICE_VERIFICATION_ORIGIN')
    try:
        parsed = urlsplit(origin or '')
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ('', '/')
                or parsed.query or parsed.fragment or parsed.port == 0):
            raise ValueError('Invalid public verification origin')
    except ValueError as error:
        raise ValueError('Invalid public verification origin') from error
    corrected = f'https://{parsed.netloc}/id/realms/heterocloud'
    replacement = base64.b64encode(corrected.encode()).decode('ascii')
    target = PREFIX + 'OIDC_ISSUER_URL_B64'
    updated = ''.join(
        f'{target}={replacement}' + ('\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else '')
        if line.startswith(target + '=') else line
        for line in lines
    ).encode('utf-8')
    atomic_replace(path, updated, info)
    try:
        schedule()
    except Exception:
        atomic_replace(path, original, info)
        try:
            schedule()
        except Exception:
            pass
        raise RuntimeError('Console issuer reconciliation failed; previous configuration restored') from None
    return 'updated'


def main():
    if os.geteuid() != 0:
        raise SystemExit('Console issuer reconciliation requires root')
    def schedule():
        # Never interrupt an in-progress reconcile: a timer-driven oneshot may
        # itself be waiting on systemd. Queue an idle run without blocking;
        # otherwise the next timer invocation reads the updated bootstrap file.
        subprocess.run(['systemctl', 'start', '--no-block', 'heteronetwork-public-services-autopilot.service'],
                       check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        print(reconcile(BOOTSTRAP, 0, schedule))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(f'Console issuer reconciliation failed: {error}') from None


if __name__ == '__main__':
    main()
