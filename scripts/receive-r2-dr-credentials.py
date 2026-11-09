#!/usr/bin/env python3
"""Receive a bucket-scoped R2 key without putting it in arguments or chat.

The operator creates one R2 object-read/write credential scoped to the two
existing disaster-recovery buckets. This program verifies both destinations
with random short-lived objects and writes protected configurations for the
existing backup tools. It never changes existing credentials or buckets.
"""
import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tomllib
import urllib.request


REPO = Path(__file__).resolve().parent.parent
DEFAULT_FLASH = 'heterocloud-flash-disaster-backups'
DEFAULT_CONTROL = 'heterocloud-control-plane-disaster-backups'
DEFAULT_DIRECTORY = REPO.parent / '.heteronetwork-iac' / 'r2-offsite'


def find_account(token, bucket_names):
    def get(path):
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
                                         headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)
        if not data.get('success'):
            raise ValueError('Cloudflare lookup failed')
        return data.get('result')

    matches = []
    accounts = get('/accounts?per_page=50')
    if not isinstance(accounts, list):
        raise ValueError('Account lookup failed')
    for account in accounts:
        account_id = account.get('id', '')
        if not re.fullmatch(r'[0-9a-f]{32}', account_id):
            continue
        try:
            result = get('/accounts/' + account_id + '/r2/buckets?per_page=100')
        except Exception:
            continue
        names = {item.get('name') for item in result.get('buckets', [])}
        if set(bucket_names).issubset(names):
            matches.append(account_id)
    if len(matches) != 1:
        raise ValueError('The two backup buckets were not found in exactly one accessible account')
    return matches[0]


def protected_directory(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('The protected output directory must be owned and mode 0700')


def write_configurations(directory, configurations):
    """Create both files without following symlinks, overwriting, or partial output."""
    protected_directory(directory)
    files = [(directory / name, value) for name, value in configurations.items()]
    if any(path.exists() or path.is_symlink() for path, _ in files):
        raise ValueError('A destination configuration already exists; rotation is a separate operation')
    created = []
    try:
        for path, value in files:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            created.append(path)
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def verify_destinations(configurations, client_class):
    """Only create, read and remove objects with names generated in this run."""
    for config in configurations:
        client = client_class(config)
        name = '_heterocloud_setup_probe/' + secrets.token_hex(24)
        contents = secrets.token_bytes(32)
        created = False
        try:
            client.request('PUT', name, contents)
            created = True
            if client.request('GET', name) != contents:
                raise ValueError('The destination readback differed')
        finally:
            if created:
                try:
                    client.request('DELETE', name)
                except Exception:
                    raise RuntimeError('A temporary verification object could not be removed') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument('--flash-bucket', default=DEFAULT_FLASH)
    parser.add_argument('--control-bucket', default=DEFAULT_CONTROL)
    args = parser.parse_args()
    if args.flash_bucket == args.control_bucket:
        raise ValueError('The Flash and control-plane buckets must be distinct')
    wrangler = Path.home() / '.config/.wrangler/config/default.toml'
    token = tomllib.loads(wrangler.read_text())['oauth_token']
    account = find_account(token, [args.flash_bucket, args.control_bucket])
    del token
    access_key = getpass.getpass('R2 Access Key ID (hidden): ').strip()
    secret_key = getpass.getpass('R2 Secret Access Key (hidden): ').strip()
    if not all(re.fullmatch(r'[A-Za-z0-9_+=/.-]{16,256}', value)
               for value in (access_key, secret_key)):
        raise ValueError('The R2 credentials have an invalid format')
    base = {'endpoint': 'https://' + account + '.r2.cloudflarestorage.com',
            'region': 'auto', 'access_key': access_key, 'secret_key': secret_key}
    configurations = {
        'flash.json': dict(base, bucket=args.flash_bucket),
        'control-plane.json': dict(base, bucket=args.control_bucket),
    }
    module_path = REPO.parent / 'IPA-RS-HeteroCloud-Flash/ops/offsite.py'
    spec = importlib.util.spec_from_file_location('heterocloud_flash_offsite', module_path)
    if not spec or not spec.loader:
        raise ValueError('The Flash S3 client is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    verify_destinations(configurations.values(), module.S3)
    write_configurations(args.directory, configurations)
    print('R2 credentials verified and saved in the protected backup configuration directory.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        raise SystemExit('Credential setup failed; check the scoped token, bucket access and protected output directory.') from None
