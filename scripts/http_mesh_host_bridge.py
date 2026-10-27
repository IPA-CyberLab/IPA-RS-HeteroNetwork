#!/usr/bin/env python3
"""Start the optional Linux HTTP bridge using only this host's existing identity."""
import argparse
import base64
import json
import os
from pathlib import Path
import stat
import sys
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', default='/var/lib/heteronetwork/agent.json')
    parser.add_argument('--binary', default='/opt/heteronetwork/bin/heteronet-headless')
    args = parser.parse_args()
    endpoint = os.environ.get('HETERONETWORK_ENDPOINT', '')
    url = urllib.parse.urlsplit(endpoint)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise ValueError('a trusted HTTPS control-plane origin is required')
    descriptor = os.open(args.state, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 1024 * 1024:
            raise ValueError('agent state must be a private root-owned regular file')
        state = json.load(source)
    registered = state.get('registered_node') or {}
    if not registered or 'heteronetwork-stopped' in registered.get('tags', []):
        raise ValueError('this host must be registered and active')
    if registered['node_id'] != state['node_id'] or registered['wireguard_public_key'] != state['wireguard_public_key_b64']:
        raise ValueError('local identity does not match registration')
    for field in ('identity_private_key_b64', 'wireguard_private_key_b64'):
        if len(base64.b64decode(state[field], validate=True)) != 32:
            raise ValueError('invalid local node key')
    binary = Path(args.binary)
    if not binary.is_absolute() or binary.is_symlink():
        raise ValueError('bridge executable must use a trusted absolute path')
    for path in [binary, *binary.parents]:
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('bridge executable path must be owned and writable only by root')
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C',
                   'GOMEMLIMIT': '256MiB', 'GOMAXPROCS': '2',
                   'HETERONETWORK_ENDPOINT': endpoint,
                   'HETERONETWORK_IDENTITY_KEY': state['identity_private_key_b64'],
                   'HETERONETWORK_WIREGUARD_PRIVATE_KEY': state['wireguard_private_key_b64']}
    os.execve(binary, [str(binary), '--kernel-interface', 'hnhttp0'], environment)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never include state, environment or private key validation values.
        print('HTTP bridge startup failed: check the local identity, permissions and HTTPS endpoint', file=sys.stderr)
        sys.exit(1)
