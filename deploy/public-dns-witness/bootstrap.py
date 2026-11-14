#!/usr/bin/env python3
"""Deploy the external witness and provision its token without storing it in Git or Terraform state."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
NAMESPACE = 'heterocloud-dns'
NAME = 'public-dns-witness-token'


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def token_file(work):
    work = Path(work).resolve(strict=True)
    st = work.stat()
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError('operator directory must be private and owned by the operator')
    path = work / 'public-dns-witness-token'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            stream.write(secrets.token_hex(32))
            stream.flush()
            os.fsync(stream.fileno())
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='ascii') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 or st.st_nlink != 1:
            raise ValueError('witness token file is not private')
        token = stream.read(256)
    if len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('invalid witness token')
    return path, token


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--kubeconfig', required=True)
    args = parser.parse_args()
    path, token = token_file(args.work_dir)
    kubectl = ['kubectl', '--kubeconfig', args.kubeconfig, '-n', NAMESPACE]
    existing = run(kubectl + ['get', 'secret', NAME, '--ignore-not-found', '-o', 'json'],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    if existing:
        value = json.loads(existing)
        if set(value.get('data', {})) != {'token'} or base64.b64decode(value['data']['token'], validate=True).decode('ascii') != token:
            raise ValueError('existing witness token differs; use an explicit rotation procedure')
    else:
        run(kubectl + ['create', 'secret', 'generic', NAME, '--from-file=token=' + str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    run(['wrangler', 'deploy'], cwd=HERE, stdout=sys.stdout, stderr=sys.stderr)
    # Wrangler receives the secret only via stdin, never the argument vector.
    run(['wrangler', 'secret', 'put', 'WITNESS_TOKEN'], cwd=HERE, input=token + '\n',
        text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    print(json.dumps({'result': 'deployed', 'kubernetes_secret': NAME}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError):
        # Commands that handle the token may include sensitive diagnostics.
        print('external witness setup failed; existing token and DNS were left in place', file=sys.stderr)
        raise SystemExit(1)
