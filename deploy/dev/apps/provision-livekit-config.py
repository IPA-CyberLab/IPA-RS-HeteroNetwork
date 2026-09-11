#!/usr/bin/env python3
"""Create/verify DEV LiveKit config only; never start services or regenerate keys."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
import app_secrets
import livekit_config


def require(value):
    if not value:
        raise ValueError('DEV LiveKit configuration contract failed')


def main():
    require(len(sys.argv) == 1)
    foundation = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(foundation.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    spec = importlib.util.spec_from_file_location('identity_apply', foundation)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    require(helper.UID == app_secrets.UID)
    path = Path('/var/lib/heteronetwork-dev-app-credentials/seeds.json')
    require(stat.S_IMODE(path.lstat().st_mode) == 0o600
            and stat.S_IMODE(path.parent.lstat().st_mode) == 0o700)
    seeds = json.loads(helper.trusted_file(path, 65536))
    desired = livekit_config.secret(seeds)
    namespace = livekit_config.NAMESPACE
    flow = json.loads(helper.run(['get', 'secret', 'heterocloud-flow-dev-secrets', '-n', namespace, '-o', 'json']))
    require(flow['metadata'].get('annotations', {}).get('heteronetwork.dev.cluster-uid') == helper.UID
            and flow['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == app_secrets.MANAGER
            and not flow['metadata'].get('deletionTimestamp'))
    for field, seed in (('redis-password', 'redis'), ('turn-shared-secret', 'turn'),
                        ('livekit-api-key', 'livekit_key'), ('livekit-api-secret', 'livekit_secret')):
        require(base64.b64decode(flow['data'][field], validate=True).decode() == seeds[seed])
    args = ['get', 'secret', livekit_config.NAME, '-n', namespace, '--ignore-not-found', '-o', 'json']
    raw = helper.run(args).strip()
    created = not raw
    if raw:
        app_secrets.verify(json.loads(raw), desired)
    else:
        payload = json.dumps(desired).encode()
        helper.run(['create', '--dry-run=server', '-f', '-'], payload)
        helper.run(['create', '-f', '-'], payload)
    app_secrets.verify(json.loads(helper.run(args)), desired)
    print(json.dumps({'secret': livekit_config.NAME, 'created': created,
                      'matches_existing_flow_credentials': True, 'workloads_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV LiveKit configuration stopped; no credentials emitted or rotated', file=sys.stderr)
        sys.exit(1)
