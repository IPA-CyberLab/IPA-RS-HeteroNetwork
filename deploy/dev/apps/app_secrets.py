"""Fresh DEV service credentials; callers must persist seeds before provisioning.

No command entrypoint and no output: return values contain private material.
This covers service authentication, not ingress TLS, OIDC or LiveKit config.
"""
import base64
import json
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

UID = 'a39281cb-d273-4c5f-b7a7-fca722fb417b'
MANAGER = 'hetero-dev-app-secrets'
KEY_ID = 'heterocloud-dev-provider-1'
TOKEN_NAMES = ('csrf', 'flow_hmac', 'syouyu_hmac', 'livekit_key', 'livekit_secret',
               'turn', 'redis', 'garage_rpc', 'garage_admin', 'garage_metrics')


def generate_seeds():
    key = Ed25519PrivateKey.generate()
    return {'schema_version': 1, 'cluster_uid': UID,
            'provider_private_key': key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            'receipt': base64.b64encode(secrets.token_bytes(32)).decode(),
            **{name: secrets.token_hex(32) for name in TOKEN_NAMES}}


def validate_seeds(seeds):
    if (set(seeds) != {'schema_version', 'cluster_uid', 'provider_private_key', 'receipt', *TOKEN_NAMES}
            or type(seeds['schema_version']) is not int or seeds['schema_version'] != 1
            or seeds['cluster_uid'] != UID):
        raise ValueError('Wrong DEV credential state')
    for name in TOKEN_NAMES:
        value = seeds[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('Invalid DEV token state')
    if len({seeds[name] for name in TOKEN_NAMES}) != len(TOKEN_NAMES):
        raise ValueError('DEV tokens must be independent')
    if len(base64.b64decode(seeds['receipt'], validate=True)) != 32:
        raise ValueError('Invalid receipt key')
    key = serialization.load_pem_private_key(seeds['provider_private_key'].encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Wrong provider key type')
    return key


def build(seeds, databases):
    key = validate_seeds(seeds)
    if set(databases) != {'heterocloud-dev', 'heterocloud-flow-dev', 'heterocloud-syouyu-dev'}:
        raise ValueError('All three DEV database connections are required')
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    public_keys = json.dumps({KEY_ID: public}, sort_keys=True)
    resources = []

    def add(namespace, name, data):
        resources.append({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
            'metadata': {'namespace': namespace, 'name': name,
                         'labels': {'app.kubernetes.io/managed-by': MANAGER},
                         'annotations': {'heteronetwork.dev.cluster-uid': UID}},
            'data': {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}})

    add('heterocloud-dev', 'heterocloud-dev-runtime', {
        'database-url': databases['heterocloud-dev']['database-url'], 'csrf-key': seeds['csrf']})
    add('heterocloud-dev', 'heterocloud-dev-provider-signing', {
        'ed25519-private.pem': seeds['provider_private_key']})
    add('heterocloud-dev', 'heterocloud-dev-flow-access', {'hmac-secret': seeds['flow_hmac']})
    add('heterocloud-dev', 'heterocloud-dev-syouyu-access', {'hmac-secret': seeds['syouyu_hmac']})
    add('heterocloud-flow-dev', 'heterocloud-flow-dev-secrets', {
        'database-url': databases['heterocloud-flow-dev']['database-url'],
        'heterocloud-provider-public-keys.json': public_keys,
        'flow-principal-context-hmac-secret': seeds['flow_hmac'],
        'livekit-api-key': seeds['livekit_key'], 'livekit-api-secret': seeds['livekit_secret'],
        'turn-shared-secret': seeds['turn'], 'redis-password': seeds['redis'],
        'livekit-keys.yaml': json.dumps({seeds['livekit_key']: seeds['livekit_secret']})})
    add('heterocloud-flash-dev', 'heterocloud-flash-dev-provider-auth', {
        'provider-public-keys.json': public_keys})
    add('heterocloud-syouyu-dev', 'heterocloud-syouyu-dev-secrets', {
        'database-url': databases['heterocloud-syouyu-dev']['database-url'],
        'provider-public-keys.json': public_keys, 'receipt-encryption-key-base64': seeds['receipt'],
        'principal-context-hmac-secret': seeds['syouyu_hmac'], 'garage-rpc-secret': seeds['garage_rpc'],
        'garage-admin-token': seeds['garage_admin'], 'garage-metrics-token': seeds['garage_metrics']})
    return resources


def verify(actual, desired):
    if actual.get('type') != desired['type'] or actual.get('data') != desired['data']:
        raise ValueError('Existing DEV Secret data differs; rotation is not automatic')
    metadata = actual.get('metadata', {})
    if metadata.get('deletionTimestamp'):
        raise ValueError('DEV Secret is being deleted')
    for key in ('namespace', 'name'):
        if metadata.get(key) != desired['metadata'][key]:
            raise ValueError('DEV Secret identity differs')
    for key in ('labels', 'annotations'):
        if any(metadata.get(key, {}).get(k) != v for k, v in desired['metadata'][key].items()):
            raise ValueError('DEV Secret ownership differs')
