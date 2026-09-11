"""Fixed isolated DEV LiveKit configuration, containing existing Redis credentials."""
import base64
import json

import app_secrets

NAMESPACE = 'heterocloud-flow-dev'
NAME = 'heterocloud-flow-dev-livekit-config'
MANAGER = 'hetero-dev-livekit-config'
DOMAIN = 'dev.heterocloud.mizuame.app'


def configuration(seeds):
    app_secrets.validate_seeds(seeds)
    host = 'turn.' + DOMAIN
    return {'port': 7880, 'prometheus_port': 6789,
            'redis': {'sentinel_master_name': 'flowmaster',
                'sentinel_addresses': [
                    f'heterocloud-flow-dev-redis-node-{i}.heterocloud-flow-dev-redis-headless.{NAMESPACE}.svc.cluster.local:26379'
                    for i in range(3)],
                'password': seeds['redis'], 'sentinel_password': seeds['redis']},
            'rtc': {'tcp_port': 7881, 'udp_port': 7882,
                'use_external_ip': True, 'advertise_internal_ip': True, 'allow_tcp_fallback': True,
                'stun_servers': [host + ':13478'],
                'turn_servers': [{'host': host, 'port': 13478, 'protocol': protocol,
                                 'secret_file': '/etc/livekit-turn/turn-shared-secret', 'ttl': 300}
                                 for protocol in ('udp', 'tcp')]},
            'logging': {'level': 'info', 'json': True}}


def secret(seeds):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
            'metadata': {'namespace': NAMESPACE, 'name': NAME,
                'labels': {'app.kubernetes.io/managed-by': MANAGER},
                'annotations': {'heteronetwork.dev.cluster-uid': app_secrets.UID}},
            'data': {'livekit.yaml': base64.b64encode(json.dumps(configuration(seeds), sort_keys=True).encode()).decode()}}
