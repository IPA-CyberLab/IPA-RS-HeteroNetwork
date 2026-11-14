#!/usr/bin/env python3
"""Keep the encrypted snapshot PVC attached until two host replicas are healthy."""
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import time
import urllib.parse
import urllib.request

ROOT = Path('/var/run/secrets/kubernetes.io/serviceaccount')
NAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def healthy_hosts(replicas, volume):
    hosts = set()
    for item in replicas:
        metadata, spec = item.get('metadata', {}), item.get('spec', {})
        if (metadata.get('deletionTimestamp') or spec.get('volumeName') != volume or
            not spec.get('healthyAt') or spec.get('failedAt') or
            item.get('status', {}).get('currentState') != 'running'):
            continue
        host = spec.get('nodeID')
        if isinstance(host, str) and NAME.fullmatch(host):
            hosts.add(host)
    return sorted(hosts)


class Kubernetes:
    def __init__(self):
        host, port = os.environ['KUBERNETES_SERVICE_HOST'], os.environ['KUBERNETES_SERVICE_PORT_HTTPS']
        self.base = f'https://[{host}]:{port}' if ':' in host else f'https://{host}:{port}'
        context = ssl.create_default_context(cafile=str(ROOT/'ca.crt'))
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=context))

    def get(self, path):
        request = urllib.request.Request(self.base + path,
            headers={'Authorization':'Bearer '+(ROOT/'token').read_text().strip(), 'Accept':'application/json'})
        with self.opener.open(request, timeout=10) as response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('inventory response too large')
        return json.loads(data)


def check(api):
    pvc = api.get('/api/v1/namespaces/openbao/persistentvolumeclaims/openbao-snapshots')
    volume = pvc.get('spec', {}).get('volumeName', '')
    if not NAME.fullmatch(volume):
        raise ValueError('snapshot volume is not bound')
    selector = urllib.parse.urlencode({'labelSelector':'longhornvolume='+volume})
    replicas = api.get('/apis/longhorn.io/v1beta2/namespaces/longhorn-system/replicas?'+selector)
    return healthy_hosts(replicas.get('items', []), volume)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--min-hosts', type=int, default=2)
    args = parser.parse_args()
    if not 60 <= args.timeout <= 3600 or not 2 <= args.min_hosts <= 5:
        raise SystemExit('invalid replica check settings')
    api = Kubernetes()
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            hosts = check(api)
            if len(hosts) >= args.min_hosts:
                print(json.dumps({'result':'healthy', 'independent_host_copies':len(hosts), 'hosts':hosts}), flush=True)
                return 0
        except Exception:
            # Never print API headers, token values, backup contents or errors.
            pass
        time.sleep(10)
    print(json.dumps({'result':'replica_check_timed_out', 'required_hosts':args.min_hosts}), flush=True)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
