#!/usr/bin/env python3
"""Extract Flash's HTTPRoute prerequisite from the pinned Envoy chart, offline."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

import yaml

CHART_SHA = '4bb4e46f4d13d234b0ce785bee691c821b39ebd6884d80bdd69205bea9939d71'
MEMBER = 'gateway-helm/charts/crds/crds/gatewayapi-crds.yaml'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chart', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.chart.read_bytes()).hexdigest() != CHART_SHA:
        raise ValueError('Unexpected Envoy Gateway v1.8.3 chart')
    with tarfile.open(args.chart) as archive:
        member = archive.getmember(MEMBER)
        if not member.isfile() or member.size > 2097152:
            raise ValueError('Unexpected Gateway API archive member')
        documents = list(yaml.safe_load_all(archive.extractfile(member)))
    selected = [d for d in documents if d and d['metadata']['name'] == 'httproutes.gateway.networking.k8s.io']
    if len(selected) != 1 or selected[0]['kind'] != 'CustomResourceDefinition':
        raise ValueError('Expected exactly one HTTPRoute CRD')
    raw = (json.dumps(selected[0], indent=2, sort_keys=True) + '\n').encode()
    with args.output.open('xb') as output:
        output.write(raw)
    print(json.dumps({'file': str(args.output), 'sha256': hashlib.sha256(raw).hexdigest(),
                      'chart_sha256': CHART_SHA, 'source': MEMBER, 'cluster_changed': False}))


if __name__ == '__main__':
    main()
